//! Stack detection: runs the compiled signatures over what the page exposed.
//!
//! Per field, an Aho-Corasick automaton finds which patterns can match at all; only
//! those regexes are compiled (once, cached) and run. Keyed fields (headers,
//! cookies, meta, DNS, JS) go straight to the patterns for that key. Every
//! detection keeps the evidence that produced it.

mod dom;
mod inputs;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind};
use insite_sigc::index::{DomCheck, Engine as RegexEngine, Field, Index, Pattern};
use insite_sigc::resolve_version;
use insite_sigc::selector::SelectorList;

pub use dom::ElementIndex;
pub use inputs::Inputs;

/// Matched text kept as evidence.
const EVIDENCE_LIMIT: usize = 120;
/// Fancy-regex patterns backtrack; cap the work and the input they see.
const BACKTRACK_LIMIT: usize = 1_000_000;
const FANCY_INPUT_LIMIT: usize = 512 << 10;
const VERSION_MAX_LEN: usize = 15;

const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/index.json"));

pub struct Engine {
    index: Index,
    origin: Origin,
    by_name: HashMap<String, u32>,
    prefilters: HashMap<Field, Prefilter>,
    /// Patterns of a field that have no needles and always run.
    always: HashMap<Field, Vec<u32>>,
    keyed: HashMap<(Field, String), Vec<u32>>,
    dom: Vec<u32>,
    compiled: Vec<OnceLock<Option<Compiled>>>,
    selectors: Vec<OnceLock<Option<SelectorList>>>,
}

/// While building: needles, the patterns each unlocks, and needle positions.
type NeedleTable = (Vec<String>, Vec<Vec<u32>>, HashMap<String, usize>);

struct Prefilter {
    automaton: AhoCorasick,
    /// Needle index to the patterns it unlocks.
    patterns: Vec<Vec<u32>>,
}

enum Compiled {
    Regex(regex::bytes::Regex),
    Fancy(fancy_regex::Regex),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Evidence {
    pub field: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// What matched, shortened.
    pub value: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    /// 0 to 100; below 100 the detection is probable, not certain.
    pub confidence: u8,
    pub categories: Vec<String>,
    pub website: Option<String>,
    pub evidence: Vec<Evidence>,
    /// Set when the technology was not seen but implied by another.
    pub implied_by: Option<String>,
}

/// Where the engine may find signatures besides the embedded ones.
struct LocalData {
    /// The cache directory, where `insite update` keeps `signatures/index.json`.
    cache: Option<PathBuf>,
    /// The configuration directory, with the user's `fingerprints/*.json`.
    config: Option<PathBuf>,
}

static LOCAL: OnceLock<LocalData> = OnceLock::new();

const CORRECTIONS: &str = include_str!("../../data/corrections.json");

/// Lets the engine use the signatures from `insite update` and the user's own.
/// Call before the engine first loads. Tests never call it, so they only ever
/// see the embedded index.
pub fn use_local_data(cache: Option<PathBuf>, config: Option<PathBuf>) {
    let _ = LOCAL.set(LocalData { cache, config });
}

/// The detection engine. Building takes tens of milliseconds; call `warm_up`
/// at t = 0 so it happens while the network works.
pub fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let (index, origin) = load_index();
        let mut engine = Engine::new(index);
        engine.origin = origin;
        engine
    })
}

/// Which signatures the engine runs.
#[derive(Debug, Clone, Default)]
pub struct Origin {
    /// The base index came from `insite update`, not from the binary.
    pub updated: bool,
    /// Technologies from the user's own signature files.
    pub custom: usize,
}

/// The embedded index, replaced by the updated one when that is newer and of
/// the same format, then our corrections, then the user's own signatures.
/// Problems are reported and skipped: they never stop an analysis.
fn load_index() -> (Index, Origin) {
    let mut index: Index = serde_json::from_slice(EMBEDDED).expect("embedded index is valid");
    let mut origin = Origin::default();
    let local = LOCAL.get();

    if let Some(path) = local
        .and_then(|l| l.cache.as_ref())
        .map(|d| d.join("signatures").join("index.json"))
        && path.exists()
    {
        match std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Index>(&b).map_err(|e| e.to_string()))
        {
            Ok(updated) if updated.format != insite_sigc::index::FORMAT => eprintln!(
                "insite: ignoring {}: index format {} (this insite reads {}); run insite update",
                path.display(),
                updated.format,
                insite_sigc::index::FORMAT
            ),
            Ok(updated) if updated.source_date > index.source_date => {
                index = updated;
                origin.updated = true;
            }
            Ok(_) => {}
            Err(e) => eprintln!("insite: ignoring {}: {e}", path.display()),
        }
    }

    // Whichever base was chosen, embedded or updated, the same fixes apply.
    index.merge(corrections(&index));

    if let Some(dir) = local.and_then(|l| l.config.as_ref()).map(|d| d.join("fingerprints"))
        && dir.is_dir()
    {
        match custom_index(&dir, &index) {
            Ok(Some(custom)) => {
                origin.custom = custom.techs.len();
                index.merge(custom);
            }
            Ok(None) => {}
            Err(e) => eprintln!("insite: ignoring custom signatures in {}: {e}", dir.display()),
        }
    }
    (index, origin)
}

/// Our replacements for webappanalyzer signatures that misfire, measured on the
/// hand-labeled sites (`bench/labels.tsv`); `data/corrections.md` says why each
/// one changed. Same format as the user's own signatures, and they win the same
/// way: by name.
fn corrections(base: &Index) -> Index {
    let categories = base.categories_json();
    let sources = insite_sigc::Sources {
        technologies: vec![CORRECTIONS],
        categories: &categories,
        source: "insite corrections".to_owned(),
        source_date: String::new(),
    };
    insite_sigc::compile(&sources)
        .map(|(index, _)| index)
        .expect("embedded corrections compile")
}

/// Compiles every `*.json` in `dir`, in the webappanalyzer format, against the
/// base index's categories.
fn custom_index(dir: &Path, base: &Index) -> Result<Option<Index>, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    if files.is_empty() {
        return Ok(None);
    }
    files.sort();
    let texts: Vec<String> = files
        .iter()
        .map(|p| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display())))
        .collect::<Result<_, _>>()?;
    let categories = base.categories_json();
    let sources = insite_sigc::Sources {
        technologies: texts.iter().map(String::as_str).collect(),
        categories: &categories,
        source: format!("custom ({})", dir.display()),
        source_date: String::new(),
    };
    insite_sigc::compile(&sources).map(|(index, _)| Some(index))
}

/// Builds the engine on a background thread.
pub fn warm_up() {
    std::thread::spawn(|| {
        engine();
    });
}

impl Engine {
    pub fn new(index: Index) -> Self {
        let by_name = index
            .techs
            .iter()
            .enumerate()
            .map(|(i, t)| (t.name.clone(), i as u32))
            .collect();
        let mut needles: HashMap<Field, NeedleTable> = HashMap::new();
        let mut always: HashMap<Field, Vec<u32>> = HashMap::new();
        let mut keyed: HashMap<(Field, String), Vec<u32>> = HashMap::new();
        let mut dom = Vec::new();

        for (id, pattern) in index.patterns.iter().enumerate() {
            let id = id as u32;
            match pattern.field {
                Field::Dom => dom.push(id),
                Field::Headers | Field::Cookies | Field::Meta | Field::Dns | Field::Js => {
                    let key = pattern.key.clone().unwrap_or_default();
                    keyed.entry((pattern.field, key)).or_default().push(id);
                }
                field if pattern.needles.is_empty() => always.entry(field).or_default().push(id),
                field => {
                    let (list, owners, seen) = needles.entry(field).or_default();
                    for needle in &pattern.needles {
                        let slot = *seen.entry(needle.clone()).or_insert_with(|| {
                            list.push(needle.clone());
                            owners.push(Vec::new());
                            list.len() - 1
                        });
                        owners[slot].push(id);
                    }
                }
            }
        }
        let prefilters = needles
            .into_iter()
            .map(|(field, (list, owners, _))| {
                let automaton = AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .kind(Some(AhoCorasickKind::ContiguousNFA))
                    .build(&list)
                    .expect("needles build an automaton");
                (
                    field,
                    Prefilter {
                        automaton,
                        patterns: owners,
                    },
                )
            })
            .collect();
        let compiled = (0..index.patterns.len()).map(|_| OnceLock::new()).collect();
        let selectors = (0..index.patterns.len()).map(|_| OnceLock::new()).collect();
        Engine {
            index,
            origin: Origin::default(),
            by_name,
            prefilters,
            always,
            keyed,
            dom,
            compiled,
            selectors,
        }
    }

    pub fn source(&self) -> (&str, &str) {
        (&self.index.source, &self.index.source_date)
    }

    /// The signatures in use, for the report: base source and date, whether
    /// they came from `insite update`, and how many custom technologies.
    pub fn provenance(&self) -> String {
        let mut text = format!("{} ({})", self.index.source, self.index.source_date);
        if self.origin.updated {
            text.push_str(", updated");
        }
        if self.origin.custom > 0 {
            text.push_str(&format!(", plus {} custom", self.origin.custom));
        }
        text
    }

    pub fn detect(&self, inputs: &Inputs) -> Vec<Technology> {
        let mut hits = Hits::default();
        for (field, contents) in inputs.lists() {
            for content in contents {
                self.scan(field, content, None, &mut hits);
            }
        }
        for (field, key, values) in inputs.keyed() {
            if let Some(ids) = self.keyed.get(&(field, key.to_owned())) {
                for value in values {
                    for &id in ids {
                        self.try_pattern(id, value, Some(key), &mut hits);
                    }
                }
            }
        }
        if let Some(elements) = &inputs.elements {
            for &id in &self.dom {
                self.try_dom(id, elements, inputs, &mut hits);
            }
        }
        self.resolve(hits)
    }

    fn scan(&self, field: Field, content: &str, key: Option<&str>, hits: &mut Hits) {
        let mut candidates: Vec<u32> = self.always.get(&field).cloned().unwrap_or_default();
        if let Some(prefilter) = self.prefilters.get(&field) {
            let mut seen = HashSet::new();
            for m in prefilter.automaton.find_overlapping_iter(content) {
                if seen.insert(m.pattern().as_usize()) {
                    candidates.extend(&prefilter.patterns[m.pattern().as_usize()]);
                }
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        for id in candidates {
            self.try_pattern(id, content, key, hits);
        }
    }

    fn try_pattern(&self, id: u32, value: &str, key: Option<&str>, hits: &mut Hits) {
        let pattern = &self.index.patterns[id as usize];
        if let Some(groups) = self.matches(id, pattern, value) {
            let version = pattern.version.as_deref().map(|t| {
                let refs: Vec<Option<&str>> = groups.iter().map(|g| g.as_deref()).collect();
                resolve_version(t, &refs)
            });
            let shown = groups.first().cloned().flatten().unwrap_or_else(|| value.to_owned());
            let evidence = Evidence {
                field: pattern.field.as_str(),
                key: key.map(str::to_owned),
                value: shorten(&shown),
            };
            hits.add(pattern, id, version, evidence);
        }
    }

    fn try_dom(&self, id: u32, elements: &ElementIndex, inputs: &Inputs, hits: &mut Hits) {
        let pattern = &self.index.patterns[id as usize];
        let Some(selector) = &pattern.key else { return };
        // Element properties exist only in a browser, which read them for us.
        if let Some(DomCheck::Property(name)) = &pattern.dom {
            let values = inputs.dom_properties.get(&(selector.clone(), name.clone()));
            for value in values.into_iter().flatten() {
                if self.try_dom_value(id, pattern, selector, value, hits) {
                    return;
                }
            }
            return;
        }
        let Some(list) = self.selectors[id as usize].get_or_init(|| insite_sigc::selector::parse(selector).ok()) else {
            return;
        };
        let matched = elements.select(list);
        for element in matched {
            let value = match &pattern.dom {
                Some(DomCheck::Attribute(name)) => match element.attr(name) {
                    Some(v) => v.to_owned(),
                    None => continue,
                },
                Some(DomCheck::Text) => element.text.clone(),
                Some(DomCheck::Property(_)) => return,
                Some(DomCheck::Exists) | None => String::new(),
            };
            // One matching element is enough.
            if self.try_dom_value(id, pattern, selector, &value, hits) {
                return;
            }
        }
    }

    /// Records a hit when `value` matches; returns whether it did.
    fn try_dom_value(&self, id: u32, pattern: &Pattern, selector: &str, value: &str, hits: &mut Hits) -> bool {
        let Some(groups) = self.matches(id, pattern, value) else {
            return false;
        };
        let version = pattern.version.as_deref().map(|t| {
            let refs: Vec<Option<&str>> = groups.iter().map(|g| g.as_deref()).collect();
            resolve_version(t, &refs)
        });
        let evidence = Evidence {
            field: "dom",
            key: Some(selector.to_owned()),
            value: shorten(value),
        };
        hits.add(pattern, id, version, evidence);
        true
    }

    /// What a browser must read for the `js` and `dom` property signatures:
    /// property paths, and selector and property pairs.
    pub fn browser_queries(&self) -> (Vec<String>, Vec<(String, String)>) {
        let mut js: Vec<String> = Vec::new();
        let mut props: Vec<(String, String)> = Vec::new();
        for p in &self.index.patterns {
            match (p.field, &p.key, &p.dom) {
                (Field::Js, Some(path), _) => js.push(path.clone()),
                (Field::Dom, Some(selector), Some(DomCheck::Property(name))) => {
                    props.push((selector.clone(), name.clone()))
                }
                _ => {}
            }
        }
        js.sort();
        js.dedup();
        props.sort();
        props.dedup();
        (js, props)
    }

    /// Capture groups (group 0 is the whole match) when `value` matches, with an
    /// empty regex meaning existence.
    fn matches(&self, id: u32, pattern: &Pattern, value: &str) -> Option<Vec<Option<String>>> {
        let Some(source) = &pattern.regex else {
            return Some(vec![None]);
        };
        let compiled = self.compiled[id as usize].get_or_init(|| compile(source, pattern.engine, pattern.unicode));
        match compiled.as_ref()? {
            Compiled::Regex(re) => re.captures(value.as_bytes()).map(|caps| {
                caps.iter()
                    .map(|g| g.map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned()))
                    .collect()
            }),
            Compiled::Fancy(re) => {
                let mut end = value.len().min(FANCY_INPUT_LIMIT);
                while !value.is_char_boundary(end) {
                    end -= 1;
                }
                match re.captures(&value[..end]) {
                    Ok(Some(caps)) => Some(caps.iter().map(|g| g.map(|m| m.as_str().to_owned())).collect()),
                    _ => None,
                }
            }
        }
    }

    fn resolve(&self, hits: Hits) -> Vec<Technology> {
        // Confidence: the best of each pattern, summed per technology, capped at 100.
        let mut found: BTreeMap<u32, Found> = BTreeMap::new();
        for (tech, per_pattern) in hits.by_tech {
            let confidence = per_pattern.values().map(|(c, _)| u32::from(*c)).sum::<u32>().min(100) as u8;
            let mut versions: Vec<String> = per_pattern.values().filter_map(|(_, v)| v.clone()).collect();
            versions.retain(|v| !v.is_empty() && v.len() <= VERSION_MAX_LEN);
            found.insert(
                tech,
                Found {
                    confidence,
                    version: best_version(versions),
                    evidence: hits.evidence.get(&tech).cloned().unwrap_or_default(),
                    implied_by: None,
                },
            );
        }

        // Implied technologies, recursively.
        let mut queue: Vec<u32> = found.keys().copied().collect();
        while let Some(tech) = queue.pop() {
            let parent_confidence = found[&tech].confidence;
            for implied in &self.index.techs[tech as usize].implies {
                let Some(&target) = self.by_name.get(&implied.name) else {
                    continue;
                };
                let confidence = ((u32::from(implied.confidence) * u32::from(parent_confidence)) / 100) as u8;
                match found.get_mut(&target) {
                    Some(existing) => existing.confidence = existing.confidence.max(confidence),
                    None => {
                        found.insert(
                            target,
                            Found {
                                confidence,
                                version: implied.version.clone(),
                                evidence: Vec::new(),
                                implied_by: Some(self.index.techs[tech as usize].name.clone()),
                            },
                        );
                        queue.push(target);
                    }
                }
            }
        }

        // Excludes, then requires and requiresCategory, until stable. One of
        // several required technologies or categories is enough: a plugin for
        // two platforms lists both.
        let excluded: HashSet<u32> = found
            .keys()
            .flat_map(|&t| {
                self.index.techs[t as usize]
                    .excludes
                    .iter()
                    .filter_map(|n| self.by_name.get(n).copied())
            })
            .collect();
        found.retain(|t, _| !excluded.contains(t));
        loop {
            let present: HashSet<u32> = found.keys().copied().collect();
            let categories: HashSet<u32> = present
                .iter()
                .flat_map(|&t| self.index.techs[t as usize].cats.iter().copied())
                .collect();
            let before = found.len();
            found.retain(|&t, _| {
                let tech = &self.index.techs[t as usize];
                (tech.requires.is_empty()
                    || tech
                        .requires
                        .iter()
                        .any(|r| self.by_name.get(r).is_some_and(|id| present.contains(id))))
                    && (tech.requires_category.is_empty()
                        || tech.requires_category.iter().any(|c| categories.contains(c)))
            });
            if found.len() == before {
                break;
            }
        }

        let category_names: HashMap<u32, (&str, u8)> = self
            .index
            .categories
            .iter()
            .map(|c| (c.id, (c.name.as_str(), c.priority)))
            .collect();
        let mut technologies: Vec<(u8, Technology)> = found
            .into_iter()
            .filter(|(_, f)| f.confidence > 0)
            .map(|(id, f)| {
                let tech = &self.index.techs[id as usize];
                let priority = tech
                    .cats
                    .iter()
                    .filter_map(|c| category_names.get(c).map(|(_, p)| *p))
                    .min()
                    .unwrap_or(u8::MAX);
                (
                    priority,
                    Technology {
                        name: tech.name.clone(),
                        version: f.version,
                        confidence: f.confidence,
                        categories: tech
                            .cats
                            .iter()
                            .filter_map(|c| category_names.get(c).map(|(n, _)| (*n).to_owned()))
                            .collect(),
                        website: tech.website.clone(),
                        evidence: f.evidence,
                        implied_by: f.implied_by,
                    },
                )
            })
            .collect();
        technologies.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name)));
        technologies.into_iter().map(|(_, t)| t).collect()
    }
}

struct Found {
    confidence: u8,
    version: Option<String>,
    evidence: Vec<Evidence>,
    implied_by: Option<String>,
}

#[derive(Default)]
struct Hits {
    /// Per technology, per pattern: best confidence and a version.
    by_tech: BTreeMap<u32, BTreeMap<u32, (u8, Option<String>)>>,
    evidence: HashMap<u32, Vec<Evidence>>,
}

impl Hits {
    fn add(&mut self, pattern: &Pattern, id: u32, version: Option<String>, evidence: Evidence) {
        let entry = self
            .by_tech
            .entry(pattern.tech)
            .or_default()
            .entry(id)
            .or_insert((0, None));
        entry.0 = entry.0.max(pattern.confidence);
        if entry.1.is_none() {
            entry.1 = version.filter(|v| !v.is_empty());
        }
        let list = self.evidence.entry(pattern.tech).or_default();
        if list.len() < 5 && !list.contains(&evidence) {
            list.push(evidence);
        }
    }
}

fn compile(source: &str, engine: RegexEngine, unicode: bool) -> Option<Compiled> {
    match engine {
        RegexEngine::Regex => regex::bytes::RegexBuilder::new(source)
            .case_insensitive(true)
            .unicode(unicode)
            .size_limit(1 << 20)
            .build()
            .ok()
            .map(Compiled::Regex),
        RegexEngine::Fancy => fancy_regex::RegexBuilder::new(source)
            .case_insensitive(true)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build()
            .ok()
            .map(Compiled::Fancy),
    }
}

/// The most specific version: most numeric components, then highest.
fn best_version(mut versions: Vec<String>) -> Option<String> {
    let key = |v: &str| -> (usize, Vec<u64>) {
        let parts: Vec<u64> = v
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect();
        (parts.len(), parts)
    };
    versions.sort_by(|a, b| key(b).cmp(&key(a)).then(a.cmp(b)));
    versions.into_iter().next()
}

fn shorten(text: &str) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= EVIDENCE_LIMIT {
        flat
    } else {
        format!("{}…", flat.chars().take(EVIDENCE_LIMIT).collect::<String>())
    }
}

#[cfg(test)]
mod tests;
