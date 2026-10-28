//! insite signature compiler: turns webappanalyzer technology files (and custom
//! signatures in the same format) into the detection index the runtime loads.
//!
//! Each pattern string such as `jquery[.-]([\d.]+)\;version:\1\;confidence:50` is
//! split into regex, version template and confidence; the regex is translated
//! from JavaScript syntax, validated, and given the literals the runtime
//! prefilter looks for.

pub mod index;
pub mod literals;
pub mod selector;
pub mod translate;

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

use index::{Category, DomCheck, Engine, FORMAT, Field, Implied, Index, Pattern, Tech};

/// Compiles a webappanalyzer checkout laid out as in `crates/core/data/webappanalyzer`:
/// `technologies/*.json`, `categories.json` and `SOURCE.toml` (source and date).
pub fn compile_dir(dir: &std::path::Path) -> Result<(Index, Report), String> {
    let read = |p: &std::path::Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir.join("technologies"))
        .map_err(|e| format!("{}: {e}", dir.join("technologies").display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let texts: Vec<String> = files.iter().map(|p| read(p)).collect::<Result<_, _>>()?;
    let categories = read(&dir.join("categories.json"))?;
    let meta = read(&dir.join("SOURCE.toml")).unwrap_or_default();
    let field = |name: &str| {
        meta.lines()
            .find_map(|l| {
                l.strip_prefix(name)?
                    .trim_start()
                    .strip_prefix('=')
                    .map(|v| v.trim().trim_matches('"').to_owned())
            })
            .unwrap_or_default()
    };
    compile(&Sources {
        technologies: texts.iter().map(String::as_str).collect(),
        categories: &categories,
        source: field("source"),
        source_date: field("date"),
    })
}

/// The input of a compilation.
pub struct Sources<'a> {
    /// Contents of `technologies/*.json` files (or custom signature files).
    pub technologies: Vec<&'a str>,
    /// Contents of `categories.json`.
    pub categories: &'a str,
    pub source: String,
    pub source_date: String,
}

/// What the compilation kept and dropped, for the build log and tests.
#[derive(Debug, Default)]
pub struct Report {
    pub techs: usize,
    pub patterns: usize,
    pub fancy: usize,
    pub always_run: usize,
    pub by_field: BTreeMap<&'static str, usize>,
    pub dropped: Vec<Dropped>,
}

#[derive(Debug)]
pub struct Dropped {
    pub tech: String,
    pub field: &'static str,
    pub pattern: String,
    pub reason: String,
}

pub fn compile(sources: &Sources) -> Result<(Index, Report), String> {
    let categories = parse_categories(sources.categories)?;
    let mut raw: BTreeMap<String, Value> = BTreeMap::new();
    for (i, text) in sources.technologies.iter().enumerate() {
        let parsed: BTreeMap<String, Value> =
            serde_json::from_str(text).map_err(|e| format!("technology file {i}: invalid JSON: {e}"))?;
        raw.extend(parsed);
    }

    let mut report = Report::default();
    let mut techs = Vec::with_capacity(raw.len());
    let mut patterns = Vec::new();
    for (name, def) in &raw {
        let id = techs.len() as u32;
        techs.push(Tech {
            name: name.clone(),
            cats: def
                .get("cats")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(as_u32).collect())
                .unwrap_or_default(),
            website: def.get("website").and_then(Value::as_str).map(str::to_owned),
            implies: strings(def.get("implies"))
                .into_iter()
                .map(|s| {
                    let (name, _, confidence) = split_pattern(&s);
                    Implied { name, confidence }
                })
                .collect(),
            requires: strings(def.get("requires")),
            requires_category: match def.get("requiresCategory") {
                Some(Value::Array(a)) => a.iter().filter_map(as_u32).collect(),
                Some(v) => as_u32(v).into_iter().collect(),
                None => Vec::new(),
            },
            excludes: strings(def.get("excludes")),
        });

        let mut add = |field: Field, key: Option<String>, dom: Option<DomCheck>, value: &str, report: &mut Report| {
            match compile_pattern(id, field, key.clone(), dom, value) {
                Ok(p) => {
                    report.patterns += 1;
                    *report.by_field.entry(field.as_str()).or_default() += 1;
                    if p.engine == Engine::Fancy {
                        report.fancy += 1;
                    }
                    if p.needles.is_empty() && p.regex.is_some() {
                        report.always_run += 1;
                    }
                    patterns.push(p);
                }
                Err(reason) => report.dropped.push(Dropped {
                    tech: name.clone(),
                    field: field.as_str(),
                    pattern: if value.is_empty() {
                        key.unwrap_or_default()
                    } else {
                        value.to_owned()
                    },
                    reason,
                }),
            }
        };

        for (key, field) in [
            ("scriptSrc", Field::ScriptSrc),
            ("scripts", Field::Scripts),
            ("html", Field::Html),
            ("text", Field::Text),
            ("url", Field::Url),
            ("xhr", Field::Xhr),
            ("css", Field::Css),
            ("robots", Field::Robots),
            ("certIssuer", Field::CertIssuer),
        ] {
            for value in strings(def.get(key)) {
                add(field, None, None, &value, &mut report);
            }
        }
        // Keyed fields: header, cookie and meta names are matched case-insensitively.
        for (key, field) in [
            ("headers", Field::Headers),
            ("cookies", Field::Cookies),
            ("meta", Field::Meta),
        ] {
            if let Some(Value::Object(map)) = def.get(key) {
                for (k, v) in map {
                    for value in strings(Some(v)) {
                        add(field, Some(k.to_ascii_lowercase()), None, &value, &mut report);
                    }
                }
            }
        }
        if let Some(Value::Object(map)) = def.get("js") {
            for (property, v) in map {
                for value in strings(Some(v)) {
                    add(Field::Js, Some(property.clone()), None, &value, &mut report);
                }
            }
        }
        if let Some(Value::Object(map)) = def.get("dns") {
            for (record_type, v) in map {
                for value in strings(Some(v)) {
                    add(
                        Field::Dns,
                        Some(record_type.to_ascii_uppercase()),
                        None,
                        &value,
                        &mut report,
                    );
                }
            }
        }
        match def.get("dom") {
            Some(Value::String(_) | Value::Array(_)) => {
                // Plain selectors may carry metadata too: `form#login\;confidence:40`.
                for raw in strings(def.get("dom")) {
                    let (selector, _, confidence) = split_pattern(&raw);
                    let meta = if confidence == 100 {
                        String::new()
                    } else {
                        format!("\\;confidence:{confidence}")
                    };
                    add(Field::Dom, Some(selector), Some(DomCheck::Exists), &meta, &mut report);
                }
            }
            Some(Value::Object(map)) => {
                for (selector, checks) in map {
                    let Value::Object(checks) = checks else { continue };
                    for (check, value) in checks {
                        match (check.as_str(), value) {
                            ("exists", _) => add(
                                Field::Dom,
                                Some(selector.clone()),
                                Some(DomCheck::Exists),
                                "",
                                &mut report,
                            ),
                            ("text", v) => {
                                for p in strings(Some(v)) {
                                    add(
                                        Field::Dom,
                                        Some(selector.clone()),
                                        Some(DomCheck::Text),
                                        &p,
                                        &mut report,
                                    );
                                }
                            }
                            ("attributes" | "properties", Value::Object(named)) => {
                                for (attr, v) in named {
                                    let dom = if check == "attributes" {
                                        DomCheck::Attribute(attr.to_ascii_lowercase())
                                    } else {
                                        DomCheck::Property(attr.clone())
                                    };
                                    for p in strings(Some(v)) {
                                        add(Field::Dom, Some(selector.clone()), Some(dom.clone()), &p, &mut report);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
        // `probe` is never compiled: it makes requests to paths the user did not ask for.
    }
    report.techs = techs.len();

    let index = Index {
        format: FORMAT,
        source: sources.source.clone(),
        source_date: sources.source_date.clone(),
        categories,
        techs,
        patterns,
    };
    Ok((index, report))
}

fn compile_pattern(
    tech: u32,
    field: Field,
    key: Option<String>,
    dom: Option<DomCheck>,
    value: &str,
) -> Result<Pattern, String> {
    let (regex_js, version, confidence) = split_pattern(value);
    if field == Field::Dom
        && let Some(selector) = &key
    {
        selector::parse(selector).map_err(|e| format!("selector: {e}"))?;
    }
    let (regex, engine, unicode, needles) = if regex_js.is_empty() {
        (None, Engine::Regex, false, Vec::new())
    } else {
        let (rust, engine) = translate::translate(&regex_js)?;
        // ASCII mode first, like JavaScript's classes; Unicode only when the
        // pattern needs it (non-ASCII characters inside a class).
        let unicode = match validate(&rust, engine, false) {
            Ok(()) => false,
            Err(first) => {
                validate(&rust, engine, true).map_err(|_| first)?;
                true
            }
        };
        let needles = if engine == Engine::Regex && !unicode {
            literals::needles(&rust)
        } else {
            Vec::new()
        };
        (Some(rust), engine, unicode, needles)
    };
    Ok(Pattern {
        tech,
        field,
        key,
        dom,
        regex,
        engine,
        unicode,
        version,
        confidence,
        needles,
    })
}

/// The regex must build exactly as the runtime builds it.
fn validate(pattern: &str, engine: Engine, unicode: bool) -> Result<(), String> {
    match engine {
        Engine::Regex => regex::bytes::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .unicode(unicode)
            .size_limit(1 << 20)
            .build()
            .map(|_| ())
            .map_err(|e| format!("regex: {e}")),
        Engine::Fancy => fancy_regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .map(|_| ())
            .map_err(|e| format!("fancy-regex: {e}")),
    }
}

/// `regex\;version:\1\;confidence:50` into its parts. Confidence defaults to 100.
pub fn split_pattern(value: &str) -> (String, Option<String>, u8) {
    let mut parts = value.split("\\;");
    let regex = parts.next().unwrap_or_default().to_owned();
    let (mut version, mut confidence) = (None, 100u8);
    for part in parts {
        if let Some(v) = part.strip_prefix("version:") {
            version = Some(v.to_owned()).filter(|v| !v.is_empty());
        } else if let Some(c) = part.strip_prefix("confidence:") {
            confidence = c.trim().parse::<u32>().map_or(100, |c| c.min(100) as u8);
        }
    }
    (regex, version, confidence)
}

fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        _ => Vec::new(),
    }
}

fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn parse_categories(text: &str) -> Result<Vec<Category>, String> {
    let raw: HashMap<String, Value> =
        serde_json::from_str(text).map_err(|e| format!("categories: invalid JSON: {e}"))?;
    let mut categories: Vec<Category> = raw
        .into_iter()
        .filter_map(|(id, def)| {
            Some(Category {
                id: id.parse().ok()?,
                name: def.get("name")?.as_str()?.to_owned(),
                priority: def.get("priority").and_then(Value::as_u64).unwrap_or(0) as u8,
            })
        })
        .collect();
    categories.sort_by_key(|c| c.id);
    Ok(categories)
}

/// Resolves a version template against the capture groups of a match, as
/// Wappalyzer does: `\1?a:b` becomes `a` when group 1 matched, `b` otherwise, then
/// every `\N` becomes group N.
pub fn resolve_version(template: &str, groups: &[Option<&str>]) -> String {
    let mut version = template.to_owned();
    for (i, group) in groups.iter().enumerate().skip(1) {
        let marker = format!("\\{i}");
        if let Some(pos) = version.find(&format!("{marker}?")) {
            let rest = &version[pos + marker.len() + 1..];
            if let Some((yes, no)) = rest.split_once(':') {
                let chosen = if group.is_some_and(|g| !g.is_empty()) { yes } else { no };
                version = format!("{}{}", &version[..pos], chosen);
            }
        }
        version = version.replace(&marker, group.unwrap_or(""));
    }
    version.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(techs: &str, source: &str) -> Index {
        let categories = r#"{"1": {"name": "CMS", "priority": 1}, "2": {"name": "Other", "priority": 9}}"#;
        let sources = Sources {
            technologies: vec![techs],
            categories,
            source: source.into(),
            source_date: "2026-01-01".into(),
        };
        compile(&sources).unwrap().0
    }

    #[test]
    fn custom_signatures_override_by_name() {
        let mut base = index_of(
            r#"{"Alpha": {"cats": [1], "headers": {"x-alpha": ""}}, "Beta": {"cats": [1], "html": "beta-marker"}}"#,
            "base",
        );
        let custom = index_of(
            r#"{"Beta": {"cats": [2], "html": "new-beta"}, "Gamma": {"cats": [2], "html": "gamma-marker"}}"#,
            "custom",
        );
        base.merge(custom);
        let names: Vec<&str> = base.techs.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Alpha", "Beta", "Gamma"]);
        let beta = 1;
        let beta_patterns: Vec<&Pattern> = base.patterns.iter().filter(|p| p.tech == beta).collect();
        assert_eq!(beta_patterns.len(), 1);
        assert_eq!(beta_patterns[0].regex.as_deref(), Some("new-beta"));
        assert_eq!(base.techs[1].cats, [2]);
        assert!(
            base.patterns
                .iter()
                .any(|p| p.tech == 2 && p.regex.as_deref() == Some("gamma-marker"))
        );
        // Categories survive a round trip through categories_json.
        let again = parse_categories(&base.categories_json()).unwrap();
        assert_eq!(again.len(), 2);
        assert_eq!(again[1].name, "Other");
    }

    #[test]
    fn splits_pattern_metadata() {
        assert_eq!(
            split_pattern(r"jquery[.-]([\d.]*)\;version:\1\;confidence:50"),
            (r"jquery[.-]([\d.]*)".to_owned(), Some(r"\1".to_owned()), 50)
        );
        assert_eq!(split_pattern("Shopify"), ("Shopify".to_owned(), None, 100));
    }

    #[test]
    fn versions_with_ternaries() {
        assert_eq!(resolve_version(r"\1", &[Some("x"), Some("3.6.0")]), "3.6.0");
        assert_eq!(resolve_version(r"\1?4:3", &[Some("x"), Some("y")]), "4");
        assert_eq!(resolve_version(r"\1?4:3", &[Some("x"), None]), "3");
        assert_eq!(resolve_version(r"\1.\2", &[Some("x"), Some("5"), Some("2")]), "5.2");
    }

    #[test]
    fn compiles_every_field_shape() {
        let techs = r##"{
            "Demo": {
                "cats": [1],
                "website": "https://demo.example",
                "headers": {"X-Powered-By": "Demo/([\\d.]+)\\;version:\\1"},
                "cookies": {"demo_session": ""},
                "meta": {"generator": ["Demo ([\\d.]+)\\;version:\\1"]},
                "scriptSrc": ["demo\\.min\\.js"],
                "dom": {"#demo-root": {"attributes": {"data-version": "([\\d.]+)\\;version:\\1"}}, "div.demo": {"exists": ""}},
                "js": {"Demo.version": "([\\d.]+)\\;version:\\1"},
                "dns": {"TXT": ["demo-verification"]},
                "implies": ["PHP\\;confidence:50"],
                "probe": {"/demo": ""}
            }
        }"##;
        let sources = Sources {
            technologies: vec![techs],
            categories: r#"{"1": {"name": "CMS", "priority": 1}}"#,
            source: "test".into(),
            source_date: "2026-01-01".into(),
        };
        let (index, report) = compile(&sources).unwrap();
        assert!(report.dropped.is_empty(), "{:?}", report.dropped);
        assert_eq!(report.patterns, 8);
        assert_eq!(index.techs[0].implies[0].confidence, 50);
        let header = index.patterns.iter().find(|p| p.field == Field::Headers).unwrap();
        assert_eq!(header.key.as_deref(), Some("x-powered-by"));
        let script = index.patterns.iter().find(|p| p.field == Field::ScriptSrc).unwrap();
        assert_eq!(script.needles, ["demo.min.js"]);
    }
}
