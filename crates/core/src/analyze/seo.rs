//! Technical SEO: indexability, metadata, structure, robots.txt and sitemap.

use std::io::Read;

use serde::Serialize;

use super::content::Content;
use crate::extract::{PageFacts, normalize_space, sniff_html};
use crate::findings::finding;
use crate::report::{Finding, Module, Status};
use crate::snapshot::{AuxFile, Hop, Snapshot};

const TITLE_MIN: usize = 10;
const TITLE_MAX: usize = 70;
const DESCRIPTION_MIN: usize = 50;
const DESCRIPTION_MAX: usize = 160;

#[derive(Debug, Clone, Serialize)]
pub struct Seo {
    pub title: Option<String>,
    pub title_length: usize,
    pub description: Option<String>,
    pub description_length: usize,
    pub canonical: Vec<String>,
    pub canonical_header: Option<String>,
    pub meta_robots: Option<String>,
    pub x_robots_tag: Vec<String>,
    pub indexable: bool,
    pub lang: Option<String>,
    pub viewport: bool,
    pub h1_count: usize,
    pub headings: [usize; 6],
    pub open_graph: Vec<String>,
    pub twitter_card: Option<String>,
    pub structured_data: Vec<String>,
    pub hreflang: Vec<String>,
    pub images: usize,
    pub images_without_alt: usize,
    pub robots_txt: Option<RobotsTxt>,
    pub sitemap: Option<Sitemap>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RobotsTxt {
    pub url: String,
    pub status: Option<u16>,
    /// `found`, `absent` (4xx: everything allowed), `server_error`, `not_robots`
    /// (an HTML page answered) or `failed`.
    pub state: &'static str,
    pub blocks_all: bool,
    pub sitemaps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sitemap {
    pub url: String,
    pub status: Option<u16>,
    /// `urlset`, `sitemapindex`, `not_sitemap` (wrong content), `absent` or `failed`.
    pub state: &'static str,
    /// `<url>` entries in a urlset, or `<sitemap>` entries in an index, counted in
    /// the part read (1 MB).
    pub entries: usize,
    pub truncated: bool,
}

pub fn analyze(snapshot: &Snapshot, content: &Result<Content, String>) -> Module<Seo> {
    let content = match content {
        Ok(c) => c,
        Err(reason) => {
            return Module {
                status: Status::Skipped,
                reason: Some(reason.clone()),
                data: None,
                findings: vec![],
            };
        }
    };
    let hop = snapshot.chain.last().expect("content implies a final hop");
    let facts = &content.facts;
    let mut findings = Vec::new();

    let title = facts
        .titles
        .first()
        .map(|t| normalize_space(t))
        .filter(|t| !t.is_empty());
    let description = facts.meta("description").map(normalize_space).filter(|d| !d.is_empty());
    let meta_robots = robots_meta(facts);
    let x_robots_tag: Vec<String> = hop
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("x-robots-tag"))
        .map(|(_, v)| v.clone())
        .collect();
    let noindex_source = meta_robots
        .as_deref()
        .filter(|m| has_noindex(m))
        .map(|m| format!("<meta name=robots content=\"{m}\">"))
        .or_else(|| {
            x_robots_tag
                .iter()
                .find(|v| header_noindex(v))
                .map(|v| format!("X-Robots-Tag: {v}"))
        });

    let canonical: Vec<String> = facts
        .links_with_rel("canonical")
        .filter_map(|l| l.href.clone())
        .collect();
    let canonical_header = canonical_from_header(hop, &content.url);
    let mut headings = [0usize; 6];
    for (level, _) in &facts.headings {
        headings[usize::from(*level - 1)] += 1;
    }
    let robots_txt = snapshot.auxiliary.robots.as_ref().map(robots_report);
    let sitemap = snapshot.auxiliary.sitemap.as_ref().map(sitemap_report);

    if let Some(source) = &noindex_source {
        findings.push(finding("seo.noindex", &[("source", source.clone())], source.clone()));
    }
    if let Some(r) = robots_txt.as_ref().filter(|r| r.blocks_all) {
        findings.push(finding(
            "seo.robots.blocks_all",
            &[("url", r.url.clone())],
            "User-agent: * / Disallow: /".into(),
        ));
    }
    match &title {
        None => findings.push(finding("seo.title.missing", &[], "no <title> or an empty one".into())),
        Some(t) if t.chars().count() < TITLE_MIN || t.chars().count() > TITLE_MAX => findings.push(finding(
            "seo.title.length",
            &[("length", t.chars().count().to_string())],
            format!("<title>{t}</title>"),
        )),
        _ => {}
    }
    match &description {
        None => findings.push(finding(
            "seo.description.missing",
            &[],
            "no <meta name=description>".into(),
        )),
        Some(d) if d.chars().count() < DESCRIPTION_MIN || d.chars().count() > DESCRIPTION_MAX => {
            findings.push(finding(
                "seo.description.length",
                &[("length", d.chars().count().to_string())],
                d.clone(),
            ))
        }
        _ => {}
    }
    if canonical.len() > 1 {
        findings.push(finding(
            "seo.canonical.multiple",
            &[("count", canonical.len().to_string())],
            canonical.join(", "),
        ));
    }
    if let (Some(tag), Some(header)) = (canonical.first(), &canonical_header)
        && tag != header
    {
        findings.push(finding(
            "seo.canonical.conflict",
            &[("tag", tag.clone()), ("header", header.clone())],
            format!("link tag {tag}, Link header {header}"),
        ));
    }
    if facts.meta("viewport").is_none() {
        findings.push(finding("seo.viewport.missing", &[], "no <meta name=viewport>".into()));
    }
    if facts.lang.is_none() {
        findings.push(finding("seo.lang.missing", &[], "<html> has no lang attribute".into()));
    }
    if headings[0] == 0 {
        findings.push(finding("seo.h1.missing", &[], "no <h1> element".into()));
    }
    let images_without_alt = facts.images.iter().filter(|i| i.alt.is_none()).count();
    if images_without_alt > 0 {
        findings.push(finding(
            "seo.images.alt",
            &[
                ("count", images_without_alt.to_string()),
                ("total", facts.images.len().to_string()),
            ],
            facts
                .images
                .iter()
                .filter(|i| i.alt.is_none())
                .filter_map(|i| i.src.clone())
                .take(5)
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    let declared_sitemaps = robots_txt.as_ref().is_some_and(|r| !r.sitemaps.is_empty());
    if let Some(s) = sitemap
        .as_ref()
        .filter(|s| matches!(s.state, "absent" | "not_sitemap") && !declared_sitemaps)
    {
        findings.push(finding(
            "seo.sitemap.missing",
            &[("url", s.url.clone())],
            format!("{}: {}", s.url, s.state),
        ));
    }

    let data = Seo {
        title_length: title.as_ref().map_or(0, |t| t.chars().count()),
        title,
        description_length: description.as_ref().map_or(0, |d| d.chars().count()),
        description,
        canonical,
        canonical_header,
        indexable: noindex_source.is_none() && !robots_txt.as_ref().is_some_and(|r| r.blocks_all),
        meta_robots,
        x_robots_tag,
        lang: facts.lang.clone(),
        viewport: facts.meta("viewport").is_some(),
        h1_count: headings[0],
        headings,
        open_graph: facts
            .metas
            .iter()
            .filter_map(|m| m.property.as_deref())
            .filter(|p| p.starts_with("og:"))
            .map(str::to_owned)
            .collect(),
        twitter_card: facts.meta("twitter:card").map(str::to_owned),
        structured_data: structured_data_types(facts),
        hreflang: facts
            .links_with_rel("alternate")
            .filter_map(|l| l.hreflang.clone())
            .collect(),
        images: facts.images.len(),
        images_without_alt,
        robots_txt,
        sitemap,
    };

    let (status, reason) = match &content.limitation {
        Some(l) => (Status::Partial, Some(l.clone())),
        None => (Status::Ok, None),
    };
    if !content.findings_allowed {
        findings.clear();
    }
    Module {
        status,
        reason,
        data: Some(data),
        findings: sorted(findings),
    }
}

fn sorted(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(b.id)));
    findings
}

fn robots_meta(facts: &PageFacts) -> Option<String> {
    facts
        .metas
        .iter()
        .filter(|m| {
            m.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case("robots") || n.eq_ignore_ascii_case("googlebot"))
        })
        .filter_map(|m| m.content.clone())
        .reduce(|a, b| format!("{a}, {b}"))
}

fn has_noindex(directives: &str) -> bool {
    directives
        .split(',')
        .map(|d| d.trim().to_ascii_lowercase())
        .any(|d| d == "noindex" || d == "none")
}

/// `X-Robots-Tag: noindex` or `X-Robots-Tag: googlebot: noindex`; directives for
/// other named bots do not count.
fn header_noindex(value: &str) -> bool {
    match value.split_once(':') {
        Some((agent, rest)) if !agent.contains(',') && !agent.trim().contains(' ') => {
            let agent = agent.trim().to_ascii_lowercase();
            (agent == "googlebot" || agent == "*") && has_noindex(rest)
        }
        _ => has_noindex(value),
    }
}

/// `Link: <https://x/>; rel="canonical"`.
fn canonical_from_header(hop: &Hop, base: &url::Url) -> Option<String> {
    hop.headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("link"))
        .flat_map(|(_, v)| v.split(','))
        .find_map(|entry| {
            let (target, params) = entry.split_once(';')?;
            let rel = params.split(';').any(|p| {
                let p = p.trim().to_ascii_lowercase();
                p == "rel=canonical" || p == "rel=\"canonical\""
            });
            let target = target.trim().strip_prefix('<')?.strip_suffix('>')?;
            if rel {
                base.join(target).ok().map(String::from)
            } else {
                None
            }
        })
}

fn structured_data_types(facts: &PageFacts) -> Vec<String> {
    let mut types = Vec::new();
    for block in &facts.json_ld {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(block) {
            collect_types(&value, &mut types);
        }
    }
    types.sort();
    types.dedup();
    types
}

fn collect_types(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            match map.get("@type") {
                Some(serde_json::Value::String(t)) => out.push(t.clone()),
                Some(serde_json::Value::Array(list)) => {
                    out.extend(list.iter().filter_map(|t| t.as_str().map(str::to_owned)))
                }
                _ => {}
            }
            for (key, child) in map {
                if key != "@type" {
                    collect_types(child, out);
                }
            }
        }
        serde_json::Value::Array(list) => list.iter().for_each(|v| collect_types(v, out)),
        _ => {}
    }
}

fn robots_report(file: &AuxFile) -> RobotsTxt {
    let body = String::from_utf8_lossy(&file.body);
    let state = match file.status {
        None => "failed",
        Some(200..=299) if sniff_html(&file.body) || body.to_ascii_lowercase().contains("<html") => "not_robots",
        Some(200..=299) => "found",
        Some(400..=499) => "absent",
        Some(_) => "server_error",
    };
    let found = state == "found";
    RobotsTxt {
        url: file.url.clone(),
        status: file.status,
        state,
        blocks_all: found && blocks_everything(&body),
        sitemaps: if found {
            body.lines()
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("sitemap"))
                .map(|(_, v)| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .collect()
        } else {
            Vec::new()
        },
    }
}

/// Whether the group for `User-agent: *` disallows the whole site with nothing
/// allowed back.
pub fn blocks_everything(robots: &str) -> bool {
    let mut in_star = false;
    let mut collecting_agents = false;
    let (mut disallow_all, mut allows) = (false, false);
    for raw in robots.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        match key.as_str() {
            "user-agent" => {
                if !collecting_agents {
                    in_star = false;
                }
                collecting_agents = true;
                in_star |= value == "*";
            }
            "disallow" | "allow" => {
                collecting_agents = false;
                if in_star {
                    if key == "disallow" && (value == "/" || value == "/*") {
                        disallow_all = true;
                    } else if key == "allow" && !value.is_empty() {
                        allows = true;
                    }
                }
            }
            _ => collecting_agents = false,
        }
    }
    disallow_all && !allows
}

fn sitemap_report(file: &AuxFile) -> Sitemap {
    let mut body = file.body.clone();
    if body.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        let _ = flate2::read::MultiGzDecoder::new(&file.body[..])
            .take(5 << 20)
            .read_to_end(&mut decoded);
        body = decoded;
    }
    let text = String::from_utf8_lossy(&body).to_ascii_lowercase();
    let (state, entries) = match file.status {
        None => ("failed", 0),
        Some(200..=299) if text.contains("<urlset") => {
            ("urlset", text.matches("<url>").count() + text.matches("<url ").count())
        }
        Some(200..=299) if text.contains("<sitemapindex") => ("sitemapindex", text.matches("<sitemap>").count()),
        Some(200..=299) => ("not_sitemap", 0),
        Some(400..=499) => ("absent", 0),
        Some(_) => ("failed", 0),
    };
    Sitemap {
        url: file.url.clone(),
        status: file.status,
        state,
        entries,
        truncated: file.truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(body: &str) -> Module<Seo> {
        let snapshot = crate::analyze::infra::tests::snapshot_with(200, &[("content-type", "text/html")], body);
        let content = crate::analyze::content::content(&snapshot);
        analyze(&snapshot, &content)
    }

    #[test]
    fn svg_title_is_not_the_page_title() {
        let module = run("<!doctype html><html><head><meta charset=utf-8></head><body>\
             <svg viewBox='0 0 1 1'><title>Logo da empresa</title><path d='M0 0'/></svg><h1>x</h1></body></html>");
        let ids: Vec<&str> = module.findings.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"seo.title.missing"), "{ids:?}");
        assert_eq!(module.data.unwrap().title, None);
    }

    #[test]
    fn head_title_wins_over_svg_title_in_the_body() {
        let module = run(
            "<!doctype html><html><head><title>Loja de Roupas Exemplo - Camisetas e Calcas</title></head><body>\
             <svg><title>Logo</title></svg></body></html>",
        );
        let data = module.data.unwrap();
        assert_eq!(
            data.title.as_deref(),
            Some("Loja de Roupas Exemplo - Camisetas e Calcas")
        );
    }

    #[test]
    fn robots_blocking_rules() {
        assert!(blocks_everything("User-agent: *\nDisallow: /\n"));
        assert!(!blocks_everything("User-agent: *\nDisallow: /\nAllow: /public\n"));
        assert!(!blocks_everything(
            "User-agent: BadBot\nDisallow: /\n\nUser-agent: *\nDisallow: /admin\n"
        ));
        assert!(blocks_everything(
            "User-agent: Googlebot\nUser-agent: *\nDisallow: / # all\n"
        ));
        assert!(!blocks_everything("User-agent: *\nDisallow:\n"));
    }

    #[test]
    fn noindex_in_meta_and_header() {
        assert!(has_noindex("noindex, follow"));
        assert!(has_noindex("NONE"));
        assert!(!has_noindex("index, follow"));
        assert!(header_noindex("noindex"));
        assert!(header_noindex("googlebot: noindex"));
        assert!(!header_noindex("otherbot: noindex"));
        assert!(header_noindex("noindex, nofollow"));
    }

    #[test]
    fn json_ld_types_including_graphs() {
        let facts = PageFacts {
            json_ld: vec![
                r#"{"@context":"https://schema.org","@graph":[{"@type":"Organization"},{"@type":["WebSite","Thing"]}]}"#.into(),
                "not json".into(),
            ],
            ..Default::default()
        };
        assert_eq!(structured_data_types(&facts), ["Organization", "Thing", "WebSite"]);
    }
}
