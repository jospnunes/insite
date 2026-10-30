//! Stack module: technologies and versions, each with the evidence behind it.

use serde::Serialize;
use x509_parser::prelude::parse_x509_certificate;

use super::content::Content;
use super::infra;
use super::network::opener;
use crate::detect::{self, ElementIndex, Inputs, Technology};
use crate::report::{Module, Status};
use crate::snapshot::{Hop, Snapshot};

#[derive(Debug, Clone, Serialize)]
pub struct Stack {
    /// With `--browser`, what the browser saw is merged in when it reached the
    /// same page: its versions win, and the evidence of both passes is kept.
    pub technologies: Vec<Technology>,
    /// The signature base used, e.g. `enthec/webappanalyzer@d91f7e5 (2026-10-19)`.
    pub signatures: String,
    /// The browser ended on another page (a mobile site, content by user
    /// agent): its stack is reported apart, never mixed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered: Option<RenderedStack>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedStack {
    pub url: String,
    pub technologies: Vec<Technology>,
}

/// Tags whose text is not visible page text.
const NOT_TEXT: &[&str] = &["script", "style", "noscript", "template", "title", "head"];

pub fn analyze(snapshot: &Snapshot, content: &Result<Content, String>) -> Module<Stack> {
    if let Some(challenge) = infra::challenge(snapshot) {
        let reason = format!(
            "{} answered with a bot challenge; nothing is concluded from it",
            challenge.name
        );
        return Module {
            status: Status::Partial,
            reason: Some(reason),
            data: None,
            findings: Vec::new(),
        };
    }
    let Some(last) = snapshot.chain.last() else {
        return Module {
            status: Status::Skipped,
            reason: Some("no response".into()),
            data: None,
            findings: Vec::new(),
        };
    };

    let (inputs, limitation) = static_inputs(snapshot, last, content);

    let engine = detect::engine();
    let mut technologies = engine.detect(&inputs);
    let (source, date) = engine.source();

    // The browser pass: the same signatures over the page JavaScript built,
    // plus what only a browser has (js properties, requests, element properties).
    let mut rendered = None;
    let browser = snapshot.browser.as_ref().filter(|b| b.html.is_some());
    let rendered_facts = browser.and_then(|b| {
        let url = url::Url::parse(&b.url).ok()?;
        Some(crate::extract::extract(
            b.html.as_deref()?.as_bytes(),
            Some("text/html; charset=utf-8"),
            &url,
        ))
    });
    if let (Some(b), Some(facts)) = (browser, rendered_facts.as_ref()) {
        let mut second = Inputs {
            headers: inputs.headers.clone(),
            cookies: inputs.cookies.clone(),
            dns: inputs.dns.clone(),
            cert_issuer: inputs.cert_issuer.clone(),
            robots: inputs.robots.clone(),
            url: vec![b.url.clone()],
            js: b.js.clone(),
            xhr: b
                .resources
                .iter()
                .filter(|r| r.kind == "XHR" || r.kind == "Fetch")
                .filter_map(|r| url::Url::parse(&r.url).ok()?.host_str().map(str::to_owned))
                .collect(),
            dom_properties: b
                .dom_properties
                .iter()
                .map(|(selector, property, values)| ((selector.clone(), property.clone()), values.clone()))
                .collect(),
            ..Default::default()
        };
        second.xhr.sort();
        second.xhr.dedup();
        fill_page(&mut second, facts);
        second
            .script_src
            .extend(b.resources.iter().filter(|r| r.kind == "Script").map(|r| r.url.clone()));
        let found = engine.detect(&second);
        if same_page(&b.url, &last.url) {
            merge(&mut technologies, found);
        } else {
            rendered = Some(RenderedStack {
                url: b.url.clone(),
                technologies: found,
            });
        }
    }
    let data = Stack {
        technologies,
        signatures: format!("{} ({date})", short_source(source)),
        rendered,
    };
    let status = if limitation.is_some() {
        Status::Partial
    } else {
        Status::Ok
    };
    Module {
        status,
        reason: limitation,
        data: Some(data),
        findings: Vec::new(),
    }
}

/// For the conformance test against the webappanalyzer JavaScript core: the
/// static inputs in that core's format, and what our engine detects in them
/// without the element index, which that core does not read (its browser
/// extension did). `None` where this module concludes nothing: a bot
/// challenge or no response.
#[doc(hidden)]
pub fn reference_case(snapshot: &Snapshot) -> Option<(serde_json::Value, Vec<Technology>)> {
    if infra::challenge(snapshot).is_some() {
        return None;
    }
    let last = snapshot.chain.last()?;
    let content = super::content::content(snapshot);
    let (mut inputs, _) = static_inputs(snapshot, last, &content);
    inputs.elements = None;
    let detected = detect::engine().detect(&inputs);
    Some((reference_items(&inputs), detected))
}

/// The inputs as the JavaScript core takes them: a string for each field read
/// whole, a list of script sources, and lists by lowercase key for the rest.
/// Inline scripts go as one text; the core reads that field whole. Our engine
/// reads them one by one, so a pattern anchored with `^` or `$`, or one spanning
/// two scripts, can differ there.
fn reference_items(inputs: &Inputs) -> serde_json::Value {
    fn by_key(pairs: &[(String, String)]) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        for (key, value) in pairs {
            if let serde_json::Value::Array(values) = map
                .entry(key.to_ascii_lowercase())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            {
                values.push(value.as_str().into());
            }
        }
        map
    }
    serde_json::json!({
        "url": inputs.url.first(),
        "html": inputs.html,
        "text": inputs.text,
        "scriptSrc": inputs.script_src,
        "scripts": inputs.scripts.join("\n"),
        "meta": by_key(&inputs.meta),
        "headers": by_key(&inputs.headers),
        "cookies": by_key(&inputs.cookies),
        "dns": by_key(&inputs.dns),
        "certIssuer": inputs.cert_issuer,
        "robots": inputs.robots,
    })
}

/// What the signatures see without a browser: the final response's headers
/// and URL, the chain's cookies, DNS, the certificate issuer, robots.txt and
/// the page, with what limits that reading.
fn static_inputs<'a>(
    snapshot: &Snapshot,
    last: &Hop,
    content: &'a Result<Content, String>,
) -> (Inputs<'a>, Option<String>) {
    let mut inputs = Inputs {
        headers: last
            .headers
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v.clone()))
            .collect(),
        cookies: snapshot
            .chain
            .iter()
            .flat_map(|hop| hop.headers.iter())
            .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
            .filter_map(|(_, v)| {
                let pair = v.split(';').next()?;
                let (name, value) = pair.split_once('=')?;
                Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect(),
        url: vec![last.url.clone()],
        ..Default::default()
    };
    for domain in &snapshot.dns {
        for (name, rtype) in [
            (domain.registrable.as_str(), "TXT"),
            (domain.registrable.as_str(), "MX"),
            (domain.registrable.as_str(), "NS"),
            (domain.registrable.as_str(), "SOA"),
            (domain.host.as_str(), "CNAME"),
        ] {
            inputs.dns.extend(
                domain
                    .records(name, rtype)
                    .iter()
                    .map(|r| (rtype.to_owned(), r.clone())),
            );
        }
    }
    inputs.cert_issuer = opener(&snapshot.chain, last)
        .and_then(|c| c.tls.as_ref())
        .and_then(|tls| tls.certificates.first())
        .and_then(|der| parse_x509_certificate(der).ok())
        .map(|(_, cert)| {
            let issuer = cert.issuer();
            issuer
                .iter_organization()
                .chain(issuer.iter_common_name())
                .filter_map(|a| a.as_str().ok())
                .collect::<Vec<_>>()
                .join(", ")
        });
    if let Some(robots) = snapshot.auxiliary.robots.as_ref().filter(|r| r.status == Some(200)) {
        inputs.robots = Some(String::from_utf8_lossy(&robots.body).into_owned());
    }

    let limitation = match content {
        Ok(content) => {
            fill_page(&mut inputs, &content.facts);
            content.limitation.clone()
        }
        Err(reason) => Some(format!(
            "only headers, cookies, DNS and the certificate were checked: {reason}"
        )),
    };
    (inputs, limitation)
}

/// The inputs that come from a page: metas, scripts, HTML, text and elements.
fn fill_page<'a>(inputs: &mut Inputs<'a>, facts: &'a crate::extract::PageFacts) {
    inputs.meta = facts
        .metas
        .iter()
        .filter_map(|m| {
            let key = m.name.as_deref().or(m.property.as_deref())?;
            Some((key.to_ascii_lowercase(), m.content.clone()?))
        })
        .collect();
    inputs.script_src = facts.scripts.iter().filter_map(|s| s.src.clone()).collect();
    inputs.scripts = facts.scripts.iter().filter_map(|s| s.inline.clone()).collect();
    inputs.html = Some(&facts.html);
    inputs.text = Some(visible_text(facts));
    inputs.elements = Some(ElementIndex::new(&facts.elements));
}

/// Whether two URLs are the same page, fragments aside.
fn same_page(a: &str, b: &str) -> bool {
    let strip = |u: &str| u.split('#').next().unwrap_or_default().trim_end_matches('/').to_owned();
    strip(a) == strip(b)
}

/// Adds the browser pass to the static one: new technologies are appended, a
/// version seen by the browser wins, and both passes' evidence is kept.
fn merge(technologies: &mut Vec<Technology>, browser: Vec<Technology>) {
    for found in browser {
        match technologies.iter_mut().find(|t| t.name == found.name) {
            Some(t) => {
                if found.version.is_some() {
                    t.version = found.version;
                }
                t.confidence = t.confidence.max(found.confidence);
                if found.implied_by.is_none() {
                    t.implied_by = None;
                }
                for e in found.evidence {
                    if !t.evidence.contains(&e) {
                        t.evidence.push(e);
                    }
                }
            }
            None => technologies.push(found),
        }
    }
}

fn visible_text(facts: &crate::extract::PageFacts) -> String {
    facts
        .elements
        .iter()
        .filter(|e| !e.text.trim().is_empty() && !NOT_TEXT.contains(&e.tag.as_str()))
        .map(|e| e.text.trim())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `enthec/webappanalyzer@d91f7e510e93...` shortened to seven characters of commit.
fn short_source(source: &str) -> String {
    match source.split_once('@') {
        Some((repo, commit)) if commit.len() > 7 => format!("{repo}@{}", &commit[..7]),
        _ => source.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Evidence;

    fn tech(name: &str, version: Option<&str>, field: &'static str) -> Technology {
        Technology {
            name: name.into(),
            version: version.map(str::to_owned),
            confidence: 100,
            categories: Vec::new(),
            website: None,
            evidence: vec![Evidence {
                field,
                key: None,
                value: name.to_lowercase(),
            }],
            implied_by: None,
        }
    }

    #[test]
    fn the_browser_pass_adds_and_refines() {
        let mut static_pass = vec![tech("React", None, "html"), tech("Nginx", None, "headers")];
        merge(
            &mut static_pass,
            vec![tech("React", Some("18.2.0"), "js"), tech("Sentry", None, "js")],
        );
        let names: Vec<&str> = static_pass.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["React", "Nginx", "Sentry"]);
        assert_eq!(static_pass[0].version.as_deref(), Some("18.2.0"));
        let fields: Vec<&str> = static_pass[0].evidence.iter().map(|e| e.field).collect();
        assert_eq!(fields, ["html", "js"]);
    }

    #[test]
    fn pages_compare_without_fragment_or_trailing_slash() {
        assert!(same_page("https://a.com/#top", "https://a.com"));
        assert!(!same_page("https://m.a.com/", "https://a.com/"));
    }
}
