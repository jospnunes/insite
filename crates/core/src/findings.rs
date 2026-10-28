//! The findings catalog: one Markdown file per finding id, embedded in the binary.
//!
//! The same text feeds the report and `insite explain`. Placeholders such as
//! `{url}` are filled from the finding's params. A file looks like:
//!
//! ```text
//! severity: high
//! title: Redirect loop
//! ---
//! What happened and why it matters.
//!
//! ## Fix
//! How to fix it.
//! ```

use std::collections::BTreeMap;

use crate::report::{Finding, Severity};

macro_rules! catalog {
    ($($id:literal),* $(,)?) => {
        pub const CATALOG: &[(&str, &str)] = &[$(($id, include_str!(concat!("../findings/", $id, ".md")))),*];
    };
}

catalog![
    "net.redirect.loop",
    "net.redirect.too_many",
    "tls.cert.expired",
    "tls.cert.not_yet_valid",
    "tls.cert.expiring",
    "tls.cert.name_mismatch",
    "tls.cert.self_signed",
    "tls.chain.incomplete",
    "tls.cert.untrusted",
    "tls.cert.weak_key",
    "tls.cert.sha1",
    "tls.version.no_tls13",
    "tls.clock_skew",
    "tls.hop.invalid",
    "tls.handshake.incompatible",
    "mail.spoofable",
    "mail.spf.missing",
    "mail.spf.multiple",
    "mail.spf.too_many_lookups",
    "mail.spf.broken_include",
    "mail.spf.pass_all",
    "mail.spf.no_all",
    "mail.spf.ptr",
    "mail.dmarc.missing",
    "mail.dmarc.none",
    "mail.dmarc.invalid",
    "infra.challenge",
    "seo.noindex",
    "seo.robots.blocks_all",
    "seo.title.missing",
    "seo.title.length",
    "seo.description.missing",
    "seo.description.length",
    "seo.canonical.multiple",
    "seo.canonical.conflict",
    "seo.viewport.missing",
    "seo.lang.missing",
    "seo.h1.missing",
    "seo.images.alt",
    "seo.sitemap.missing",
    "weight.uncompressed",
    "weight.render_blocking",
    "weight.html_large",
];

pub struct Entry<'a> {
    pub severity: Severity,
    pub title: &'a str,
    pub detail: &'a str,
    pub fix: &'a str,
}

pub fn entry(id: &str) -> Option<Entry<'static>> {
    CATALOG
        .iter()
        .find(|(i, _)| *i == id)
        .and_then(|(_, source)| parse(source))
}

pub fn parse(source: &str) -> Option<Entry<'_>> {
    let (header, body) = source.split_once("\n---\n")?;
    let mut severity = None;
    let mut title = None;
    for line in header.lines() {
        match line.split_once(':') {
            Some(("severity", v)) => severity = Severity::parse(v.trim()),
            Some(("title", v)) => title = Some(v.trim()),
            _ => {}
        }
    }
    let (detail, fix) = body.split_once("\n## Fix\n")?;
    Some(Entry {
        severity: severity?,
        title: title?,
        detail: detail.trim(),
        fix: fix.trim(),
    })
}

/// Builds a finding from the catalog. Panics on an id missing from the catalog,
/// which the catalog test catches before release.
pub fn finding(id: &'static str, params: &[(&str, String)], evidence: String) -> Finding {
    let entry = entry(id).unwrap_or_else(|| panic!("finding `{id}` is missing from the catalog"));
    let params: BTreeMap<String, String> = params.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
    Finding {
        id,
        severity: entry.severity,
        title: fill(entry.title, &params),
        detail: fill(entry.detail, &params),
        fix: fill(entry.fix, &params),
        params,
        evidence,
    }
}

fn fill(template: &str, params: &BTreeMap<String, String>) -> String {
    params.iter().fold(template.to_owned(), |text, (key, value)| {
        text.replace(&format!("{{{key}}}"), value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalog_entry_parses() {
        for (id, source) in CATALOG {
            assert!(parse(source).is_some(), "catalog entry `{id}` is malformed");
        }
    }

    #[test]
    fn params_fill_the_text() {
        let f = finding(
            "net.redirect.loop",
            &[("url", "https://a.example/".into())],
            String::new(),
        );
        assert!(f.detail.contains("https://a.example/"));
        assert!(!f.detail.contains("{url}"));
    }
}
