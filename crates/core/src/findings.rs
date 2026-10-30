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
    "sec.https.unavailable",
    "sec.https.downgrade",
    "sec.csp.missing",
    "sec.csp.report_only",
    "sec.csp.invalid",
    "sec.csp.unsafe_inline",
    "sec.csp.insecure_scheme",
    "sec.csp.unsafe_eval",
    "sec.csp.insecure_passive",
    "sec.cookies.session_insecure",
    "sec.cookies.session_httponly",
    "sec.cookies.csrf_samesite",
    "sec.cookies.samesite_invalid",
    "sec.cookies.insecure",
    "sec.cookies.session_insecure_hsts",
    "sec.cookies.insecure_hsts",
    "sec.redirect.missing",
    "sec.redirect.not_https",
    "sec.redirect.initial_http",
    "sec.redirect.off_host",
    "sec.referrer.unsafe",
    "sec.referrer.invalid",
    "sec.hsts.missing",
    "sec.hsts.invalid",
    "sec.hsts.short",
    "sec.sri.missing",
    "sec.sri.insecure",
    "sec.xcto.missing",
    "sec.xcto.invalid",
    "sec.xfo.missing",
    "sec.xfo.invalid",
    "sec.corp.invalid",
    "sec.coep.invalid",
    "sec.coop.invalid",
    "sec.mixed_content.active",
    "sec.mixed_content.passive",
    "sec.form.insecure",
    "sec.version_leak",
    "sec.permissions_policy.missing",
    "sec.security_txt.expired",
    "perf.lcp.poor",
    "perf.cls.poor",
    "perf.tbt.poor",
    "browser.console_errors",
    "browser.requests_failed",
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
    let (header, body) = split_at_line(source, "---")?;
    let mut severity = None;
    let mut title = None;
    for line in header.lines() {
        match line.split_once(':') {
            Some(("severity", v)) => severity = Severity::parse(v.trim()),
            Some(("title", v)) => title = Some(v.trim()),
            _ => {}
        }
    }
    let (detail, fix) = split_at_line(body, "## Fix")?;
    Some(Entry {
        severity: severity?,
        title: title?,
        detail: detail.trim(),
        fix: fix.trim(),
    })
}

/// The text before and after the first line that reads `marker`, with LF or
/// CRLF line endings alike (a Windows checkout may convert them).
fn split_at_line<'a>(text: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let end = start + line.len();
        if line.trim_end() == marker {
            return Some((&text[..start], &text[end..]));
        }
        start = end;
    }
    None
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
    // One pass over the template, so a value that happens to hold `{other}` is never
    // expanded by a later parameter. Unknown placeholders stay as written.
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after
            .find('}')
            .and_then(|close| params.get(&after[..close]).map(|v| (close, v)))
        {
            Some((close, value)) => {
                out.push_str(value);
                rest = &after[close + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
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
    fn every_catalog_file_is_registered() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/findings");
        for file in std::fs::read_dir(dir).unwrap() {
            let name = file.unwrap().file_name().into_string().unwrap();
            let id = name.strip_suffix(".md").unwrap_or(&name);
            assert!(
                CATALOG.iter().any(|(i, _)| *i == id),
                "{name} is not in the catalog! list"
            );
        }
    }

    #[test]
    fn crlf_entries_parse_too() {
        let source = "severity: low\r\ntitle: T\r\n---\r\nDetail.\r\n\r\n## Fix\r\nFix it.\r\n";
        let entry = parse(source).unwrap();
        assert_eq!((entry.title, entry.detail, entry.fix), ("T", "Detail.", "Fix it."));
    }

    #[test]
    fn fill_does_not_expand_placeholders_inside_values() {
        // "a" sorts before "domain": a sequential replace would expand the `{domain}` that
        // arrived inside a server-controlled value.
        let params: BTreeMap<String, String> = [("a", "x{domain}y"), ("domain", "example.com")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        assert_eq!(
            fill("{a} and {domain} {unknown} {", &params),
            "x{domain}y and example.com {unknown} {"
        );
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
