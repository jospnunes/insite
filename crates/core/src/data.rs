//! Reference data embedded in the binary.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// A CA certificate disclosed to the root programs, from the CCADB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ca {
    pub kind: CaKind,
    pub state: CaState,
    pub name: &'static str,
    pub owner: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaKind {
    Root,
    Intermediate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaState {
    /// Trusted by Mozilla or Chrome (and, for intermediates, not revoked).
    Trusted,
    /// An intermediate revoked by its issuer, or under a revoked parent.
    Revoked,
    /// Disclosed but trusted by neither Mozilla nor Chrome.
    Untrusted,
    /// A root that Mozilla or Chrome removed or blocked.
    Removed,
}

const INTERMEDIATES: &str = include_str!("../data/intermediates.tsv");

/// Looks up a CA by subject key identifier, the value a child certificate
/// carries as its authority key identifier.
pub fn ca_by_key_id(key_id: &[u8]) -> Option<Ca> {
    static INDEX: OnceLock<HashMap<Vec<u8>, Ca>> = OnceLock::new();
    INDEX.get_or_init(|| parse(INTERMEDIATES)).get(key_id).copied()
}

fn parse(source: &'static str) -> HashMap<Vec<u8>, Ca> {
    let mut index = HashMap::new();
    for line in source.lines().filter(|l| !l.starts_with('#')) {
        let mut fields = line.split('\t');
        let (Some(ski), Some(kind), Some(state), Some(name), Some(owner)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let kind = match kind {
            "R" => CaKind::Root,
            _ => CaKind::Intermediate,
        };
        let state = match state {
            "trusted" => CaState::Trusted,
            "revoked" => CaState::Revoked,
            "removed" => CaState::Removed,
            _ => CaState::Untrusted,
        };
        if let Some(key) = hex(ski) {
            index.entry(key).or_insert(Ca {
                kind,
                state,
                name,
                owner,
            });
        }
    }
    index
}

const PROVIDERS: &str = include_str!("../data/providers.toml");

/// Providers recognized from DNS, mail, network and HTTP evidence.
#[derive(Debug, Deserialize)]
pub struct Providers {
    pub dns: Vec<NamedPatterns<NsField>>,
    pub mail: Vec<NamedPatterns<MxField>>,
    pub hosting: Vec<Hosting>,
    pub cdn: Vec<Cdn>,
    pub challenge: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
pub struct NamedPatterns<F> {
    pub name: String,
    #[serde(flatten)]
    pub patterns: F,
}

#[derive(Debug, Deserialize)]
pub struct NsField {
    pub ns: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MxField {
    pub mx: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Hosting {
    pub name: String,
    pub asn: Vec<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Cdn {
    pub name: String,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub server: Vec<String>,
    #[serde(default)]
    pub cname: Vec<String>,
    #[serde(default)]
    pub asn: Vec<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    pub name: String,
    pub signals: Vec<Signal>,
}

#[derive(Debug, Deserialize)]
pub struct Signal {
    #[serde(default)]
    pub status: Vec<u16>,
    pub header: Option<String>,
    pub value: Option<String>,
    pub body: Option<String>,
}

pub fn providers() -> &'static Providers {
    static PARSED: OnceLock<Providers> = OnceLock::new();
    PARSED.get_or_init(|| toml::from_str(PROVIDERS).expect("embedded providers.toml is valid"))
}

/// Whether `name` matches a provider pattern: a suffix on a label boundary, or
/// anywhere when the pattern starts with `~`.
pub fn name_matches(name: &str, pattern: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix('~') {
        Some(fragment) => name.contains(fragment),
        None => name == pattern || name.ends_with(&format!(".{pattern}")),
    }
}

const HSTS_PRELOAD: &str = include_str!("../data/hsts-preload.tsv");

/// Whether browsers preload HSTS for `host`: the host itself is on Chromium's
/// list, or a parent domain is, covering its subdomains. The same rule the
/// Observatory applies.
pub fn hsts_preloaded(host: &str) -> bool {
    static INDEX: OnceLock<HashMap<&'static str, bool>> = OnceLock::new();
    let index = INDEX.get_or_init(|| {
        HSTS_PRELOAD
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .map(|(name, subdomains)| (name, subdomains == "y"))
            .collect()
    });
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if index.contains_key(host.as_str()) {
        return true;
    }
    let mut parent = host.as_str();
    while let Some((_, rest)) = parent.split_once('.') {
        if index.get(rest) == Some(&true) {
            return true;
        }
        parent = rest;
    }
    false
}

const WEBAPPANALYZER_SOURCE: &str = include_str!("../data/webappanalyzer/SOURCE.toml");

/// The reference data embedded in this build, for the report's `sources`.
pub fn sources() -> Vec<crate::report::DataSource> {
    use crate::report::DataSource;
    #[derive(Deserialize)]
    struct Source {
        source: String,
        date: String,
    }
    let signatures: Source = toml::from_str(WEBAPPANALYZER_SOURCE).expect("embedded SOURCE.toml is valid");
    // "... on 2026.10.28." / "... as of 2026.10.28." in the first line of each file.
    let dated = |text: &str| {
        let first = text.lines().next().unwrap_or_default();
        first
            .split_whitespace()
            .find(|w| w.len() >= 10 && w.as_bytes()[0].is_ascii_digit())
            .map(|w| w.trim_end_matches('.').replace('.', "-"))
            .unwrap_or_default()
    };
    vec![
        DataSource {
            name: "webappanalyzer",
            version: format!("{} ({})", signatures.source, signatures.date),
            license: "GPL-3.0",
        },
        DataSource {
            name: "ccadb",
            version: dated(INTERMEDIATES),
            license: "CDLA-Permissive-2.0",
        },
        DataSource {
            name: "hsts-preload",
            version: format!("chromium ({})", dated(HSTS_PRELOAD)),
            license: "BSD-3-Clause",
        },
        DataSource {
            name: "observatory-scoring",
            version: "mdn/mdn-http-observatory@2776308".into(),
            license: "MPL-2.0",
        },
    ]
}

pub fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_parse_and_match_on_label_boundaries() {
        let p = providers();
        assert!(p.dns.len() > 10 && p.mail.len() > 10 && !p.cdn.is_empty() && !p.challenge.is_empty());
        assert!(name_matches("ns1.cloudflare.com.", "cloudflare.com"));
        assert!(!name_matches("notcloudflare.com", "cloudflare.com"));
        assert!(name_matches("ns-12.awsdns-01.org", "~awsdns-"));
    }

    #[test]
    fn finds_lets_encrypt_r12() {
        let ca = ca_by_key_id(&hex("00b529f22d8e6f31e89b4cad783efadce90cd1d2").unwrap()).unwrap();
        assert_eq!(
            (ca.kind, ca.state, ca.name),
            (CaKind::Intermediate, CaState::Trusted, "R12")
        );
    }

    #[test]
    fn hsts_preload_covers_subdomains_only_when_listed() {
        // bbc.co.uk is preloaded without subdomains (www has its own entry),
        // github.com with them.
        assert!(hsts_preloaded("bbc.co.uk"));
        assert!(!hsts_preloaded("news.bbc.co.uk"));
        assert!(hsts_preloaded("github.com"));
        assert!(hsts_preloaded("API.GitHub.com."));
        assert!(!hsts_preloaded("example.com"));
        // Whole TLDs are on the list too.
        assert!(hsts_preloaded("anything.dev"));
    }

    #[test]
    fn sources_name_their_versions() {
        let sources = sources();
        assert!(sources.iter().all(|s| !s.version.is_empty()), "{sources:?}");
        let ccadb = sources.iter().find(|s| s.name == "ccadb").unwrap();
        assert_eq!(ccadb.version.len(), 10, "{}", ccadb.version);
        assert!(sources[0].version.starts_with("enthec/webappanalyzer@"));
    }

    #[test]
    fn index_is_not_empty_and_parses_every_line() {
        let lines = INTERMEDIATES.lines().filter(|l| !l.starts_with('#')).count();
        assert!(lines > 1000);
        assert_eq!(parse(INTERMEDIATES).len(), lines);
    }
}
