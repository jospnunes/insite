//! SPF (RFC 7208) parsing and DNS lookup counting. Used by the collection, to know
//! which includes to fetch, and by the analysis.

use std::collections::HashSet;

/// Mechanisms and modifiers that cost a DNS lookup count against this limit.
pub const LOOKUP_LIMIT: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Include(String),
    A,
    Mx,
    Ptr,
    Exists,
    Ip,
    /// `-all`, `~all`, `?all` or `+all`, with the qualifier kept.
    All(char),
    Redirect(String),
    Other(String),
}

impl Term {
    pub fn costs_lookup(&self) -> bool {
        matches!(
            self,
            Term::Include(_) | Term::A | Term::Mx | Term::Ptr | Term::Exists | Term::Redirect(_)
        )
    }
}

/// The SPF records among a name's TXT records (more than one is an error).
pub fn records(txt: &[String]) -> Vec<&str> {
    txt.iter()
        .map(String::as_str)
        .filter(|t| {
            let t = t.trim_start();
            t.len() >= 6 && t[..6].eq_ignore_ascii_case("v=spf1") && t[6..].chars().next().is_none_or(|c| c == ' ')
        })
        .collect()
}

pub fn parse(record: &str) -> Vec<Term> {
    record
        .split_whitespace()
        .skip(1)
        .map(|raw| {
            let (qualifier, body) = match raw.chars().next() {
                Some(q @ ('+' | '-' | '~' | '?')) => (q, &raw[1..]),
                _ => ('+', raw),
            };
            let lower = body.to_ascii_lowercase();
            let (name, arg) = match lower.split_once([':', '=']) {
                Some((n, _)) => (n.to_owned(), Some(body[n.len() + 1..].to_owned())),
                None => (lower.split('/').next().unwrap_or_default().to_owned(), None),
            };
            match (name.as_str(), arg) {
                ("include", Some(domain)) => Term::Include(domain.trim_end_matches('.').to_ascii_lowercase()),
                ("redirect", Some(domain)) => Term::Redirect(domain.trim_end_matches('.').to_ascii_lowercase()),
                ("a", _) => Term::A,
                ("mx", _) => Term::Mx,
                ("ptr", _) => Term::Ptr,
                ("exists", _) => Term::Exists,
                ("ip4" | "ip6", _) => Term::Ip,
                ("all", None) => Term::All(qualifier),
                _ => Term::Other(raw.to_owned()),
            }
        })
        .collect()
}

/// Result of walking the include tree from one domain.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Walk {
    pub lookups: usize,
    /// Includes or redirects whose target has no SPF record or does not exist.
    pub broken: Vec<String>,
    /// Targets whose TXT records were not available (not fetched or failed), so
    /// `lookups` is a lower bound.
    pub unknown: Vec<String>,
    pub uses_ptr: bool,
    pub has_macros: bool,
}

/// Counts DNS lookups from `domain` through includes and redirects. `txt` gives the
/// TXT records of a name: `Some(records)` when the query answered (possibly empty),
/// `None` when it was not made or failed.
pub fn walk<'a>(domain: &str, txt: &dyn Fn(&str) -> Option<&'a [String]>) -> Walk {
    let mut walk = Walk::default();
    let mut visited = HashSet::new();
    visit(domain, txt, &mut walk, &mut visited, 0);
    walk
}

fn visit<'a>(
    domain: &str,
    txt: &dyn Fn(&str) -> Option<&'a [String]>,
    walk: &mut Walk,
    visited: &mut HashSet<String>,
    depth: usize,
) {
    if depth > LOOKUP_LIMIT || walk.lookups > LOOKUP_LIMIT || !visited.insert(domain.to_owned()) {
        return;
    }
    let Some(records) = txt(domain) else {
        walk.unknown.push(domain.to_owned());
        return;
    };
    let spf = self::records(records);
    let Some(record) = spf.first() else {
        if depth > 0 {
            walk.broken.push(domain.to_owned());
        }
        return;
    };
    let terms = parse(record);
    let has_all = terms.iter().any(|t| matches!(t, Term::All(_)));
    for term in &terms {
        // A redirect is ignored when the record has an `all`.
        if matches!(term, Term::Redirect(_)) && has_all {
            continue;
        }
        if term.costs_lookup() {
            walk.lookups += 1;
        }
        match term {
            Term::Ptr => walk.uses_ptr = true,
            Term::Include(target) | Term::Redirect(target) => {
                if target.contains('%') {
                    walk.has_macros = true;
                } else {
                    visit(target, txt, walk, visited, depth + 1);
                }
            }
            _ => {}
        }
    }
}

/// Targets the collection should fetch next, given what is known so far.
pub fn pending_targets<'a>(domain: &str, txt: &dyn Fn(&str) -> Option<&'a [String]>) -> Vec<String> {
    let walk = walk(domain, txt);
    if walk.lookups > LOOKUP_LIMIT {
        return Vec::new();
    }
    walk.unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn zone(entries: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(n, t)| (n.to_string(), vec![t.to_string()]))
            .collect()
    }

    #[test]
    fn parses_terms_and_qualifiers() {
        let terms = parse("v=spf1 ip4:192.0.2.0/24 a mx/24 include:_spf.Google.com. ~all");
        assert_eq!(
            terms,
            [
                Term::Ip,
                Term::A,
                Term::Mx,
                Term::Include("_spf.google.com".into()),
                Term::All('~')
            ]
        );
        assert_eq!(
            parse("v=spf1 redirect=_spf.example.com"),
            [Term::Redirect("_spf.example.com".into())]
        );
    }

    #[test]
    fn finds_spf_among_txt() {
        let txt = vec![
            "google-site-verification=x".into(),
            "v=spf1 -all".into(),
            "v=spf10 x".into(),
        ];
        assert_eq!(records(&txt), ["v=spf1 -all"]);
    }

    #[test]
    fn counts_nested_lookups_and_broken_includes() {
        let z = zone(&[
            ("example.com", "v=spf1 a mx include:a.example include:gone.example -all"),
            ("a.example", "v=spf1 include:b.example ip4:192.0.2.1 ~all"),
            ("b.example", "v=spf1 exists:%{i}.x.example ptr ~all"),
            ("gone.example", "some other text"),
        ]);
        let lookup = |d: &str| z.get(d).map(Vec::as_slice);
        let w = walk("example.com", &lookup);
        // a, mx, include a, include gone, include b, exists, ptr
        assert_eq!(w.lookups, 7);
        assert_eq!(w.broken, ["gone.example"]);
        assert!(w.uses_ptr && w.unknown.is_empty());
    }

    #[test]
    fn unknown_targets_are_pending_until_the_limit_is_passed() {
        let z = zone(&[("example.com", "v=spf1 include:x.example include:y.example -all")]);
        let lookup = |d: &str| z.get(d).map(Vec::as_slice);
        assert_eq!(pending_targets("example.com", &lookup), ["x.example", "y.example"]);

        let many = format!("v=spf1 {}-all", "a ".repeat(11));
        let z = zone(&[("example.com", many.as_str())]);
        let lookup = |d: &str| z.get(d).map(Vec::as_slice);
        assert!(pending_targets("example.com", &lookup).is_empty());
        assert_eq!(walk("example.com", &lookup).lookups, 11);
    }

    #[test]
    fn include_loops_terminate() {
        let z = zone(&[
            ("a.example", "v=spf1 include:b.example -all"),
            ("b.example", "v=spf1 include:a.example -all"),
        ]);
        let lookup = |d: &str| z.get(d).map(Vec::as_slice);
        assert_eq!(walk("a.example", &lookup).lookups, 2);
    }
}
