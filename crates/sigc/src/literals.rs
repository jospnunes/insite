//! Literals every match of a regex must contain, for the Aho-Corasick prefilter.
//!
//! Three candidates are computed and the most selective one wins: the set of
//! possible prefixes and the set of possible suffixes (from regex-syntax's
//! extractor), and the longest literal required in the middle of a concatenation
//! (our own walk over the HIR, which the extractor does not provide).

use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Hir, HirKind};

/// Shorter literals appear everywhere and filter nothing.
pub const MIN_LEN: usize = 3;
/// More alternatives than this make the prefilter no better than running the regex.
const MAX_SET: usize = 32;

/// Lowercase needles of which any match contains at least one, or empty when no
/// useful set exists (the pattern then always runs).
pub fn needles(pattern: &str) -> Vec<String> {
    // Parsed without case folding, so literals keep one spelling; the prefilter
    // itself ignores ASCII case.
    let Ok(hir) = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(pattern)
    else {
        return Vec::new();
    };
    let mut candidates: Vec<Vec<Vec<u8>>> = Vec::new();
    for kind in [ExtractKind::Prefix, ExtractKind::Suffix] {
        let seq = Extractor::new().kind(kind).extract(&hir);
        if let Some(literals) = seq.literals() {
            candidates.push(literals.iter().map(|l| l.as_bytes().to_vec()).collect());
        }
    }
    if let Some(inner) = required(&hir) {
        candidates.push(vec![inner]);
    }

    candidates
        .into_iter()
        .filter(|set| !set.is_empty() && set.len() <= MAX_SET && set.iter().all(|l| l.len() >= MIN_LEN))
        .max_by_key(|set| {
            (
                set.iter().map(Vec::len).min().unwrap_or(0),
                std::cmp::Reverse(set.len()),
            )
        })
        .map(|set| {
            let mut needles: Vec<String> = set
                .iter()
                .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
                .collect();
            needles.sort();
            needles.dedup();
            needles
        })
        .unwrap_or_default()
}

/// The longest literal that every match must contain.
fn required(hir: &Hir) -> Option<Vec<u8>> {
    match hir.kind() {
        HirKind::Literal(lit) => Some(lit.0.to_vec()),
        HirKind::Capture(cap) => required(&cap.sub),
        HirKind::Repetition(rep) if rep.min >= 1 => required(&rep.sub),
        HirKind::Concat(subs) => {
            // Adjacent literals form one longer run.
            let mut best: Option<Vec<u8>> = None;
            let mut run: Vec<u8> = Vec::new();
            let consider = |candidate: Vec<u8>, best: &mut Option<Vec<u8>>| {
                if best.as_ref().is_none_or(|b| candidate.len() > b.len()) {
                    *best = Some(candidate);
                }
            };
            for sub in subs {
                match sub.kind() {
                    HirKind::Literal(lit) => run.extend_from_slice(&lit.0),
                    _ => {
                        if !run.is_empty() {
                            consider(std::mem::take(&mut run), &mut best);
                        }
                        if let Some(inner) = required(sub) {
                            consider(inner, &mut best);
                        }
                    }
                }
            }
            if !run.is_empty() {
                consider(run, &mut best);
            }
            best
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_literal() {
        assert_eq!(needles(r"wp-content/themes/([^/]+)"), ["wp-content/themes/"]);
    }

    #[test]
    fn alternation_gives_a_set() {
        assert_eq!(needles(r"(?:jquery|zepto)\.min\.js"), ["jquery.min.js", "zepto.min.js"]);
    }

    #[test]
    fn inner_literal_when_ends_vary() {
        assert_eq!(needles(r"[a-z]+/cdn-cgi/[0-9]+"), ["/cdn-cgi/"]);
    }

    #[test]
    fn short_or_missing_literals_mean_always_run() {
        assert!(needles(r"\d+").is_empty());
        assert!(needles(r"js").is_empty());
        assert!(needles(r"").is_empty());
    }

    #[test]
    fn needles_are_lowercase() {
        assert_eq!(needles("Shopify"), ["shopify"]);
    }
}
