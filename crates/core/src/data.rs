//! Reference data embedded in the binary.

use std::collections::HashMap;
use std::sync::OnceLock;

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
    fn finds_lets_encrypt_r12() {
        let ca = ca_by_key_id(&hex("00b529f22d8e6f31e89b4cad783efadce90cd1d2").unwrap()).unwrap();
        assert_eq!(
            (ca.kind, ca.state, ca.name),
            (CaKind::Intermediate, CaState::Trusted, "R12")
        );
    }

    #[test]
    fn index_is_not_empty_and_parses_every_line() {
        let lines = INTERMEDIATES.lines().filter(|l| !l.starts_with('#')).count();
        assert!(lines > 1000);
        assert_eq!(parse(INTERMEDIATES).len(), lines);
    }
}
