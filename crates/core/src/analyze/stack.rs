//! Stack module: technologies and versions, each with the evidence behind it.

use serde::Serialize;
use x509_parser::prelude::parse_x509_certificate;

use super::content::Content;
use super::infra;
use super::network::opener;
use crate::detect::{self, ElementIndex, Inputs, Technology};
use crate::report::{Module, Status};
use crate::snapshot::Snapshot;

#[derive(Debug, Clone, Serialize)]
pub struct Stack {
    pub technologies: Vec<Technology>,
    /// The signature base used, e.g. `enthec/webappanalyzer@d91f7e5 (2026-10-19)`.
    pub signatures: String,
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

    let limitation;
    match content {
        Ok(content) => {
            let facts = &content.facts;
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
            limitation = content.limitation.clone();
        }
        Err(reason) => {
            limitation = Some(format!(
                "only headers, cookies, DNS and the certificate were checked: {reason}"
            ))
        }
    }

    let engine = detect::engine();
    let technologies = engine.detect(&inputs);
    let (source, date) = engine.source();
    let data = Stack {
        technologies,
        signatures: format!("{} ({date})", short_source(source)),
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
