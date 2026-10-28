//! Infrastructure module: address owner, hosting, CDN or edge proxy, and whether
//! the response was a bot challenge instead of the page.

use serde::Serialize;

use super::network::opener;
use crate::data::{Signal, name_matches, providers};
use crate::findings::finding;
use crate::report::{Module, Status};
use crate::snapshot::{Hop, Snapshot};

/// How much of the body challenge markers are searched in.
const BODY_WINDOW: usize = 64 << 10;

#[derive(Debug, Clone, Serialize)]
pub struct Infra {
    pub ip: Option<String>,
    pub asn: Option<u32>,
    /// As registered, e.g. `CLOUDFLARENET, US`.
    pub as_name: Option<String>,
    pub prefix: Option<String>,
    pub country: Option<String>,
    /// Friendly name of the network owner, when known.
    pub hosting: Option<String>,
    pub cdn: Vec<Detected>,
    pub challenge: Option<Detected>,
    pub server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detected {
    pub name: String,
    pub evidence: String,
}

pub fn analyze(snapshot: &Snapshot) -> Module<Infra> {
    let Some(last) = snapshot.chain.last() else {
        return Module {
            status: Status::Skipped,
            reason: Some("no response".into()),
            data: None,
            findings: Vec::new(),
        };
    };
    let asn = snapshot.asn.as_ref();
    let as_number = asn.and_then(|a| a.asn);
    let cnames: Vec<String> = snapshot
        .dns
        .iter()
        .flat_map(|d| d.records(&d.host, "CNAME").iter().cloned())
        .collect();

    let mut cdn: Vec<Detected> = Vec::new();
    for entry in &providers().cdn {
        let evidence = entry
            .headers
            .iter()
            .find(|h| last.header(h).is_some())
            .map(|h| format!("header {h}"))
            .or_else(|| {
                let server = last.header("server")?.to_ascii_lowercase();
                entry
                    .server
                    .iter()
                    .find(|s| server.contains(s.as_str()))
                    .map(|_| format!("Server: {server}"))
            })
            .or_else(|| {
                cnames
                    .iter()
                    .find(|c| entry.cname.iter().any(|p| name_matches(c, p)))
                    .map(|c| format!("CNAME {c}"))
            })
            .or_else(|| {
                as_number
                    .filter(|n| entry.asn.contains(n))
                    .map(|n| format!("address in AS{n}"))
            });
        if let Some(evidence) = evidence {
            cdn.push(Detected {
                name: entry.name.clone(),
                evidence,
            });
        }
    }

    let challenge = challenge(snapshot);
    let mut findings = Vec::new();
    if let Some(c) = &challenge {
        findings.push(finding(
            "infra.challenge",
            &[("provider", c.name.clone())],
            c.evidence.clone(),
        ));
    }

    let data = Infra {
        ip: opener(&snapshot.chain, last).map(|c| c.peer.ip().to_string()),
        asn: as_number,
        as_name: asn.and_then(|a| a.name.clone()),
        prefix: asn.and_then(|a| a.prefix.clone()),
        country: asn.and_then(|a| a.country.clone()),
        hosting: as_number.and_then(|n| {
            providers()
                .hosting
                .iter()
                .find(|h| h.asn.contains(&n))
                .map(|h| h.name.clone())
        }),
        cdn,
        challenge,
        server: last.header("server").map(str::to_owned),
    };
    let status = if asn.is_some_and(|a| a.error.is_some()) {
        Status::Partial
    } else {
        Status::Ok
    };
    let reason = asn
        .and_then(|a| a.error.clone())
        .map(|e| format!("AS lookup failed: {e}"));
    Module {
        status,
        reason,
        data: Some(data),
        findings,
    }
}

/// A bot challenge or block page served instead of the content. When present, the
/// page does not represent the site and nothing should be concluded from it.
pub fn challenge(snapshot: &Snapshot) -> Option<Detected> {
    let last = snapshot.chain.last()?;
    let body = snapshot
        .page
        .as_ref()
        .map(|p| String::from_utf8_lossy(&p.body[..p.body.len().min(BODY_WINDOW)]).into_owned())
        .unwrap_or_default();
    providers().challenge.iter().find_map(|c| {
        c.signals
            .iter()
            .find(|s| signal_matches(s, last, &body))
            .map(|s| Detected {
                name: c.name.clone(),
                evidence: describe(s, last),
            })
    })
}

fn signal_matches(signal: &Signal, hop: &Hop, body: &str) -> bool {
    let status_ok = signal.status.is_empty() || signal.status.contains(&hop.status);
    let header_ok = match &signal.header {
        None => true,
        Some(name) => hop.headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case(name)
                && signal
                    .value
                    .as_ref()
                    .is_none_or(|want| v.to_ascii_lowercase().contains(&want.to_ascii_lowercase()))
        }),
    };
    let body_ok = signal.body.as_ref().is_none_or(|marker| body.contains(marker.as_str()));
    status_ok && header_ok && body_ok
}

fn describe(signal: &Signal, hop: &Hop) -> String {
    let mut parts = Vec::new();
    if !signal.status.is_empty() {
        parts.push(format!("status {}", hop.status));
    }
    if let Some(name) = &signal.header {
        parts.push(format!("{name}: {}", hop.header(name).unwrap_or_default()));
    }
    if let Some(marker) = &signal.body {
        parts.push(format!("page contains `{marker}`"));
    }
    parts.join(", ")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::snapshot::{ConnectionUse, HttpVersion, Page, RequestProfile, SNAPSHOT_VERSION};
    use std::time::{Duration, SystemTime};

    pub fn snapshot_with(status: u16, headers: &[(&str, &str)], body: &str) -> Snapshot {
        Snapshot {
            snapshot_version: SNAPSHOT_VERSION,
            collector_version: "test".into(),
            collected_at: SystemTime::UNIX_EPOCH,
            duration: Duration::ZERO,
            input: "https://example.com/".into(),
            request: RequestProfile {
                user_agent: String::new(),
                accept_language: String::new(),
                accept_encoding: String::new(),
            },
            chain: vec![Hop {
                url: "https://example.com/".into(),
                connection: ConnectionUse::Reused,
                request_at: Duration::ZERO,
                ttfb: Duration::ZERO,
                download: Duration::ZERO,
                status,
                version: HttpVersion::Http2,
                headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
                attempts: 1,
            }],
            page: Some(Page {
                body: body.as_bytes().to_vec(),
                transferred: 0,
                content_encoding: None,
                truncated: false,
                decode_error: None,
            }),
            http_check: None,
            https_fallback: None,
            failure: None,
            deadline_hit: false,
            dns: Vec::new(),
            asn: None,
        }
    }

    #[test]
    fn cloudflare_challenge_by_header() {
        let snap = snapshot_with(
            403,
            &[("cf-mitigated", "challenge"), ("server", "cloudflare")],
            "<html>",
        );
        assert_eq!(challenge(&snap).unwrap().name, "Cloudflare");
    }

    #[test]
    fn a_normal_cloudflare_page_is_not_a_challenge() {
        let snap = snapshot_with(200, &[("server", "cloudflare"), ("cf-ray", "x")], "<html>hello</html>");
        assert!(challenge(&snap).is_none());
        let infra = analyze(&snap).data.unwrap();
        assert_eq!(
            infra.cdn,
            [Detected {
                name: "Cloudflare".into(),
                evidence: "header cf-ray".into()
            }]
        );
    }

    #[test]
    fn body_markers_need_the_status_too() {
        let page = r#"<script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>"#;
        let ok = snapshot_with(200, &[("server", "cloudflare")], page);
        assert!(challenge(&ok).is_none());
        let blocked = snapshot_with(403, &[("server", "cloudflare")], page);
        assert_eq!(challenge(&blocked).unwrap().name, "Cloudflare");
    }
}
