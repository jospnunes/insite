//! Network module: redirect chain, timing per phase, protocol, IPv6, HTTPS enforcement.

use std::time::Duration;

use serde::Serialize;
use url::Url;

use crate::findings::finding;
use crate::report::{Module, Status};
use crate::snapshot::{ConnectionInfo, ConnectionUse, FailureKind, Hop, HttpCheck, ResolutionSource, Snapshot};

#[derive(Debug, Clone, Serialize)]
pub struct Network {
    pub final_url: Option<String>,
    pub status: Option<u16>,
    pub protocol: Option<&'static str>,
    /// From t = 0 to the last byte of the final response, redirects included.
    pub total_ms: Option<f64>,
    pub redirects: Vec<Redirect>,
    /// Time spent before the final hop started.
    pub redirects_ms: f64,
    /// Phases of the final hop only.
    pub phases: Option<Phases>,
    /// The address connected to; absent behind a proxy, where it would be the proxy's.
    pub peer: Option<String>,
    /// `host:port` of the proxy that carried the final connection.
    pub proxy: Option<String>,
    /// Whether the final host has AAAA records; absent for IP literals.
    pub ipv6: Option<bool>,
    /// Absent when the DNS phase could not be timed (system resolver, IP literal, cache).
    pub dns_source: Option<&'static str>,
    pub https: HttpsEnforcement,
    /// Network retries used across the chain.
    pub retries: u32,
    pub page: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Redirect {
    pub url: String,
    pub status: u16,
    pub location: String,
    pub ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Phases {
    /// The final hop rode a connection opened by an earlier hop, so it has no
    /// DNS, TCP or TLS of its own.
    pub connection_reused: bool,
    pub dns_ms: Option<f64>,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: f64,
    pub download_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PageInfo {
    pub transferred_bytes: u64,
    pub size_bytes: u64,
    pub content_encoding: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpsEnforcement {
    /// Port 80 redirects to HTTPS.
    Redirects,
    /// Nothing answers on port 80, so there is no plain HTTP version to visit.
    NoHttpListener,
    /// Port 80 serves the page without redirecting.
    ServesHttp,
    /// Port 80 redirects, but to another plain HTTP address.
    RedirectsToHttp,
    /// HTTPS did not work and the page came over port 80.
    HttpsUnavailable,
    /// The port 80 check did not run (explicit port) or ended inconclusively.
    NotChecked,
}

pub fn analyze(snapshot: &Snapshot) -> Module<Network> {
    let Some(last) = snapshot.chain.last() else {
        let reason = snapshot
            .failure
            .as_ref()
            .map_or_else(|| "no response".to_owned(), |f| f.message.clone());
        let status = if snapshot.deadline_hit {
            Status::Timeout
        } else {
            Status::Failed
        };
        return Module {
            status,
            reason: Some(reason),
            data: None,
            findings: Vec::new(),
        };
    };

    let final_hop = (!last.is_redirect() || snapshot.failure.is_none()).then_some(last);
    let redirects = snapshot
        .chain
        .iter()
        .filter(|hop| hop.is_redirect())
        .map(|hop| Redirect {
            url: hop.url.clone(),
            status: hop.status,
            location: hop.header("location").unwrap_or_default().to_owned(),
            ms: ms(hop.ttfb + hop.download),
        })
        .collect();
    let redirects_ms = match snapshot.chain.len() {
        0 | 1 => 0.0,
        n => ms(snapshot.chain[n - 2].finished_at()),
    };
    let connection = final_hop.and_then(|hop| opener(&snapshot.chain, hop));

    let data = Network {
        final_url: final_hop.map(|h| h.url.clone()),
        status: final_hop.map(|h| h.status),
        protocol: final_hop.map(|h| h.version.as_str()),
        total_ms: final_hop.map(|h| ms(h.finished_at())),
        redirects,
        redirects_ms,
        phases: final_hop.map(phases),
        peer: connection
            .filter(|c| c.proxy.is_none())
            .map(|c| c.peer.ip().to_string()),
        proxy: connection.and_then(|c| c.proxy.clone()),
        ipv6: connection.and_then(|c| c.resolution.as_ref()).map(|r| r.has_ipv6),
        dns_source: connection.and_then(|c| c.resolution.as_ref()).map(|r| match r.source {
            ResolutionSource::Resolver => "resolver",
            ResolutionSource::System => "system",
        }),
        https: https_enforcement(snapshot),
        retries: snapshot
            .chain
            .iter()
            .map(|h| u32::from(h.attempts.saturating_sub(1)))
            .sum(),
        page: snapshot.page.as_ref().map(|p| PageInfo {
            transferred_bytes: p.transferred,
            size_bytes: p.body.len() as u64,
            content_encoding: p.content_encoding.clone(),
            truncated: p.truncated,
        }),
    };

    let mut findings = Vec::new();
    let mut status = Status::Ok;
    let mut reason = None;
    if let Some(failure) = &snapshot.failure {
        match failure.kind {
            FailureKind::RedirectLoop => {
                findings.push(finding(
                    "net.redirect.loop",
                    &[("url", failure.url.clone())],
                    failure.message.clone(),
                ));
            }
            FailureKind::TooManyRedirects => {
                let max = snapshot.chain.len().saturating_sub(1).to_string();
                findings.push(finding(
                    "net.redirect.too_many",
                    &[("max", max)],
                    failure.message.clone(),
                ));
            }
            FailureKind::Timeout => {
                status = Status::Timeout;
                reason = Some(failure.message.clone());
            }
            _ => {
                status = Status::Partial;
                reason = Some(failure.message.clone());
            }
        }
    } else if snapshot.deadline_hit {
        status = Status::Partial;
        reason = Some("the deadline expired while the page was downloading".to_owned());
    }

    Module {
        status,
        reason,
        data: Some(data),
        findings,
    }
}

fn phases(hop: &Hop) -> Phases {
    let (reused, info): (bool, Option<&ConnectionInfo>) = match &hop.connection {
        ConnectionUse::New(info) => (false, Some(info)),
        ConnectionUse::Reused => (true, None),
    };
    Phases {
        connection_reused: reused,
        dns_ms: info
            .and_then(|i| i.resolution.as_ref())
            .and_then(|r| r.duration)
            .map(ms),
        tcp_ms: info.map(|i| ms(i.tcp)),
        tls_ms: info.and_then(|i| i.tls.as_ref()).map(|t| ms(t.handshake)),
        ttfb_ms: ms(hop.ttfb),
        download_ms: ms(hop.download),
    }
}

/// The connection that carried `hop`: its own, or the latest one opened to the
/// same origin earlier in the chain.
pub(crate) fn opener<'a>(chain: &'a [Hop], hop: &'a Hop) -> Option<&'a ConnectionInfo> {
    let origin = |h: &Hop| Url::parse(&h.url).ok().map(|u| u.origin());
    let target = origin(hop)?;
    chain
        .iter()
        .rev()
        .filter(|h| origin(h).as_ref() == Some(&target))
        .find_map(|h| match &h.connection {
            ConnectionUse::New(info) => Some(info.as_ref()),
            ConnectionUse::Reused => None,
        })
}

fn https_enforcement(snapshot: &Snapshot) -> HttpsEnforcement {
    if snapshot.https_fallback.is_some() {
        return HttpsEnforcement::HttpsUnavailable;
    }
    let redirect_scheme = |base: &str, location: &str| {
        Url::parse(base)
            .and_then(|b| b.join(location))
            .ok()
            .map(|u| u.scheme().to_owned())
    };
    match &snapshot.http_check {
        Some(HttpCheck::Response { status, location, .. }) => {
            let http_url = Url::parse(&snapshot.input)
                .map(|mut u| {
                    let _ = u.set_scheme("http");
                    u.to_string()
                })
                .unwrap_or_default();
            match location {
                Some(loc) if (300..400).contains(status) => match redirect_scheme(&http_url, loc).as_deref() {
                    Some("https") => HttpsEnforcement::Redirects,
                    _ => HttpsEnforcement::RedirectsToHttp,
                },
                _ => HttpsEnforcement::ServesHttp,
            }
        }
        Some(HttpCheck::Failed(f)) if f.kind == FailureKind::Connect => HttpsEnforcement::NoHttpListener,
        Some(HttpCheck::Failed(_)) => HttpsEnforcement::NotChecked,
        // An http:// input: the first hop of the chain is the check.
        None => match snapshot.chain.first() {
            Some(first) if first.url.starts_with("http://") => match first.header("location") {
                Some(loc) if first.is_redirect() => match redirect_scheme(&first.url, loc).as_deref() {
                    Some("https") => HttpsEnforcement::Redirects,
                    _ => HttpsEnforcement::RedirectsToHttp,
                },
                _ => HttpsEnforcement::ServesHttp,
            },
            _ => HttpsEnforcement::NotChecked,
        },
    }
}

/// Milliseconds rounded to two decimals, so serialization is stable.
pub fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 100_000.0).round() / 100.0
}
