//! Host resolution for the connection engine.
//!
//! A and AAAA go out in parallel. The DNS phase ends at the first address, and
//! connecting starts after the RFC 8305 resolution delay; an AAAA answer that is
//! still pending at that point keeps running so the report can say whether the
//! host has IPv6 without holding up the connection.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolveHosts;
use hickory_resolver::proto::rr::{RData, RecordType};
use tokio::task::JoinHandle;

use crate::snapshot::{FailureKind, HostResolution, ResolutionSource};

/// How long to wait for AAAA once A has answered (RFC 8305, section 3).
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub struct Resolver {
    inner: TokioResolver,
}

pub struct DnsError {
    pub kind: FailureKind,
    pub message: String,
    /// A timeout or server failure, worth one more attempt; NXDOMAIN is not.
    pub retryable: bool,
}

/// A resolution that may still be waiting for its AAAA answer.
pub struct Resolved {
    pub resolution: HostResolution,
    late_ipv6: Option<JoinHandle<Vec<IpAddr>>>,
}

impl Resolved {
    /// Waits for the AAAA answer that missed the resolution delay. Called after
    /// the page arrived, when it has long finished.
    pub async fn settle(&mut self) {
        if let Some(handle) = self.late_ipv6.take()
            && let Ok(v6) = handle.await
        {
            self.resolution.has_ipv6 = !v6.is_empty();
        }
    }
}

impl Resolver {
    /// Uses the system configuration (`/etc/resolv.conf`, the Windows registry) and
    /// the hosts file. Our own retry layer decides on retries, so hickory gets one
    /// attempt per query.
    pub fn from_system() -> Result<Self, String> {
        let mut builder =
            TokioResolver::builder_tokio().map_err(|e| format!("cannot read the system DNS configuration: {e}"))?;
        let opts = builder.options_mut();
        opts.use_hosts_file = ResolveHosts::Always;
        opts.attempts = 1;
        opts.timeout = Duration::from_secs(2);
        let inner = builder
            .build()
            .map_err(|e| format!("cannot build the DNS resolver: {e}"))?;
        Ok(Resolver { inner })
    }

    pub async fn resolve(&self, host: &str) -> Result<Resolved, DnsError> {
        let start = Instant::now();
        let mut v4 = tokio::spawn(lookup(self.inner.clone(), host.to_owned(), RecordType::A));
        let mut v6 = tokio::spawn(lookup(self.inner.clone(), host.to_owned(), RecordType::AAAA));

        // Whichever family answers first marks the end of the DNS phase.
        let (first_family, first) = tokio::select! {
            r = &mut v4 => (RecordType::A, joined(r)),
            r = &mut v6 => (RecordType::AAAA, joined(r)),
        };
        let mut first_at = first.as_ref().ok().filter(|a| !a.is_empty()).map(|_| start.elapsed());

        let (mut ipv4, mut ipv6, mut late_ipv6) = (Vec::new(), Vec::new(), None);
        let mut errors = Vec::new();
        match first_family {
            RecordType::A => {
                take(first, &mut ipv4, &mut errors);
                // With A in hand, give AAAA the resolution delay before connecting;
                // without A, there is nothing to connect to yet, so wait for it.
                let wait = if ipv4.is_empty() { None } else { Some(RESOLUTION_DELAY) };
                match wait {
                    Some(delay) => match tokio::time::timeout(delay, &mut v6).await {
                        Ok(r) => take(joined(r), &mut ipv6, &mut errors),
                        Err(_) => late_ipv6 = Some(v6),
                    },
                    None => take(joined(v6.await), &mut ipv6, &mut errors),
                }
            }
            _ => {
                take(first, &mut ipv6, &mut errors);
                // IPv6 goes first in the race, but A is still needed as a fallback.
                take(joined(v4.await), &mut ipv4, &mut errors);
            }
        }
        if first_at.is_none() && !(ipv4.is_empty() && ipv6.is_empty()) {
            first_at = Some(start.elapsed());
        }

        if ipv4.is_empty() && ipv6.is_empty() {
            return self.system_fallback(host, errors).await;
        }
        let has_ipv6 = !ipv6.is_empty();
        let addresses = ipv6.into_iter().chain(ipv4).collect();
        Ok(Resolved {
            resolution: HostResolution {
                host: host.to_owned(),
                duration: first_at,
                addresses,
                has_ipv6,
                source: ResolutionSource::Resolver,
            },
            late_ipv6: late_ipv6.map(|handle| tokio::spawn(async move { joined(handle.await).unwrap_or_default() })),
        })
    }

    /// Our resolver found nothing. The operating system may still know the name
    /// (VPN with split DNS, internal names, mDNS); if it does, we use its answer and
    /// say so, since we cannot time it.
    async fn system_fallback(&self, host: &str, errors: Vec<LookupError>) -> Result<Resolved, DnsError> {
        if let Ok(addrs) = tokio::net::lookup_host((host, 0)).await {
            let mut addresses: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            addresses.dedup();
            if !addresses.is_empty() {
                let has_ipv6 = addresses.iter().any(IpAddr::is_ipv6);
                return Ok(Resolved {
                    resolution: HostResolution {
                        host: host.to_owned(),
                        duration: None,
                        addresses,
                        has_ipv6,
                        source: ResolutionSource::System,
                    },
                    late_ipv6: None,
                });
            }
        }
        let retryable = errors.iter().any(|e| e.retryable);
        let message = if errors.iter().all(|e| e.no_records) {
            format!("{host} does not exist or has no A/AAAA records")
        } else {
            let detail: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
            format!("could not resolve {host}: {}", detail.join("; "))
        };
        Err(DnsError {
            kind: FailureKind::Dns,
            message,
            retryable,
        })
    }
}

struct LookupError {
    message: String,
    no_records: bool,
    retryable: bool,
}

async fn lookup(resolver: TokioResolver, host: String, record_type: RecordType) -> Result<Vec<IpAddr>, LookupError> {
    match resolver.lookup(host.as_str(), record_type).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                _ => None,
            })
            .collect()),
        Err(e) if e.is_no_records_found() || e.is_nx_domain() => Ok(Vec::new()),
        Err(e) => Err(LookupError {
            message: e.to_string(),
            no_records: false,
            retryable: true,
        }),
    }
}

fn joined(r: Result<Result<Vec<IpAddr>, LookupError>, tokio::task::JoinError>) -> Result<Vec<IpAddr>, LookupError> {
    r.unwrap_or_else(|e| {
        Err(LookupError {
            message: format!("lookup task failed: {e}"),
            no_records: false,
            retryable: false,
        })
    })
}

fn take(r: Result<Vec<IpAddr>, LookupError>, into: &mut Vec<IpAddr>, errors: &mut Vec<LookupError>) {
    match r {
        Ok(addrs) if addrs.is_empty() => errors.push(LookupError {
            message: "no records".into(),
            no_records: true,
            retryable: false,
        }),
        Ok(addrs) => into.extend(addrs),
        Err(e) => errors.push(e),
    }
}
