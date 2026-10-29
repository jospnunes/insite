//! Host resolution for the connection engine.
//!
//! A and AAAA go out in parallel. The DNS phase ends at the first address, and
//! connecting starts after the RFC 8305 resolution delay; an AAAA answer that is
//! still pending at that point keeps running so the report can say whether the
//! host has IPv6 without holding up the connection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError, NoRecords};
use hickory_resolver::proto::op::{Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::recursor::{Recursor, RecursorOptions};
use hickory_resolver::{ResolverBuilder, TokioResolver};
use tokio::task::JoinHandle;

use crate::snapshot::{DnsResult, FailureKind, HostResolution, ResolutionSource};

/// How long to wait for AAAA once A has answered (RFC 8305, section 3).
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

/// The root servers' IPv4 addresses (IANA root hints), where iterative
/// resolution starts.
const ROOT_SERVERS: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),
    Ipv4Addr::new(170, 247, 170, 2),
    Ipv4Addr::new(192, 33, 4, 12),
    Ipv4Addr::new(199, 7, 91, 13),
    Ipv4Addr::new(192, 203, 230, 10),
    Ipv4Addr::new(192, 5, 5, 241),
    Ipv4Addr::new(192, 112, 36, 4),
    Ipv4Addr::new(198, 97, 190, 53),
    Ipv4Addr::new(192, 36, 148, 17),
    Ipv4Addr::new(192, 58, 128, 30),
    Ipv4Addr::new(193, 0, 14, 129),
    Ipv4Addr::new(199, 7, 83, 42),
    Ipv4Addr::new(202, 12, 27, 33),
];

#[derive(Clone)]
pub struct Resolver {
    inner: TokioResolver,
    /// Iterative resolution from the root servers, to find a zone's own servers
    /// without the system resolver that just failed. Absent in the tests, which
    /// have no root.
    iterative: Option<Arc<Recursor<TokioRuntimeProvider>>>,
    /// Where zones' own name servers listen: 53, or a local port in the tests.
    authoritative_port: u16,
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
    /// the hosts file.
    pub fn from_system() -> Result<Self, String> {
        let builder =
            TokioResolver::builder_tokio().map_err(|e| format!("cannot read the system DNS configuration: {e}"))?;
        let mut resolver = Self::finish(builder, ResolveHosts::Always)?;
        let roots = ROOT_SERVERS.map(IpAddr::V4);
        resolver.iterative =
            Recursor::with_options(&roots, RecursorOptions::default(), TokioRuntimeProvider::default())
                .ok()
                .map(Arc::new);
        Ok(resolver)
    }

    /// Sends every query to one name server. Tests point it at a local server.
    pub fn with_nameserver(addr: SocketAddr) -> Result<Self, String> {
        let mut server = NameServerConfig::udp(addr.ip());
        for connection in &mut server.connections {
            connection.port = addr.port();
        }
        let config = ResolverConfig::from_name_servers(vec![server]);
        Self::finish(
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default()),
            ResolveHosts::Always,
        )
    }

    /// Tests run the zones' name servers on a local port.
    pub fn with_authoritative_port(mut self, port: u16) -> Self {
        self.authoritative_port = port;
        self
    }

    /// Asks one of a zone's own name servers directly, over UDP and then TCP when
    /// the answer is truncated, without asking it to recurse. Only public
    /// addresses: a zone's NS can name any host, and following one into the local
    /// network would make insite probe it for the site being analyzed. Tests,
    /// which move the port, run their name servers on loopback.
    pub fn authoritative(&self, ip: IpAddr) -> Result<Self, String> {
        if self.authoritative_port == 53 && !is_public(ip) {
            return Err(format!("{ip} is not a public address"));
        }
        let mut server = NameServerConfig::udp_and_tcp(ip);
        for connection in &mut server.connections {
            connection.port = self.authoritative_port;
        }
        let config = ResolverConfig::from_name_servers(vec![server]);
        let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().recursion_desired = false;
        let mut resolver = Self::finish(builder, ResolveHosts::Never)?;
        resolver.authoritative_port = self.authoritative_port;
        Ok(resolver)
    }

    /// Our own retry layer decides on retries, so hickory gets one attempt per query.
    fn finish(mut builder: ResolverBuilder<TokioRuntimeProvider>, hosts: ResolveHosts) -> Result<Self, String> {
        let opts = builder.options_mut();
        opts.use_hosts_file = hosts;
        opts.attempts = 1;
        opts.timeout = Duration::from_secs(2);
        let inner = builder
            .build()
            .map_err(|e| format!("cannot build the DNS resolver: {e}"))?;
        Ok(Resolver {
            inner,
            iterative: None,
            authoritative_port: 53,
        })
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

    /// One query, recorded as found, empty, nonexistent or failed.
    pub async fn query(&self, name: &str, record_type: RecordType) -> DnsResult {
        let name = match fqdn(name) {
            Ok(name) => name,
            Err(e) => return DnsResult::Failed(e),
        };
        match self.inner.lookup(name, record_type).await {
            Ok(lookup) => {
                let records = presentation(lookup.answers(), record_type);
                if records.is_empty() {
                    DnsResult::Empty
                } else {
                    DnsResult::Records(records)
                }
            }
            Err(e) if e.is_nx_domain() => DnsResult::NxDomain,
            Err(e) if e.is_no_records_found() => DnsResult::Empty,
            Err(e) => DnsResult::Failed(e.to_string()),
        }
    }

    /// A query for finding a zone's servers. The system resolver races iterative
    /// resolution from the root servers, and the first answer wins: the system
    /// resolver is quicker while it works, and the root does not depend on it when
    /// it fails. Without iterative resolution (the tests), only the system resolver
    /// is asked.
    pub async fn query_for_servers(&self, name: &str, record_type: RecordType) -> DnsResult {
        let Some(recursor) = &self.iterative else {
            return self.query(name, record_type).await;
        };
        let iterative = async {
            let name = match fqdn(name) {
                Ok(name) => name,
                Err(e) => return DnsResult::Failed(e),
            };
            match recursor
                .resolve(Query::query(name, record_type), Instant::now(), false)
                .await
            {
                Ok(message) => {
                    let records = presentation(&message.answers, record_type);
                    if records.is_empty() {
                        DnsResult::Empty
                    } else {
                        DnsResult::Records(records)
                    }
                }
                Err(e) if e.is_nx_domain() => DnsResult::NxDomain,
                Err(e) if e.is_no_records_found() => DnsResult::Empty,
                Err(e) => DnsResult::Failed(e.to_string()),
            }
        };
        let system = self.query(name, record_type);
        tokio::pin!(system, iterative);
        tokio::select! {
            result = &mut system => match result {
                DnsResult::Failed(_) => iterative.await,
                result => result,
            },
            result = &mut iterative => match result {
                DnsResult::Failed(_) => system.await,
                result => result,
            },
        }
    }

    /// One query to a zone's own name server, stricter than [`Self::query`]. An
    /// absence counts only with the zone's SOA as proof: without it the answer is a
    /// referral to a delegated zone. A CNAME without the records it leads to was not
    /// followed, so it is no answer either.
    pub async fn query_authoritative(&self, name: &str, record_type: RecordType) -> DnsResult {
        let name = match fqdn(name) {
            Ok(name) => name,
            Err(e) => return DnsResult::Failed(e),
        };
        match self.inner.lookup(name, record_type).await {
            Ok(lookup) => {
                let records = presentation(lookup.answers(), record_type);
                if records.is_empty() {
                    DnsResult::Failed("the answer points to another name".into())
                } else {
                    DnsResult::Records(records)
                }
            }
            Err(NetError::Dns(HickoryDnsError::NoRecordsFound(NoRecords {
                soa: Some(_),
                response_code,
                ..
            }))) => match response_code {
                ResponseCode::NXDomain => DnsResult::NxDomain,
                _ => DnsResult::Empty,
            },
            Err(e) if e.is_no_records_found() => DnsResult::Failed("referred to another name server".into()),
            Err(e) => DnsResult::Failed(e.to_string()),
        }
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

/// Whether an address belongs to the public internet: not loopback, private,
/// shared (CGNAT), link-local, unique-local, multicast, documentation or reserved.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || first & 0xfe00 == 0xfc00
                    || first & 0xffc0 == 0xfe80
                    || first == 0x2001 && v6.segments()[1] == 0x0db8)
            }
        },
    }
}

/// Fully qualified, so the resolver's search list never applies. ASCII names are
/// taken as they are: the IDNA rules for host names reject the underscores that
/// SPF services put inside labels (`_spf.exemplo_com._d.provider.com`).
fn fqdn(name: &str) -> Result<Name, String> {
    let fqdn = format!("{}.", name.trim_end_matches('.'));
    let parsed = if fqdn.is_ascii() {
        Name::from_ascii(&fqdn)
    } else {
        Name::from_utf8(&fqdn)
    };
    parsed.map_err(|e| format!("invalid name {fqdn}: {e}"))
}

/// The records of the asked type in presentation format, without the trailing dot;
/// the strings of a TXT record are joined.
fn presentation(answers: &[Record], record_type: RecordType) -> Vec<String> {
    answers
        .iter()
        .filter(|r| r.record_type() == record_type)
        .map(|r| match &r.data {
            RData::TXT(txt) => txt.txt_data.iter().map(|part| String::from_utf8_lossy(part)).collect(),
            other => other.to_string().trim_end_matches('.').to_owned(),
        })
        .collect()
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
