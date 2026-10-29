//! DNS records of a domain and its mail configuration, all queried in parallel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_resolver::proto::rr::RecordType;
use tokio::sync::OnceCell;
use tokio::task::JoinSet;

use super::deadline::{Deadline, Expired};
use super::dns::Resolver;
use crate::analyze::spf;
use crate::snapshot::{DnsAnswer, DnsResult, DomainRecords, DomainRole};

/// Common DKIM selectors. Without the real selector DKIM cannot be checked, so a
/// miss here means "not determined", never "absent".
pub const DKIM_SELECTORS: &[&str] = &["google", "selector1", "selector2", "k1", "default"];
/// Budget for following SPF includes, on top of the per-query timeout.
const SPF_BUDGET: Duration = Duration::from_secs(2);
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Name servers of a zone asked when the system resolver fails, out of at most
/// `MAX_NS_LOOKUPS` whose addresses are looked up.
const AUTHORITATIVE_SERVERS: usize = 3;
const MAX_NS_LOOKUPS: usize = 5;
/// How long the system resolver has before the zone's name servers are asked too.
/// A working resolver answers well within it, even without the answer cached.
const HEDGE_DELAY: Duration = Duration::from_millis(500);

/// The registrable domain per the public suffix list, or the host itself when it
/// has none (a single label, or a public suffix).
pub fn registrable(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&host).map(str::to_owned).unwrap_or(host)
}

/// The queries for one domain, in report order.
pub fn plan(host: &str, registrable: &str) -> Vec<(String, RecordType)> {
    let mut queries = vec![
        (host.to_owned(), RecordType::A),
        (host.to_owned(), RecordType::AAAA),
        (host.to_owned(), RecordType::CNAME),
    ];
    // CAA is looked up from the host towards the registrable domain, as a
    // certificate authority does.
    let mut name = host.to_owned();
    loop {
        queries.push((name.clone(), RecordType::CAA));
        if name == registrable {
            break;
        }
        match name.split_once('.') {
            Some((_, parent)) if parent.len() >= registrable.len() => name = parent.to_owned(),
            _ => break,
        }
    }
    for record_type in [
        RecordType::NS,
        RecordType::MX,
        RecordType::TXT,
        RecordType::SOA,
        RecordType::DS,
    ] {
        queries.push((registrable.to_owned(), record_type));
    }
    queries.push((format!("_dmarc.{host}"), RecordType::TXT));
    if host != registrable {
        queries.push((format!("_dmarc.{registrable}"), RecordType::TXT));
    }
    for selector in DKIM_SELECTORS {
        queries.push((format!("{selector}._domainkey.{registrable}"), RecordType::TXT));
    }
    for prefix in ["_mta-sts", "_smtp._tls", "default._bimi"] {
        queries.push((format!("{prefix}.{registrable}"), RecordType::TXT));
    }
    queries
}

pub async fn collect(resolver: &Resolver, host: &str, role: DomainRole, deadline: &Deadline) -> DomainRecords {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let registrable = registrable(&host);
    let zones = Zones::default();
    let mut answers = run(
        resolver,
        &zones,
        plan(&host, &registrable),
        deadline,
        deadline.instant(),
    )
    .await;

    // Follow SPF includes and redirects until the tree is known or the lookup
    // limit is passed, in rounds of parallel queries.
    let spf_deadline = deadline.instant().min(tokio::time::Instant::now() + SPF_BUDGET);
    loop {
        let known: HashMap<String, Vec<String>> = answers
            .iter()
            .filter(|a| a.record_type == "TXT")
            .filter_map(|a| match &a.result {
                DnsResult::Records(r) => Some((a.name.clone(), r.clone())),
                DnsResult::Empty | DnsResult::NxDomain => Some((a.name.clone(), Vec::new())),
                DnsResult::Failed(_) => None,
            })
            .collect();
        let failed: Vec<&str> = answers
            .iter()
            .filter(|a| a.record_type == "TXT" && matches!(a.result, DnsResult::Failed(_)))
            .map(|a| a.name.as_str())
            .collect();
        let lookup = |d: &str| known.get(d).map(Vec::as_slice);
        let pending: Vec<(String, RecordType)> = spf::pending_targets(&registrable, &lookup)
            .into_iter()
            .filter(|t| !failed.contains(&t.as_str()))
            .map(|t| (t, RecordType::TXT))
            .collect();
        if pending.is_empty() || deadline.passed() || tokio::time::Instant::now() >= spf_deadline {
            break;
        }
        answers.extend(run(resolver, &zones, pending, deadline, spf_deadline).await);
    }

    DomainRecords {
        role,
        host,
        registrable,
        answers,
    }
}

/// Runs the queries in parallel, each until `cap`, its own timeout or the deadline.
async fn run(
    resolver: &Resolver,
    zones: &Zones,
    queries: Vec<(String, RecordType)>,
    deadline: &Deadline,
    cap: tokio::time::Instant,
) -> Vec<DnsAnswer> {
    let mut set = JoinSet::new();
    for (i, (name, record_type)) in queries.iter().cloned().enumerate() {
        let resolver = resolver.clone();
        let zones = zones.clone();
        let deadline = deadline.clone();
        set.spawn(async move { (i, ask(&resolver, &zones, &name, record_type, &deadline, cap).await) });
    }
    let mut results: Vec<Option<(DnsResult, Option<String>)>> = vec![None; queries.len()];
    while let Some(joined) = set.join_next().await {
        if let Ok((i, result)) = joined {
            results[i] = Some(result);
        }
    }
    queries
        .into_iter()
        .zip(results)
        .map(|((name, record_type), result)| {
            let (result, authoritative) =
                result.unwrap_or_else(|| (DnsResult::Failed("query task failed".into()), None));
            DnsAnswer {
                name,
                record_type: record_type.to_string(),
                result,
                authoritative,
            }
        })
        .collect()
}

/// One query to the system resolver. When it fails, or is still silent after
/// `HEDGE_DELAY`, the zone's own name servers are asked too, and the first answer
/// wins: home routers often truncate large answers and refuse TCP, or reject DS
/// queries. Returns the result and, if they answered, which name server.
async fn ask(
    resolver: &Resolver,
    zones: &Zones,
    name: &str,
    record_type: RecordType,
    deadline: &Deadline,
    cap: tokio::time::Instant,
) -> (DnsResult, Option<String>) {
    // Both paths share the query's timeout, so a resolver that answers nothing
    // still ends the DNS phase on time.
    let until = cap.min(tokio::time::Instant::now() + QUERY_TIMEOUT);
    let system = async {
        match deadline.run_until(until, resolver.query(name, record_type)).await {
            Ok(result) => result,
            Err(Expired::Limit) => DnsResult::Failed(format!("no answer within {} s", QUERY_TIMEOUT.as_secs())),
            Err(Expired::Global) => DnsResult::Failed("no answer before the deadline".into()),
        }
    };
    let direct = async {
        let found = async {
            let servers = zones.servers(resolver, name, record_type, deadline, until).await;
            ask_servers(&servers, name, record_type).await
        };
        deadline.run_until(until, found).await.ok().flatten()
    };
    tokio::pin!(system, direct);
    let either = |failure: DnsResult, direct: Option<(DnsResult, String)>| match direct {
        Some((result, server)) => (result, Some(server)),
        None => (failure, None),
    };
    match tokio::time::timeout(HEDGE_DELAY, &mut system).await {
        Ok(DnsResult::Failed(e)) => either(DnsResult::Failed(e), direct.await),
        Ok(result) => (result, None),
        Err(_) => tokio::select! {
            result = &mut system => match result {
                DnsResult::Failed(e) => either(DnsResult::Failed(e), direct.await),
                result => (result, None),
            },
            found = &mut direct => match found {
                Some((result, server)) => (result, Some(server)),
                None => (system.await, None),
            },
        },
    }
}

/// Tries the servers one after another; the first that answers wins.
async fn ask_servers(
    servers: &[(String, Resolver)],
    name: &str,
    record_type: RecordType,
) -> Option<(DnsResult, String)> {
    for (host, server) in servers {
        let result = server.query_authoritative(name, record_type).await;
        if !matches!(result, DnsResult::Failed(_)) {
            return Some((result, host.clone()));
        }
    }
    None
}

/// The zone that holds each name and the name servers of each zone, found once
/// per collection and shared by the queries that need them. A search that found
/// nothing is not kept, so a later query can try again.
#[derive(Clone, Default)]
struct Zones(Arc<Mutex<ZoneCache>>);

#[derive(Default)]
struct ZoneCache {
    /// Name to its zone and the zone's NS.
    zone_of: HashMap<String, (String, Vec<String>)>,
    servers: HashMap<String, Arc<OnceCell<Servers>>>,
}

/// Name server host and a resolver that asks only it.
type Servers = Vec<(String, Resolver)>;

impl Zones {
    /// The servers of the zone that holds `name`'s record of `record_type`.
    async fn servers(
        &self,
        resolver: &Resolver,
        name: &str,
        record_type: RecordType,
        deadline: &Deadline,
        until: tokio::time::Instant,
    ) -> Servers {
        let name = name.trim_end_matches('.');
        // DS lives above the cut, in the parent zone.
        let start = match record_type {
            RecordType::DS => match name.split_once('.') {
                Some((_, parent)) => parent,
                None => return Vec::new(),
            },
            _ => name,
        };
        let known = self.lock().zone_of.get(start).cloned();
        let (zone, ns) = match known {
            Some(found) => found,
            None => match zone_of(resolver, start, deadline, until).await {
                Some(found) => {
                    self.lock().zone_of.insert(start.to_owned(), found.clone());
                    found
                }
                None => return Vec::new(),
            },
        };
        let cell = self.lock().servers.entry(zone).or_default().clone();
        cell.get_or_try_init(|| async {
            let servers = zone_servers(resolver, ns, deadline, until).await;
            if servers.is_empty() { Err(()) } else { Ok(servers) }
        })
        .await
        .cloned()
        .unwrap_or_default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ZoneCache> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The zone that holds `start`, with its NS: the closest name with NS records,
/// from `start` up to its registrable domain. A delegated subzone such as
/// `campaign.provider.com` has servers of its own; the registrable domain's would
/// only refer to them.
async fn zone_of(
    resolver: &Resolver,
    start: &str,
    deadline: &Deadline,
    until: tokio::time::Instant,
) -> Option<(String, Vec<String>)> {
    let stop = registrable(start);
    let mut candidates = vec![start.to_owned()];
    while let Some(last) = candidates.last()
        && last.len() > stop.len()
        && let Some((_, parent)) = last.split_once('.')
    {
        candidates.push(parent.to_owned());
    }

    let mut set = JoinSet::new();
    for (order, zone) in candidates.into_iter().enumerate() {
        let resolver = resolver.clone();
        let deadline = deadline.clone();
        set.spawn(async move {
            match deadline
                .run_until(until, resolver.query_for_servers(&zone, RecordType::NS))
                .await
            {
                Ok(DnsResult::Records(ns)) => Some((order, zone, ns)),
                _ => None,
            }
        });
    }
    let mut found = Vec::new();
    while let Some(joined) = set.join_next().await {
        found.extend(joined.ok().flatten());
    }
    found
        .into_iter()
        .min_by_key(|(order, _, _)| *order)
        .map(|(_, zone, ns)| (zone, ns))
}

/// Up to three of the zone's name servers with an address, in name order so the
/// one asked first does not depend on the order of the NS answer.
async fn zone_servers(
    resolver: &Resolver,
    mut ns: Vec<String>,
    deadline: &Deadline,
    until: tokio::time::Instant,
) -> Servers {
    ns.sort();
    ns.dedup();
    ns.truncate(MAX_NS_LOOKUPS);

    let mut lookups = JoinSet::new();
    for (order, host) in ns.into_iter().enumerate() {
        let resolver = resolver.clone();
        let deadline = deadline.clone();
        lookups.spawn(async move {
            let ip = match deadline
                .run_until(until, resolver.query_for_servers(&host, RecordType::A))
                .await
            {
                Ok(DnsResult::Records(ips)) => ips.iter().find_map(|ip| ip.parse::<IpAddr>().ok()),
                _ => None,
            };
            (order, host, ip.and_then(|ip| resolver.authoritative(ip).ok()))
        });
    }
    let mut servers = Vec::new();
    while let Some(joined) = lookups.join_next().await {
        if let Ok((order, host, Some(server))) = joined {
            servers.push((order, host, server));
        }
    }
    servers.sort_by_key(|(order, _, _)| *order);
    servers
        .into_iter()
        .take(AUTHORITATIVE_SERVERS)
        .map(|(_, host, server)| (host, server))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_follows_the_public_suffix_list() {
        assert_eq!(registrable("www.exemplo.com.br"), "exemplo.com.br");
        assert_eq!(registrable("a.b.example.co.uk."), "example.co.uk");
        assert_eq!(registrable("localhost"), "localhost");
    }

    #[test]
    fn caa_climbs_from_host_to_registrable() {
        let caa: Vec<String> = plan("a.www.exemplo.com.br", "exemplo.com.br")
            .into_iter()
            .filter(|(_, t)| *t == RecordType::CAA)
            .map(|(n, _)| n)
            .collect();
        assert_eq!(caa, ["a.www.exemplo.com.br", "www.exemplo.com.br", "exemplo.com.br"]);
    }

    #[test]
    fn dmarc_is_asked_at_host_and_registrable() {
        let names: Vec<String> = plan("www.exemplo.com.br", "exemplo.com.br")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(names.contains(&"_dmarc.www.exemplo.com.br".to_owned()));
        assert!(names.contains(&"_dmarc.exemplo.com.br".to_owned()));
        assert!(names.contains(&"google._domainkey.exemplo.com.br".to_owned()));
    }
}
