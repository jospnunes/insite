//! DNS records of a domain and its mail configuration, all queried in parallel.

use std::collections::HashMap;
use std::time::Duration;

use hickory_resolver::proto::rr::RecordType;
use tokio::task::JoinSet;

use super::deadline::Deadline;
use super::dns::Resolver;
use crate::analyze::spf;
use crate::snapshot::{DnsAnswer, DnsResult, DomainRecords, DomainRole};

/// Common DKIM selectors. Without the real selector DKIM cannot be checked, so a
/// miss here means "not determined", never "absent".
pub const DKIM_SELECTORS: &[&str] = &["google", "selector1", "selector2", "k1", "default"];
/// Budget for following SPF includes, on top of the per-query timeout.
const SPF_BUDGET: Duration = Duration::from_secs(2);
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

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
    let mut answers = run(resolver, plan(&host, &registrable), deadline, deadline.instant()).await;

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
        answers.extend(run(resolver, pending, deadline, spf_deadline).await);
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
    queries: Vec<(String, RecordType)>,
    deadline: &Deadline,
    cap: tokio::time::Instant,
) -> Vec<DnsAnswer> {
    let mut set = JoinSet::new();
    for (i, (name, record_type)) in queries.iter().cloned().enumerate() {
        let resolver = resolver.clone();
        let deadline = deadline.clone();
        let until = cap.min(tokio::time::Instant::now() + QUERY_TIMEOUT);
        set.spawn(async move {
            let result = match deadline.run_until(until, resolver.query(&name, record_type)).await {
                Ok(result) => result,
                Err(_) => DnsResult::Failed("no answer before the deadline".into()),
            };
            (i, result)
        });
    }
    let mut results: Vec<Option<DnsResult>> = vec![None; queries.len()];
    while let Some(joined) = set.join_next().await {
        if let Ok((i, result)) = joined {
            results[i] = Some(result);
        }
    }
    queries
        .into_iter()
        .zip(results)
        .map(|((name, record_type), result)| DnsAnswer {
            name,
            record_type: record_type.to_string(),
            result: result.unwrap_or_else(|| DnsResult::Failed("query task failed".into())),
        })
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
