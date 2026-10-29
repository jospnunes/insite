//! DNS and e-mail module: providers, SPF, DMARC, DKIM, MTA-STS, CAA and DNSSEC for
//! each registrable domain the chain touched.

use serde::Serialize;

use super::spf;
use crate::collect::records::DKIM_SELECTORS;
use crate::data::{name_matches, providers};
use crate::findings::finding;
use crate::report::{Finding, Module, Status};
use crate::snapshot::{DnsResult, DomainRecords, DomainRole, Snapshot};

#[derive(Debug, Clone, Serialize)]
pub struct Dns {
    pub domains: Vec<DomainReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainReport {
    pub domain: String,
    pub role: &'static str,
    pub host: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname: Vec<String>,
    pub ns: Vec<String>,
    pub dns_provider: Option<String>,
    pub mx: Vec<String>,
    /// The only MX is `0 .` (RFC 7505): the domain accepts no mail.
    pub null_mx: bool,
    pub mail_provider: Option<String>,
    pub caa: Vec<String>,
    /// A DS record exists at the parent, so the zone is signed.
    pub dnssec: bool,
    pub spf: Option<SpfReport>,
    pub dmarc: Option<DmarcReport>,
    /// Selectors among the common ones that have a key; empty means not determined.
    pub dkim_selectors_found: Vec<String>,
    pub mta_sts: bool,
    pub tls_rpt: bool,
    pub bimi: bool,
    /// Queries that failed, so absence was not established for them.
    pub failed_queries: Vec<String>,
    /// Queries the system resolver failed and the zone's own name servers
    /// answered, as `name type @server`.
    pub authoritative_queries: Vec<String>,
    /// False when the resolver looks like it filters queries: then a missing
    /// record says nothing, and only the records that came back count.
    pub absences_reliable: bool,
}

impl DomainReport {
    /// Whether "no `record_type` at `name`" was established: the query was made,
    /// answered, and the resolver is trusted for absences.
    pub fn absence_known(&self, name: &str, record_type: &str) -> bool {
        self.absences_reliable
            && !self
                .failed_queries
                .iter()
                .any(|q| *q == format!("{name} {record_type}"))
    }

    /// Whether "no CAA" was established: none of the queries climbing from the host
    /// to the registrable domain failed.
    pub fn caa_absence_known(&self) -> bool {
        self.absences_reliable && !self.failed_queries.iter().any(|q| q.ends_with(" CAA"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SpfReport {
    pub record: String,
    /// The `all` mechanism with its qualifier (`-all`, `~all`), if any.
    pub all: Option<String>,
    pub lookups: usize,
    /// True when some include could not be fetched, so `lookups` is a lower bound.
    pub lookups_incomplete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DmarcReport {
    pub record: String,
    pub found_at: String,
    pub policy: Option<String>,
    pub subdomain_policy: Option<String>,
    pub pct: Option<u8>,
    pub rua: Vec<String>,
}

pub fn analyze(snapshot: &Snapshot) -> Module<Dns> {
    if snapshot.dns.is_empty() {
        return Module {
            status: Status::Skipped,
            reason: Some("the input is an IP address".into()),
            data: None,
            findings: Vec::new(),
        };
    }
    let mut findings = Vec::new();
    let mut reasons = Vec::new();
    let mut domains = Vec::new();
    for records in &snapshot.dns {
        if resolver_hides_records(records) {
            // Report what came back, but conclude nothing from absences.
            reasons.push(format!(
                "the DNS resolver returned no NS records for {}, which every delegated domain has; it is probably \
                 filtering queries, so records it did not return are not reported as missing",
                records.registrable
            ));
            let mut report = domain(records, &mut Vec::new());
            report.absences_reliable = false;
            domains.push(report);
        } else {
            domains.push(domain(records, &mut findings));
        }
    }
    if domains.iter().any(|d| !d.failed_queries.is_empty()) {
        reasons.push("some DNS queries failed, so their records are unknown".into());
    }
    Module {
        status: if reasons.is_empty() {
            Status::Ok
        } else {
            Status::Partial
        },
        reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
        data: Some(Dns { domains }),
        findings,
    }
}

/// A delegated domain always has NS records. A resolver that answers "no NS" for a
/// domain whose host resolves is filtering or broken, and its other empty answers
/// cannot be trusted either.
fn resolver_hides_records(records: &DomainRecords) -> bool {
    let host_resolves =
        !records.records(&records.host, "A").is_empty() || !records.records(&records.host, "AAAA").is_empty();
    host_resolves
        && matches!(
            records.result(&records.registrable, "NS"),
            Some(DnsResult::Empty | DnsResult::NxDomain)
        )
}

fn domain(records: &DomainRecords, findings: &mut Vec<Finding>) -> DomainReport {
    let reg = records.registrable.as_str();
    let host = records.host.as_str();
    let list = |name: &str, rtype: &str| records.records(name, rtype).to_vec();

    let ns = list(reg, "NS");
    // The collector trims the root's dot, so a null MX arrives as `0 `.
    let mx: Vec<String> = list(reg, "MX")
        .into_iter()
        .map(|m| {
            if mx_host(&m).is_empty() {
                format!("{} .", m.trim())
            } else {
                m
            }
        })
        .collect();
    let caa = caa(records);
    let failed_queries: Vec<String> = records
        .answers
        .iter()
        .filter(|a| matches!(a.result, DnsResult::Failed(_)))
        .map(|a| format!("{} {}", a.name, a.record_type))
        .collect();
    let authoritative_queries: Vec<String> = records
        .answers
        .iter()
        .filter_map(|a| {
            let server = a.authoritative.as_ref()?;
            Some(format!("{} {} @{server}", a.name, a.record_type))
        })
        .collect();

    let spf = spf_report(records, findings);
    let dmarc = dmarc_report(records, findings);
    let txt_has = |name: &str, prefix: &str| {
        records
            .records(name, "TXT")
            .iter()
            .any(|t| t.to_ascii_lowercase().starts_with(prefix))
    };
    let dkim_selectors_found: Vec<String> = DKIM_SELECTORS
        .iter()
        .filter(|s| {
            txt_has(&format!("{s}._domainkey.{reg}"), "v=dkim1") || has_key(records, &format!("{s}._domainkey.{reg}"))
        })
        .map(|s| (*s).to_owned())
        .collect();

    // A domain that receives no mail should still say it sends none, or anyone can
    // send mail in its name.
    let mx_known = !matches!(records.result(reg, "MX"), Some(DnsResult::Failed(_)) | None);
    // A null MX (`0 .`, RFC 7505) declares that the domain accepts no mail.
    let receives_mail = mx.iter().any(|m| !mx_host(m).trim_end_matches('.').is_empty());
    let null_mx = !mx.is_empty() && !receives_mail;
    if mx_known && !receives_mail && spf.is_none() && dmarc.is_none() && txt_known(records, reg) {
        findings.push(finding(
            "mail.spoofable",
            &[("domain", reg.to_owned())],
            format!("{reg}: no MX, SPF or DMARC"),
        ));
    } else if receives_mail {
        if spf.is_none() && txt_known(records, reg) {
            findings.push(finding(
                "mail.spf.missing",
                &[("domain", reg.to_owned())],
                format!("no v=spf1 TXT record at {reg}"),
            ));
        }
        if dmarc.is_none() && txt_known(records, &format!("_dmarc.{reg}")) {
            findings.push(finding(
                "mail.dmarc.missing",
                &[("domain", reg.to_owned())],
                format!("no TXT record at _dmarc.{reg}"),
            ));
        }
    }

    DomainReport {
        domain: reg.to_owned(),
        role: match records.role {
            DomainRole::Input => "input",
            DomainRole::Final => "final",
        },
        host: host.to_owned(),
        a: list(host, "A"),
        aaaa: list(host, "AAAA"),
        cname: list(host, "CNAME"),
        dns_provider: provider(
            &ns,
            providers()
                .dns
                .iter()
                .map(|d| (d.name.as_str(), d.patterns.ns.as_slice())),
        ),
        mail_provider: provider(
            &mx.iter()
                .map(|m| mx_host(m).to_owned())
                .filter(|h| h != ".")
                .collect::<Vec<_>>(),
            providers()
                .mail
                .iter()
                .map(|m| (m.name.as_str(), m.patterns.mx.as_slice())),
        ),
        ns,
        mx,
        null_mx,
        caa,
        dnssec: !records.records(reg, "DS").is_empty(),
        spf,
        dmarc,
        dkim_selectors_found,
        mta_sts: txt_has(&format!("_mta-sts.{reg}"), "v=stsv1"),
        tls_rpt: txt_has(&format!("_smtp._tls.{reg}"), "v=tlsrptv1"),
        bimi: txt_has(&format!("default._bimi.{reg}"), "v=bimi1"),
        failed_queries,
        authoritative_queries,
        absences_reliable: true,
    }
}

fn txt_known(records: &DomainRecords, name: &str) -> bool {
    matches!(
        records.result(name, "TXT"),
        Some(DnsResult::Records(_) | DnsResult::Empty | DnsResult::NxDomain)
    )
}

/// DKIM records without the optional `v=DKIM1` tag still carry `p=`.
fn has_key(records: &DomainRecords, name: &str) -> bool {
    records.records(name, "TXT").iter().any(|t| {
        t.split(';')
            .any(|tag| tag.trim().starts_with("p=") && tag.trim().len() > 2)
    })
}

/// The first CAA set found climbing from the host, as a CA would apply it.
fn caa(records: &DomainRecords) -> Vec<String> {
    records
        .answers
        .iter()
        .filter(|a| a.record_type == "CAA")
        .find_map(|a| match &a.result {
            DnsResult::Records(r) => Some(r.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn mx_host(mx: &str) -> &str {
    mx.split_whitespace().nth(1).unwrap_or_default()
}

/// The provider whose patterns match every name in `names` (mixed NS sets, such
/// as a migration in progress, get no provider rather than a wrong one).
fn provider<'a>(names: &[String], mut entries: impl Iterator<Item = (&'a str, &'a [String])>) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    entries
        .find(|(_, patterns)| names.iter().all(|n| patterns.iter().any(|p| name_matches(n, p))))
        .map(|(name, _)| name.to_owned())
}

fn spf_report(records: &DomainRecords, findings: &mut Vec<Finding>) -> Option<SpfReport> {
    let reg = records.registrable.as_str();
    let txt = records.records(reg, "TXT");
    let spf_records = spf::records(txt);
    let record = *spf_records.first()?;
    if spf_records.len() > 1 {
        findings.push(finding(
            "mail.spf.multiple",
            &[("domain", reg.to_owned()), ("count", spf_records.len().to_string())],
            spf_records.join(" | "),
        ));
    }

    let lookup = |name: &str| match records.result(name, "TXT") {
        Some(DnsResult::Records(r)) => Some(r.as_slice()),
        Some(DnsResult::Empty | DnsResult::NxDomain) => Some(&[][..]),
        _ => None,
    };
    let walk = spf::walk(reg, &lookup);
    let terms = spf::parse(record);
    let all = terms.iter().find_map(|t| match t {
        spf::Term::All(q) => Some(if *q == '+' {
            "+all".to_owned()
        } else {
            format!("{q}all")
        }),
        _ => None,
    });
    let has_redirect = terms.iter().any(|t| matches!(t, spf::Term::Redirect(_)));

    if walk.lookups > spf::LOOKUP_LIMIT {
        findings.push(finding(
            "mail.spf.too_many_lookups",
            &[("domain", reg.to_owned()), ("count", walk.lookups.to_string())],
            format!("{} DNS lookups counted through includes from {reg}", walk.lookups),
        ));
    }
    for target in &walk.broken {
        findings.push(finding(
            "mail.spf.broken_include",
            &[("domain", reg.to_owned()), ("target", target.clone())],
            format!("{target} has no SPF record"),
        ));
    }
    match all.as_deref() {
        Some("+all") => findings.push(finding(
            "mail.spf.pass_all",
            &[("domain", reg.to_owned())],
            record.to_owned(),
        )),
        None if !has_redirect => findings.push(finding(
            "mail.spf.no_all",
            &[("domain", reg.to_owned())],
            record.to_owned(),
        )),
        _ => {}
    }
    if walk.uses_ptr {
        findings.push(finding(
            "mail.spf.ptr",
            &[("domain", reg.to_owned())],
            record.to_owned(),
        ));
    }

    Some(SpfReport {
        record: record.to_owned(),
        all,
        lookups: walk.lookups,
        lookups_incomplete: !walk.unknown.is_empty() || walk.has_macros,
    })
}

fn dmarc_report(records: &DomainRecords, findings: &mut Vec<Finding>) -> Option<DmarcReport> {
    let reg = records.registrable.as_str();
    let candidates = [format!("_dmarc.{}", records.host), format!("_dmarc.{reg}")];
    let (found_at, dmarc_records) = candidates.iter().find_map(|name| {
        let r: Vec<&String> = records
            .records(name, "TXT")
            .iter()
            .filter(|t| t.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
            .collect();
        (!r.is_empty()).then(|| (name.clone(), r))
    })?;
    let record = dmarc_records[0].clone();
    let tags = dmarc_tags(&record);
    let tag = |k: &str| tags.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    let policy = tag("p").map(|p| p.to_ascii_lowercase());

    if dmarc_records.len() > 1 || !matches!(policy.as_deref(), Some("none" | "quarantine" | "reject")) {
        let reason = if dmarc_records.len() > 1 {
            "more than one DMARC record, so receivers ignore all of them".to_owned()
        } else {
            "the record has no valid p= policy".to_owned()
        };
        findings.push(finding(
            "mail.dmarc.invalid",
            &[("domain", reg.to_owned()), ("reason", reason)],
            record.clone(),
        ));
    } else if policy.as_deref() == Some("none") {
        findings.push(finding(
            "mail.dmarc.none",
            &[("domain", reg.to_owned())],
            record.clone(),
        ));
    }

    Some(DmarcReport {
        found_at,
        policy,
        subdomain_policy: tag("sp").map(|p| p.to_ascii_lowercase()),
        pct: tag("pct").and_then(|p| p.parse().ok()),
        rua: tag("rua")
            .map(|r| {
                r.split(',')
                    .map(|u| u.trim().to_owned())
                    .filter(|u| !u.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        record,
    })
}

pub fn dmarc_tags(record: &str) -> Vec<(String, String)> {
    record
        .split(';')
        .filter_map(|part| part.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::DnsAnswer;

    fn answer(name: &str, rtype: &str, records: &[&str]) -> DnsAnswer {
        DnsAnswer {
            name: name.into(),
            record_type: rtype.into(),
            result: if records.is_empty() {
                DnsResult::Empty
            } else {
                DnsResult::Records(records.iter().map(|r| r.to_string()).collect())
            },
            authoritative: None,
        }
    }

    fn domain_records(answers: Vec<DnsAnswer>) -> DomainRecords {
        DomainRecords {
            role: DomainRole::Input,
            host: "www.exemplo.com.br".into(),
            registrable: "exemplo.com.br".into(),
            answers,
        }
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.id).collect()
    }

    #[test]
    fn google_workspace_with_good_spf_and_dmarc() {
        let rec = domain_records(vec![
            answer(
                "exemplo.com.br",
                "NS",
                &["abby.ns.cloudflare.com", "rob.ns.cloudflare.com"],
            ),
            answer(
                "exemplo.com.br",
                "MX",
                &["1 aspmx.l.google.com", "5 alt1.aspmx.l.google.com"],
            ),
            answer(
                "exemplo.com.br",
                "TXT",
                &["v=spf1 include:_spf.google.com ~all", "google-site-verification=x"],
            ),
            answer("_spf.google.com", "TXT", &["v=spf1 include:_netblocks.google.com ~all"]),
            answer("_netblocks.google.com", "TXT", &["v=spf1 ip4:35.190.247.0/24 ~all"]),
            answer("_dmarc.www.exemplo.com.br", "TXT", &[]),
            answer(
                "_dmarc.exemplo.com.br",
                "TXT",
                &["v=DMARC1; p=reject; rua=mailto:d@exemplo.com.br"],
            ),
            answer(
                "google._domainkey.exemplo.com.br",
                "TXT",
                &["v=DKIM1; k=rsa; p=MIIBIjANBg"],
            ),
        ]);
        let mut findings = Vec::new();
        let d = domain(&rec, &mut findings);
        assert!(findings.is_empty(), "{:?}", ids(&findings));
        assert_eq!(d.dns_provider.as_deref(), Some("Cloudflare"));
        assert_eq!(d.mail_provider.as_deref(), Some("Google Workspace"));
        let spf = d.spf.unwrap();
        assert_eq!(
            (spf.all.as_deref(), spf.lookups, spf.lookups_incomplete),
            (Some("~all"), 2, false)
        );
        let dmarc = d.dmarc.unwrap();
        assert_eq!(
            (dmarc.policy.as_deref(), dmarc.found_at.as_str()),
            (Some("reject"), "_dmarc.exemplo.com.br")
        );
        assert_eq!(d.dkim_selectors_found, ["google"]);
    }

    #[test]
    fn mail_without_spf_or_dmarc() {
        let rec = domain_records(vec![
            answer("exemplo.com.br", "MX", &["10 mx.locaweb.com.br"]),
            answer("exemplo.com.br", "TXT", &["something=else"]),
            answer("_dmarc.www.exemplo.com.br", "TXT", &[]),
            answer("_dmarc.exemplo.com.br", "TXT", &[]),
        ]);
        let mut findings = Vec::new();
        let d = domain(&rec, &mut findings);
        assert_eq!(ids(&findings), ["mail.spf.missing", "mail.dmarc.missing"]);
        assert_eq!(d.mail_provider.as_deref(), Some("Locaweb"));
    }

    #[test]
    fn null_mx_declares_no_mail() {
        // The collector trims the root's dot, so `0 .` arrives as `0 `.
        let rec = domain_records(vec![
            answer("exemplo.com.br", "MX", &["0 "]),
            answer("exemplo.com.br", "TXT", &["v=spf1 -all"]),
            answer("_dmarc.www.exemplo.com.br", "TXT", &[]),
            answer("_dmarc.exemplo.com.br", "TXT", &["v=DMARC1; p=reject;"]),
        ]);
        let mut findings = Vec::new();
        let d = domain(&rec, &mut findings);
        assert!(findings.is_empty(), "{:?}", ids(&findings));
        assert!(d.null_mx);
        assert_eq!(d.mx, ["0 ."]);
        assert_eq!(d.mail_provider, None);
    }

    #[test]
    fn failed_caa_is_not_measured() {
        let mut rec = domain_records(vec![answer("exemplo.com.br", "CAA", &[])]);
        rec.answers.push(DnsAnswer {
            name: "www.exemplo.com.br".into(),
            record_type: "CAA".into(),
            result: DnsResult::Failed("timeout".into()),
            authoritative: None,
        });
        let d = domain(&rec, &mut Vec::new());
        assert!(d.caa.is_empty());
        assert!(!d.caa_absence_known());
    }

    #[test]
    fn failed_queries_never_become_missing_records() {
        let mut rec = domain_records(vec![answer("exemplo.com.br", "MX", &["10 mx.example.net"])]);
        rec.answers.push(DnsAnswer {
            name: "exemplo.com.br".into(),
            record_type: "TXT".into(),
            result: DnsResult::Failed("timeout".into()),
            authoritative: None,
        });
        let mut findings = Vec::new();
        let d = domain(&rec, &mut findings);
        assert!(!ids(&findings).contains(&"mail.spf.missing"));
        assert_eq!(d.failed_queries, ["exemplo.com.br TXT"]);
    }

    #[test]
    fn spf_problems() {
        let rec = domain_records(vec![
            answer("exemplo.com.br", "MX", &["10 mx.example.net"]),
            answer(
                "exemplo.com.br",
                "TXT",
                &["v=spf1 include:gone.example ptr +all", "v=spf1 -all"],
            ),
            answer("gone.example", "TXT", &[]),
            answer("_dmarc.exemplo.com.br", "TXT", &["v=DMARC1; p=none"]),
        ]);
        let mut findings = Vec::new();
        domain(&rec, &mut findings);
        assert_eq!(
            ids(&findings),
            [
                "mail.spf.multiple",
                "mail.spf.broken_include",
                "mail.spf.pass_all",
                "mail.spf.ptr",
                "mail.dmarc.none"
            ]
        );
    }

    #[test]
    fn domain_without_mail_should_say_so() {
        let rec = domain_records(vec![
            answer("exemplo.com.br", "MX", &[]),
            answer("exemplo.com.br", "TXT", &[]),
            answer("_dmarc.exemplo.com.br", "TXT", &[]),
        ]);
        let mut findings = Vec::new();
        domain(&rec, &mut findings);
        assert_eq!(ids(&findings), ["mail.spoofable"]);
    }

    #[test]
    fn a_resolver_without_ns_answers_is_not_trusted_for_absences() {
        let rec = domain_records(vec![
            answer("www.exemplo.com.br", "A", &["192.0.2.1"]),
            answer("exemplo.com.br", "NS", &[]),
            answer("exemplo.com.br", "MX", &[]),
            answer("exemplo.com.br", "TXT", &[]),
            answer("_dmarc.exemplo.com.br", "TXT", &[]),
        ]);
        let mut snap = crate::analyze::infra::tests::snapshot_with(200, &[], "");
        snap.dns = vec![rec];
        let module = analyze(&snap);
        assert!(module.findings.is_empty(), "{:?}", ids(&module.findings));
        assert_eq!(module.status, Status::Partial);
        assert!(module.reason.unwrap().contains("filtering"));
    }

    #[test]
    fn mixed_name_servers_get_no_provider() {
        let rec = domain_records(vec![answer(
            "exemplo.com.br",
            "NS",
            &["abby.ns.cloudflare.com", "a.auto.dns.br"],
        )]);
        assert_eq!(domain(&rec, &mut Vec::new()).dns_provider, None);
    }
}
