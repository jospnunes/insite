//! DNS records, SPF chain, ASN and the DNS module against a local name server.

mod server;

use std::time::Duration;

use hickory_resolver::proto::rr::RecordType;
use insite_core::analyze::analyze;
use insite_core::collect::deadline::Deadline;
use insite_core::collect::dns::Resolver;
use insite_core::collect::{asn, records};
use insite_core::report::Status;
use insite_core::snapshot::{DnsResult, DomainRole};
use server::dns::{Zone, serve};

fn deadline() -> Deadline {
    Deadline::new(tokio::time::Instant::now() + Duration::from_secs(5), None)
}

fn healthy_zone() -> Zone {
    Zone::default()
        .a("www.exemplo.test", "192.0.2.10")
        .ns("exemplo.test", "abby.ns.cloudflare.com.")
        .ns("exemplo.test", "rob.ns.cloudflare.com.")
        .mx("exemplo.test", 1, "aspmx.l.google.com.")
        .txt("exemplo.test", "v=spf1 include:_spf.provider.test -all")
        .txt("exemplo.test", "google-site-verification=abc")
        .txt(
            "_spf.provider.test",
            "v=spf1 include:_n1.provider.test include:_n2.provider.test ~all",
        )
        .txt("_n1.provider.test", "v=spf1 ip4:192.0.2.0/24 ~all")
        .txt("_n2.provider.test", "v=spf1 ip6:2001:db8::/32 ~all")
        .txt(
            "_dmarc.exemplo.test",
            "v=DMARC1; p=quarantine; rua=mailto:d@exemplo.test",
        )
        .txt("google._domainkey.exemplo.test", "v=DKIM1; k=rsa; p=MIIBIjANBgkq")
        .txt("_mta-sts.exemplo.test", "v=STSv1; id=2026")
        .caa_issue("exemplo.test", "letsencrypt.org")
}

#[tokio::test(flavor = "multi_thread")]
async fn collects_records_and_follows_spf_includes() {
    let resolver = Resolver::with_nameserver(serve(healthy_zone()).await).unwrap();
    let records = records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await;

    assert_eq!(records.registrable, "exemplo.test");
    assert_eq!(records.records("www.exemplo.test", "A"), ["192.0.2.10"]);
    // Nested includes were fetched in rounds.
    for name in ["_spf.provider.test", "_n1.provider.test", "_n2.provider.test"] {
        assert!(
            matches!(records.result(name, "TXT"), Some(DnsResult::Records(_))),
            "{name}"
        );
    }
    // A name with no records of the type is NODATA, an unknown name NXDOMAIN.
    assert_eq!(records.result("www.exemplo.test", "AAAA"), Some(&DnsResult::Empty));
    assert_eq!(
        records.result("selector1._domainkey.exemplo.test", "TXT"),
        Some(&DnsResult::NxDomain)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_module_reads_a_healthy_domain_without_findings() {
    let resolver = Resolver::with_nameserver(serve(healthy_zone()).await).unwrap();
    let mut snap = snapshot();
    snap.dns = vec![records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await];
    let module = analyze(&snap).modules.dns;

    assert!(
        module.findings.is_empty(),
        "{:?}",
        module.findings.iter().map(|f| f.id).collect::<Vec<_>>()
    );
    assert_eq!(module.status, Status::Ok);
    let d = &module.data.unwrap().domains[0];
    assert_eq!(d.dns_provider.as_deref(), Some("Cloudflare"));
    assert_eq!(d.mail_provider.as_deref(), Some("Google Workspace"));
    let spf = d.spf.as_ref().unwrap();
    assert_eq!(
        (spf.all.as_deref(), spf.lookups, spf.lookups_incomplete),
        (Some("-all"), 3, false)
    );
    assert_eq!(d.dmarc.as_ref().unwrap().policy.as_deref(), Some("quarantine"));
    assert_eq!(d.dkim_selectors_found, ["google"]);
    assert!(d.mta_sts && !d.tls_rpt);
    assert_eq!(d.caa, ["0 issue \"letsencrypt.org\""]);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_failures_are_unknown_not_missing() {
    let zone = Zone::default()
        .a("www.exemplo.test", "192.0.2.10")
        .ns("exemplo.test", "ns1.exemplo.test.")
        .mx("exemplo.test", 10, "mx.exemplo.test.")
        .failing("_dmarc.exemplo.test")
        .failing("_dmarc.www.exemplo.test");
    let zone = zone.txt("exemplo.test", "v=spf1 mx -all");
    let resolver = Resolver::with_nameserver(serve(zone).await).unwrap();
    let mut snap = snapshot();
    snap.dns = vec![records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await];
    let module = analyze(&snap).modules.dns;

    let ids: Vec<&str> = module.findings.iter().map(|f| f.id).collect();
    assert!(!ids.contains(&"mail.dmarc.missing"), "{ids:?}");
    assert_eq!(module.status, Status::Partial);
}

/// Home routers often truncate large answers and refuse TCP, or reject DS
/// queries. What the system resolver could not answer is asked of the zone's own
/// name servers.
#[tokio::test(flavor = "multi_thread")]
async fn failed_queries_are_asked_of_the_authoritative_servers() {
    let authoritative = serve(
        Zone::default()
            .txt("exemplo.test", "v=spf1 -all")
            .txt("_dmarc.exemplo.test", "v=DMARC1; p=reject"),
    )
    .await;
    let system = Zone::default()
        .a("www.exemplo.test", "192.0.2.10")
        .ns("exemplo.test", "ns1.exemplo.test.")
        .a("ns1.exemplo.test", "127.0.0.1")
        .ns("test", "ns.nic.test.")
        .a("ns.nic.test", "127.0.0.1")
        .failing_type("exemplo.test", RecordType::TXT)
        .failing_type("exemplo.test", RecordType::DS)
        .failing("_dmarc.exemplo.test");
    let resolver = Resolver::with_nameserver(serve(system).await)
        .unwrap()
        .with_authoritative_port(authoritative.port());
    let records = records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await;

    let answer = |name: &str, rtype: &str| {
        records
            .answers
            .iter()
            .find(|a| a.name == name && a.record_type == rtype)
            .unwrap()
    };
    let txt = answer("exemplo.test", "TXT");
    assert_eq!(txt.result, DnsResult::Records(vec!["v=spf1 -all".into()]));
    assert_eq!(txt.authoritative.as_deref(), Some("ns1.exemplo.test"));
    assert_eq!(
        answer("_dmarc.exemplo.test", "TXT").authoritative.as_deref(),
        Some("ns1.exemplo.test")
    );
    // DS lives in the parent zone, so its name servers are the ones asked.
    let ds = answer("exemplo.test", "DS");
    assert_eq!(ds.result, DnsResult::Empty);
    assert_eq!(ds.authoritative.as_deref(), Some("ns.nic.test"));
    // What the system resolver answered is left alone.
    assert_eq!(answer("www.exemplo.test", "A").authoritative, None);

    let mut snap = snapshot();
    snap.dns = vec![records];
    let d = &analyze(&snap).modules.dns.data.unwrap().domains[0];
    assert!(d.failed_queries.is_empty(), "{:?}", d.failed_queries);
    assert_eq!(
        d.authoritative_queries,
        [
            "exemplo.test TXT @ns1.exemplo.test",
            "exemplo.test DS @ns.nic.test",
            "_dmarc.exemplo.test TXT @ns1.exemplo.test"
        ]
    );
}

/// SPF services build names like `_spf.exemplo_test._d.provider.test`: an
/// underscore inside a label is valid in DNS, even if not in a host name.
#[tokio::test(flavor = "multi_thread")]
async fn underscores_inside_labels_are_queried() {
    let zone = Zone::default()
        .a("www.exemplo.test", "192.0.2.10")
        .txt("exemplo.test", "v=spf1 include:_spf.exemplo_test._d.provider.test -all")
        .txt("_spf.exemplo_test._d.provider.test", "v=spf1 ip4:192.0.2.0/24 -all");
    let resolver = Resolver::with_nameserver(serve(zone).await).unwrap();
    let records = records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await;

    assert_eq!(
        records.records("_spf.exemplo_test._d.provider.test", "TXT"),
        ["v=spf1 ip4:192.0.2.0/24 -all"]
    );
}

/// A name in a delegated subzone is asked of the subzone's servers, not of the
/// registrable domain's, which would only refer to them.
#[tokio::test(flavor = "multi_thread")]
async fn delegated_subzones_are_asked_of_their_own_servers() {
    let authoritative =
        serve(Zone::default().txt("__spf.campaign.provider.test", "v=spf1 ip4:192.0.2.0/24 -all")).await;
    let system = Zone::default()
        .a("www.exemplo.test", "192.0.2.10")
        .txt("exemplo.test", "v=spf1 include:__spf.campaign.provider.test -all")
        .ns("provider.test", "ns1.provider.test.")
        .a("ns1.provider.test", "127.0.0.1")
        .ns("campaign.provider.test", "ns.campaign.provider.test.")
        .a("ns.campaign.provider.test", "127.0.0.1")
        .failing_type("__spf.campaign.provider.test", RecordType::TXT);
    let resolver = Resolver::with_nameserver(serve(system).await)
        .unwrap()
        .with_authoritative_port(authoritative.port());
    let records = records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await;

    let include = records
        .answers
        .iter()
        .find(|a| a.name == "__spf.campaign.provider.test")
        .unwrap();
    assert!(matches!(include.result, DnsResult::Records(_)), "{:?}", include.result);
    assert_eq!(include.authoritative.as_deref(), Some("ns.campaign.provider.test"));
}

/// A resolver that answers nothing leaves every query unmeasured within the query
/// timeout: looking for the zone's servers through it must not hold the DNS phase
/// until the global deadline.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_resolver_ends_on_the_query_timeout() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = Resolver::with_nameserver(silent.local_addr().unwrap()).unwrap();
    let started = std::time::Instant::now();
    let records = records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await;

    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert!(
        records.answers.iter().all(|a| matches!(a.result, DnsResult::Failed(_))),
        "{:?}",
        records.answers
    );
}

/// A negative answer without the zone's SOA is a referral, not proof of absence.
#[tokio::test(flavor = "multi_thread")]
async fn a_referral_is_not_an_absence() {
    let authoritative = serve(Zone::default().txt("exemplo.test", "v=spf1 -all").no_soa()).await;
    let system = Zone::default()
        .a("www.exemplo.test", "192.0.2.10")
        .ns("exemplo.test", "ns1.exemplo.test.")
        .a("ns1.exemplo.test", "127.0.0.1")
        .failing("_dmarc.exemplo.test");
    let resolver = Resolver::with_nameserver(serve(system).await)
        .unwrap()
        .with_authoritative_port(authoritative.port());
    let records = records::collect(&resolver, "www.exemplo.test", DomainRole::Input, &deadline()).await;

    let dmarc = records
        .answers
        .iter()
        .find(|a| a.name == "_dmarc.exemplo.test")
        .unwrap();
    assert!(matches!(dmarc.result, DnsResult::Failed(_)), "{:?}", dmarc.result);
    assert_eq!(dmarc.authoritative, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn asn_from_team_cymru_records() {
    let zone = Zone::default()
        .txt(
            "10.2.0.192.origin.asn.cymru.com",
            "64500 | 192.0.2.0/24 | BR | lacnic | 2010-01-01",
        )
        .txt(
            "AS64500.asn.cymru.com",
            "64500 | BR | lacnic | 2010-01-01 | EXEMPLO-NET, BR",
        );
    let resolver = Resolver::with_nameserver(serve(zone).await).unwrap();
    let found = asn::lookup(&resolver, "192.0.2.10".parse().unwrap()).await;

    assert_eq!(found.asn, Some(64500));
    assert_eq!(found.prefix.as_deref(), Some("192.0.2.0/24"));
    assert_eq!(found.country.as_deref(), Some("BR"));
    assert_eq!(found.name.as_deref(), Some("EXEMPLO-NET, BR"));
    assert!(found.error.is_none());
}

fn snapshot() -> insite_core::snapshot::Snapshot {
    use insite_core::snapshot::*;
    use std::time::SystemTime;
    Snapshot {
        snapshot_version: SNAPSHOT_VERSION,
        collector_version: "test".into(),
        collected_at: SystemTime::UNIX_EPOCH,
        duration: Duration::ZERO,
        input: "https://www.exemplo.test/".into(),
        request: RequestProfile {
            user_agent: String::new(),
            accept_language: String::new(),
            accept_encoding: String::new(),
        },
        chain: Vec::new(),
        page: None,
        http_check: None,
        https_fallback: None,
        failure: None,
        deadline_hit: false,
        interrupted: false,
        browser: None,
        dns: Vec::new(),
        asn: None,
        auxiliary: Default::default(),
    }
}
