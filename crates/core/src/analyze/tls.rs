//! TLS module: certificate, chain, trust and negotiated protocol of the final origin.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use url::{Host, Url};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{X509Certificate, X509Name, parse_x509_certificate};
use x509_parser::public_key::PublicKey;

use super::network::opener;
use super::rfc3339;
use crate::data::{CaKind, CaState, ca_by_key_id};
use crate::findings::finding;
use crate::report::{Finding, Module, Status};
use crate::snapshot::{CertProblem, ConnectionUse, FailureKind, Snapshot, TlsInfo, Verification};

const DAY: i64 = 86_400;
/// Beyond this difference from the server's `Date`, our day counts may be off.
const CLOCK_SKEW_LIMIT: i64 = 300;

#[derive(Debug, Clone, Serialize)]
pub struct Tls {
    pub host: String,
    pub version: String,
    pub cipher_suite: String,
    pub key_exchange: Option<String>,
    pub alpn: Option<String>,
    /// The chain validates against the embedded Mozilla roots.
    pub trusted: bool,
    pub verification_error: Option<String>,
    pub certificate: Option<Certificate>,
    /// Certificates the server sent after the leaf.
    pub chain: Vec<ChainEntry>,
    pub ocsp_stapled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub issuer_organization: Option<String>,
    pub not_before: String,
    pub not_after: String,
    /// Negative once expired. Counted from the collection time.
    pub days_remaining: i64,
    pub lifetime_days: i64,
    pub names: Vec<String>,
    pub covers_host: bool,
    pub key: String,
    pub signature_algorithm: String,
    pub sct_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainEntry {
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
}

pub fn analyze(snapshot: &Snapshot) -> Module<Tls> {
    let mut findings = hop_findings(snapshot);
    let handshake_failure = snapshot
        .https_fallback
        .as_ref()
        .or(snapshot.failure.as_ref())
        .filter(|f| f.kind == FailureKind::TlsIncompatible);
    if let Some(failure) = handshake_failure {
        let host = Url::parse(&failure.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned));
        findings.push(finding(
            "tls.handshake.incompatible",
            &[("host", host.unwrap_or_default())],
            failure.message.clone(),
        ));
        return module(Status::Failed, Some(failure.message.clone()), None, findings);
    }

    let Some(final_hop) = snapshot.chain.last() else {
        return module(Status::Skipped, Some("no response to analyze".into()), None, findings);
    };
    let Some((tls, host)) = opener(&snapshot.chain, final_hop)
        .and_then(|c| c.tls.as_ref())
        .and_then(|tls| Some((tls, Url::parse(&final_hop.url).ok()?.host()?.to_owned())))
    else {
        let reason = match &snapshot.https_fallback {
            Some(f) => format!("the site does not answer HTTPS: {}", f.message),
            None => "the final page is served over plain HTTP".to_owned(),
        };
        return module(Status::Skipped, Some(reason), None, findings);
    };

    let now = unix(snapshot.collected_at);
    let (data, mut cert_findings) = examine(tls, &host, now);
    findings.append(&mut cert_findings);

    if let Some(skew) = clock_skew(snapshot) {
        findings.push(finding(
            "tls.clock_skew",
            &[("minutes", (skew.abs() / 60).to_string())],
            format!("server Date header differs from the local clock by {skew} s"),
        ));
    }
    let status = if data.certificate.is_some() {
        Status::Ok
    } else {
        Status::Partial
    };
    let reason = (status == Status::Partial).then(|| "the certificate could not be parsed".to_owned());
    module(status, reason, Some(data), findings)
}

fn module(status: Status, reason: Option<String>, data: Option<Tls>, findings: Vec<Finding>) -> Module<Tls> {
    Module {
        status,
        reason,
        data,
        findings,
    }
}

/// Everything we can say about one TLS connection. `now` is Unix seconds.
pub fn examine(tls: &TlsInfo, host: &Host<String>, now: i64) -> (Tls, Vec<Finding>) {
    let mut findings = Vec::new();
    // Position matters: the first certificate the server sends is the leaf. If it
    // cannot be read, the next one is an intermediate, not a stand-in.
    let decoded: Vec<Option<X509Certificate>> = tls
        .certificates
        .iter()
        .map(|der| parse_x509_certificate(der).ok().map(|(_, c)| c))
        .collect();
    let leaf = decoded.first().and_then(Option::as_ref);
    let parsed: Vec<&X509Certificate> = decoded.iter().flatten().collect();
    let host_text = host.to_string();

    let certificate = leaf.map(|leaf| {
        let not_before = leaf.validity().not_before.timestamp();
        let not_after = leaf.validity().not_after.timestamp();
        let names = san_names(leaf);
        let covers_host = covers(&names, host);
        let key = key_description(leaf);

        if now > not_after {
            findings.push(finding(
                "tls.cert.expired",
                &[
                    ("date", date(not_after)),
                    ("days", ((now - not_after) / DAY).to_string()),
                ],
                format!("notAfter {}", time(not_after)),
            ));
        } else if now < not_before {
            findings.push(finding(
                "tls.cert.not_yet_valid",
                &[("date", date(not_before))],
                format!("notBefore {}", time(not_before)),
            ));
        } else {
            let remaining = not_after - now;
            let threshold = (14 * DAY).min((not_after - not_before) / 4);
            if remaining < threshold {
                findings.push(finding(
                    "tls.cert.expiring",
                    &[("days", (remaining / DAY).to_string()), ("date", date(not_after))],
                    format!("notAfter {}", time(not_after)),
                ));
            }
        }
        if !covers_host {
            let shown: Vec<&str> = names.iter().take(5).map(String::as_str).collect();
            findings.push(finding(
                "tls.cert.name_mismatch",
                &[("host", host_text.clone()), ("names", shown.join(", "))],
                format!("subjectAltName: {}", names.join(", ")),
            ));
        }
        if let Some((algorithm, bits)) = weak_key(leaf) {
            findings.push(finding(
                "tls.cert.weak_key",
                &[("key", format!("{algorithm} {bits}"))],
                format!("public key {algorithm} {bits} bits"),
            ));
        }

        Certificate {
            subject: common_name(leaf.subject()).unwrap_or_else(|| leaf.subject().to_string()),
            issuer: common_name(leaf.issuer()).unwrap_or_else(|| leaf.issuer().to_string()),
            issuer_organization: organization(leaf.issuer()),
            not_before: time(not_before),
            not_after: time(not_after),
            days_remaining: (not_after - now).div_euclid(DAY),
            lifetime_days: (not_after - not_before) / DAY,
            names,
            covers_host,
            key,
            signature_algorithm: signature_name(leaf),
            sct_count: sct_count(leaf),
        }
    });

    // SHA-1 anywhere below the root breaks the chain in every current browser.
    if let Some(weak) = parsed.iter().find(|c| signature_name(c).starts_with("SHA-1")) {
        findings.push(finding(
            "tls.cert.sha1",
            &[("subject", subject_of(weak))],
            format!("{} is signed with {}", subject_of(weak), signature_name(weak)),
        ));
    }

    if let Verification::Invalid { problem, message } = &tls.verification
        && leaf.is_some()
        && let Some(f) = trust_finding(*problem, message, &parsed)
    {
        findings.push(f);
    }

    if tls.version == "TLS 1.2" {
        findings.push(finding(
            "tls.version.no_tls13",
            &[],
            "negotiated TLS 1.2 while offering TLS 1.3".into(),
        ));
    }

    let data = Tls {
        host: host_text,
        version: tls.version.clone(),
        cipher_suite: tls.cipher_suite.clone(),
        key_exchange: tls.key_exchange.clone(),
        alpn: tls.alpn.clone(),
        trusted: tls.verification == Verification::Valid,
        verification_error: match &tls.verification {
            Verification::Valid => None,
            Verification::Invalid { message, .. } => Some(message.clone()),
        },
        certificate,
        chain: decoded
            .iter()
            .skip(1)
            .flatten()
            .map(|c| ChainEntry {
                subject: subject_of(c),
                issuer: common_name(c.issuer()).unwrap_or_else(|| c.issuer().to_string()),
                not_after: time(c.validity().not_after.timestamp()),
            })
            .collect(),
        ocsp_stapled: tls.ocsp_stapled,
    };
    (data, findings)
}

/// Why the chain did not validate, told apart precisely: a missing intermediate
/// (works in browsers that fetch it), a self-signed certificate, or an issuer
/// that browsers do not trust. Dates and names are reported separately.
fn trust_finding(problem: CertProblem, message: &str, chain: &[&X509Certificate]) -> Option<Finding> {
    match problem {
        CertProblem::Expired | CertProblem::NotYetValid | CertProblem::NameMismatch => return None,
        CertProblem::UnknownIssuer => {}
        _ => {
            return Some(finding(
                "tls.cert.untrusted",
                &[("reason", message.to_owned())],
                message.to_owned(),
            ));
        }
    }
    let leaf = chain.first()?;
    // Equal names are not enough: the certificate must verify with its own key.
    if leaf.subject().as_raw() == leaf.issuer().as_raw() && leaf.verify_signature(None).is_ok() {
        return Some(finding(
            "tls.cert.self_signed",
            &[],
            format!("issuer equals subject: {}", leaf.subject()),
        ));
    }

    // Climb what the server sent; the first issuer it did not send is the gap.
    let mut top = leaf;
    let mut used = vec![false; chain.len()];
    used[0] = true;
    while let Some((i, parent)) = chain
        .iter()
        .enumerate()
        .find(|(i, c)| !used[*i] && c.subject().as_raw() == top.issuer().as_raw())
    {
        used[i] = true;
        top = parent;
    }
    let missing = authority_key_id(top);
    let issuer = common_name(top.issuer()).unwrap_or_else(|| top.issuer().to_string());
    let evidence = format!(
        "{message}; the chain sent by the server ends at {} (issuer {issuer}, authority key id {})",
        subject_of(top),
        missing.as_deref().map(to_hex).unwrap_or_else(|| "absent".into())
    );

    let reason = match missing.as_deref().and_then(ca_by_key_id) {
        Some(ca) if ca.kind == CaKind::Intermediate && ca.state == CaState::Trusted => {
            return Some(finding(
                "tls.chain.incomplete",
                &[("missing", ca.name.to_owned()), ("owner", ca.owner.to_owned())],
                evidence,
            ));
        }
        Some(ca) => match ca.state {
            CaState::Revoked => format!("it is issued under {} ({}), which has been revoked", ca.name, ca.owner),
            CaState::Removed => format!(
                "it chains to {} ({}), a root removed from browser trust stores",
                ca.name, ca.owner
            ),
            CaState::Untrusted => format!(
                "it is issued by {} ({}), which browsers do not trust",
                ca.name, ca.owner
            ),
            CaState::Trusted => format!(
                "it chains to {} ({}), which is missing from our root store",
                ca.name, ca.owner
            ),
        },
        None => format!(
            "its issuer, {issuer}, is not a publicly trusted certificate authority (a private CA, or a proxy inspecting TLS on this network)"
        ),
    };
    Some(finding("tls.cert.untrusted", &[("reason", reason)], evidence))
}

/// Seconds between the server's `Date` header and our clock at that moment,
/// when beyond the limit.
fn clock_skew(snapshot: &Snapshot) -> Option<i64> {
    let hop = snapshot.chain.last()?;
    let server = parse_http_date(hop.header("date")?)?;
    let local = unix(snapshot.collected_at + hop.request_at + hop.ttfb);
    let skew = local - server;
    (skew.abs() > CLOCK_SKEW_LIMIT).then_some(skew)
}

fn hop_findings(snapshot: &Snapshot) -> Vec<Finding> {
    let final_host = snapshot
        .chain
        .last()
        .and_then(|h| Url::parse(&h.url).ok())
        .and_then(|u| u.host_str().map(str::to_owned));
    let mut findings = Vec::new();
    for hop in &snapshot.chain {
        let ConnectionUse::New(info) = &hop.connection else {
            continue;
        };
        let Some(TlsInfo {
            verification: Verification::Invalid { message, .. },
            ..
        }) = &info.tls
        else {
            continue;
        };
        let host = Url::parse(&hop.url).ok().and_then(|u| u.host_str().map(str::to_owned));
        if host.is_some() && host != final_host {
            findings.push(finding(
                "tls.hop.invalid",
                &[("host", host.unwrap_or_default()), ("problem", message.clone())],
                format!("{}: {message}", hop.url),
            ));
        }
    }
    findings
}

fn san_names(cert: &X509Certificate) -> Vec<String> {
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_ascii_lowercase()),
            GeneralName::IPAddress(bytes) => ip_text(bytes),
            _ => None,
        })
        .collect()
}

fn ip_text(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?).to_string()),
        16 => Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).to_string()),
        _ => None,
    }
}

/// RFC 6125 matching as browsers do it: the wildcard must be the whole leftmost
/// label and matches exactly one label. IP hosts only match IP names.
pub fn covers(names: &[String], host: &Host<String>) -> bool {
    match host {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            names.iter().any(|name| {
                let name = name.trim_end_matches('.');
                match name.strip_prefix("*.") {
                    Some(suffix) => domain
                        .split_once('.')
                        .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix && suffix.contains('.')),
                    None => name == domain,
                }
            })
        }
        Host::Ipv4(ip) => names.iter().any(|n| n == &ip.to_string()),
        Host::Ipv6(ip) => names.iter().any(|n| n == &ip.to_string()),
    }
}

fn key_description(cert: &X509Certificate) -> String {
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA {}", rsa.key_size()),
        Ok(PublicKey::EC(ec)) => format!("ECDSA P-{}", ec.key_size()),
        _ if cert.public_key().algorithm.algorithm.to_id_string() == "1.3.101.112" => "Ed25519".into(),
        _ => "unknown".into(),
    }
}

fn weak_key(cert: &X509Certificate) -> Option<(&'static str, usize)> {
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) if rsa.key_size() < 2048 => Some(("RSA", rsa.key_size())),
        Ok(PublicKey::EC(ec)) if ec.key_size() < 256 => Some(("ECDSA", ec.key_size())),
        _ => None,
    }
}

fn signature_name(cert: &X509Certificate) -> String {
    let oid = cert.signature_algorithm.algorithm.to_id_string();
    match oid.as_str() {
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA",
        "1.2.840.10045.4.1" => "SHA-1 with ECDSA",
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "1.3.101.112" => "Ed25519",
        _ => return oid,
    }
    .to_owned()
}

fn sct_count(cert: &X509Certificate) -> usize {
    cert.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SCT(list) => Some(list.len()),
            _ => None,
        })
        .unwrap_or(0)
}

fn authority_key_id(cert: &X509Certificate) -> Option<Vec<u8>> {
    cert.extensions().iter().find_map(|ext| match ext.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => aki.key_identifier.as_ref().map(|k| k.0.to_vec()),
        _ => None,
    })
}

fn common_name(name: &X509Name) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned)
}

fn organization(name: &X509Name) -> Option<String> {
    name.iter_organization()
        .next()
        .and_then(|o| o.as_str().ok())
        .map(str::to_owned)
}

fn subject_of(cert: &X509Certificate) -> String {
    common_name(cert.subject()).unwrap_or_else(|| cert.subject().to_string())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn time(secs: i64) -> String {
    rfc3339(UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64))
}

fn date(secs: i64) -> String {
    time(secs)[..10].to_owned()
}

/// IMF-fixdate, the only format servers are allowed to send: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn parse_http_date(text: &str) -> Option<i64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [_, day, month, year, clock, "GMT"] = parts.as_slice() else {
        return None;
    };
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| m == month)? as i64
        + 1;
    let (day, year): (i64, i64) = (day.parse().ok()?, year.parse().ok()?);
    let mut hms = clock.split(':').map(|p| p.parse::<i64>().ok());
    let (h, m, s) = (hms.next()??, hms.next()??, hms.next()??);
    // Days from civil, Howard Hinnant.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * DAY + h * 3600 + m * 60 + s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::TlsInfo;
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyIdMethod, KeyPair, date_time_ymd};

    const NOW: i64 = 1_793_212_345; // 2026-10-28

    fn host(name: &str) -> Host<String> {
        Host::parse(name).unwrap()
    }

    fn tls_info(certs: Vec<Vec<u8>>, verification: Verification) -> TlsInfo {
        TlsInfo {
            handshake: Duration::from_millis(5),
            sni: Some("example.com".into()),
            version: "TLS 1.3".into(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
            key_exchange: Some("X25519".into()),
            alpn: Some("h2".into()),
            verification,
            certificates: certs,
            ocsp_stapled: false,
        }
    }

    /// A leaf for `names`, valid between the two dates, issued by a CA whose key
    /// identifier is `ca_key_id`.
    fn leaf(names: &[&str], from: (i32, u8, u8), to: (i32, u8, u8), ca_key_id: Vec<u8>) -> Vec<u8> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_identifier_method = KeyIdMethod::PreSpecified(ca_key_id);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let mut params = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
        params.not_before = date_time_ymd(from.0, from.1, from.2);
        params.not_after = date_time_ymd(to.0, to.1, to.2);
        params.use_authority_key_identifier_extension = true;
        params.distinguished_name.push(rcgen::DnType::CommonName, names[0]);
        params
            .signed_by(&KeyPair::generate().unwrap(), &ca)
            .unwrap()
            .der()
            .to_vec()
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id).collect()
    }

    fn unknown_issuer() -> Verification {
        Verification::Invalid {
            problem: CertProblem::UnknownIssuer,
            message: "invalid peer certificate: UnknownIssuer".into(),
        }
    }

    #[test]
    fn healthy_certificate_has_no_findings() {
        let der = leaf(&["example.com"], (2026, 9, 1), (2026, 12, 1), vec![1; 20]);
        let (data, findings) = examine(&tls_info(vec![der], Verification::Valid), &host("example.com"), NOW);
        assert!(findings.is_empty(), "{:?}", ids(&findings));
        let cert = data.certificate.unwrap();
        assert_eq!((cert.days_remaining, cert.lifetime_days), (33, 91));
        assert!(cert.covers_host);
        assert_eq!(cert.not_after, "2026-12-01T00:00:00.000Z");
    }

    #[test]
    fn expiry_threshold_is_relative_to_lifetime() {
        // 90-day certificate with 10 days left: below min(14, 22) days.
        let short = leaf(&["example.com"], (2026, 8, 8), (2026, 11, 7), vec![1; 20]);
        let (_, f) = examine(&tls_info(vec![short], Verification::Valid), &host("example.com"), NOW);
        assert_eq!(ids(&f), ["tls.cert.expiring"]);
        // 6-day certificate with 2 days left: 1/4 of the lifetime is 1.5 days, so fine.
        let tiny = leaf(&["example.com"], (2026, 10, 25), (2026, 10, 31), vec![1; 20]);
        let (_, f) = examine(&tls_info(vec![tiny], Verification::Valid), &host("example.com"), NOW);
        assert!(f.is_empty(), "{:?}", ids(&f));
    }

    #[test]
    fn expired_and_wrong_name_are_both_reported() {
        let der = leaf(&["other.example"], (2025, 1, 1), (2026, 1, 1), vec![1; 20]);
        let verification = Verification::Invalid {
            problem: CertProblem::Expired,
            message: "invalid peer certificate: Expired".into(),
        };
        let (_, f) = examine(&tls_info(vec![der], verification), &host("example.com"), NOW);
        assert_eq!(ids(&f), ["tls.cert.expired", "tls.cert.name_mismatch"]);
    }

    #[test]
    fn missing_lets_encrypt_intermediate_is_an_incomplete_chain() {
        let r12 = crate::data::hex("00b529f22d8e6f31e89b4cad783efadce90cd1d2").unwrap();
        let der = leaf(&["example.com"], (2026, 9, 1), (2026, 12, 1), r12);
        let (data, f) = examine(&tls_info(vec![der], unknown_issuer()), &host("example.com"), NOW);
        assert_eq!(ids(&f), ["tls.chain.incomplete"]);
        assert_eq!(f[0].params["missing"], "R12");
        assert!(!data.trusted);
    }

    #[test]
    fn unknown_issuer_is_untrusted_not_incomplete() {
        let der = leaf(&["example.com"], (2026, 9, 1), (2026, 12, 1), vec![7; 20]);
        let (_, f) = examine(&tls_info(vec![der], unknown_issuer()), &host("example.com"), NOW);
        assert_eq!(ids(&f), ["tls.cert.untrusted"]);
        assert!(f[0].params["reason"].contains("not a publicly trusted"));
    }

    #[test]
    fn self_signed_needs_a_valid_self_signature() {
        let own = rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
        let (_, f) = examine(
            &tls_info(vec![own.cert.der().to_vec()], unknown_issuer()),
            &host("example.com"),
            NOW,
        );
        assert_eq!(ids(&f), ["tls.cert.self_signed"]);

        // Same names as its issuer, but signed by another key: not self-signed.
        let mut ca_params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let lookalike = CertificateParams::new(vec!["example.com".to_owned()])
            .unwrap()
            .signed_by(&KeyPair::generate().unwrap(), &ca)
            .unwrap();
        let (_, f) = examine(
            &tls_info(vec![lookalike.der().to_vec()], unknown_issuer()),
            &host("example.com"),
            NOW,
        );
        assert_eq!(ids(&f), ["tls.cert.untrusted"]);
    }

    #[test]
    fn wildcards_match_one_label_only() {
        let names = vec!["*.example.com".to_owned(), "example.org".to_owned()];
        assert!(covers(&names, &host("www.example.com")));
        assert!(!covers(&names, &host("a.b.example.com")));
        assert!(!covers(&names, &host("example.com")));
        assert!(covers(&names, &host("EXAMPLE.org")));
        assert!(!covers(&["*.com".to_owned()], &host("example.com")));
        assert!(covers(&["192.0.2.1".to_owned()], &host("192.0.2.1")));
    }

    #[test]
    fn tls12_is_noted() {
        let der = leaf(&["example.com"], (2026, 9, 1), (2026, 12, 1), vec![1; 20]);
        let mut info = tls_info(vec![der], Verification::Valid);
        info.version = "TLS 1.2".into();
        assert_eq!(
            ids(&examine(&info, &host("example.com"), NOW).1),
            ["tls.version.no_tls13"]
        );
    }

    #[test]
    fn unparsable_leaf_is_not_replaced_by_the_next_certificate() {
        // The intermediate expired and is for another name: neither must be
        // reported against the site when the real leaf cannot be read.
        let other = leaf(&["other.example"], (2025, 1, 1), (2026, 1, 1), vec![1; 20]);
        let (data, f) = examine(
            &tls_info(vec![vec![0x30, 0x03, 0x01, 0x02, 0x03], other], Verification::Valid),
            &host("example.com"),
            NOW,
        );
        assert!(data.certificate.is_none());
        assert!(f.is_empty(), "{:?}", ids(&f));
        // The certificate after the leaf is still the chain, not the leaf.
        assert_eq!(data.chain.len(), 1);
    }

    #[test]
    fn parses_imf_fixdate() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_http_date("Wed, 28 Oct 2026 18:32:25 GMT"), Some(NOW));
        assert_eq!(parse_http_date("garbage"), None);
    }
}
