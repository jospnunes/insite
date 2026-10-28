use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::analyze::content::content;
use crate::analyze::infra::tests::snapshot_with;
use crate::snapshot::{ConnectionInfo, ConnectionUse, FetchFailure, TlsInfo};

const PAGE: &str = "<!doctype html><html lang=en><head><title>t</title></head><body><h1>t</h1></body></html>";

fn tls(verification: Verification) -> ConnectionUse {
    ConnectionUse::New(Box::new(ConnectionInfo {
        resolution: None,
        peer: "192.0.2.1:443".parse().unwrap(),
        connect_at: Duration::ZERO,
        tcp: Duration::ZERO,
        tls: Some(TlsInfo {
            handshake: Duration::ZERO,
            sni: Some("example.com".into()),
            version: "TLSv1.3".into(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
            key_exchange: None,
            alpn: Some("h2".into()),
            verification,
            certificates: Vec::new(),
            ocsp_stapled: false,
        }),
        proxy: None,
    }))
}

/// An HTTPS page with a valid certificate, the given headers and body.
fn site(headers: &[(&str, &str)], body: &str) -> Snapshot {
    let mut all = headers.to_vec();
    if !headers.iter().any(|(n, _)| *n == "content-type") {
        all.push(("content-type", "text/html; charset=utf-8"));
    }
    let mut s = snapshot_with(200, &all, body);
    s.chain[0].connection = tls(Verification::Valid);
    s
}

fn run(s: &Snapshot) -> Module<Security> {
    analyze(s, &content(s))
}

fn result(s: &Snapshot, name: &str) -> &'static str {
    let module = run(s);
    module
        .data
        .unwrap()
        .tests
        .iter()
        .find(|t| t.test == name)
        .unwrap()
        .result
}

fn header(name: &'static str, value: &'static str) -> Snapshot {
    site(&[(name, value)], PAGE)
}

fn ids(m: &Module<Security>) -> Vec<&'static str> {
    m.findings.iter().map(|f| f.id).collect()
}

#[test]
fn grades_follow_the_observatory_chart() {
    let cases = [
        (135, "A+"),
        (100, "A+"),
        (99, "A"),
        (90, "A"),
        (89, "A-"),
        (85, "A-"),
        (84, "B+"),
        (80, "B+"),
        (79, "B"),
        (70, "B"),
        (69, "B-"),
        (65, "B-"),
        (64, "C+"),
        (60, "C+"),
        (59, "C"),
        (50, "C"),
        (49, "C-"),
        (45, "C-"),
        (44, "D+"),
        (40, "D+"),
        (39, "D"),
        (30, "D"),
        (29, "D-"),
        (25, "D-"),
        (24, "F"),
        (0, "F"),
    ];
    for (score, expected) in cases {
        assert_eq!(grade(score), expected, "score {score}");
    }
}

#[test]
fn bonuses_count_only_from_ninety() {
    assert_eq!(score([-5, 10, 5]), 110);
    assert_eq!(score([-10, 10]), 100);
    assert_eq!(score([-15, 10]), 85);
    assert_eq!(score([-50, -50, -40, 10]), 0);
    assert_eq!(score([]), 100);
}

#[test]
fn score_table_matches_the_methodology() {
    // A sample across tests, checked against the published table.
    let table = [
        ("csp-implemented-with-no-unsafe-default-src-none", 10),
        ("csp-not-implemented", -25),
        ("cookies-session-without-secure-flag", -40),
        ("cookies-without-secure-flag-but-protected-by-hsts", -5),
        ("redirection-not-to-https-on-initial-redirection", -10),
        ("referrer-policy-private", 5),
        ("hsts-implemented-max-age-less-than-six-months", -10),
        ("sri-not-implemented-and-external-scripts-not-loaded-securely", -50),
        ("x-frame-options-implemented-via-csp", 5),
        ("corp-implemented-with-same-site", 10),
        ("coop-implemented-with-noopener-allow-popups", 10),
        ("coep-header-invalid", -5),
        ("redirection-not-checked", 0),
    ];
    for (result, expected) in table {
        assert_eq!(modifier(result), expected, "{result}");
    }
    // Every result with a finding costs points, and every finding is in the catalog.
    for (result, id) in FINDINGS {
        assert!(modifier(result) < 0, "{result} has a finding but no penalty");
        assert!(crate::findings::entry(id).is_some(), "{id} is missing from the catalog");
    }
}

#[test]
fn a_bare_site_gets_a_d() {
    let module = run(&site(&[], PAGE));
    let found = ids(&module);
    let data = module.data.unwrap();
    // CSP -25, X-Frame-Options -20, HSTS -20, X-Content-Type-Options -5.
    assert_eq!(data.score, Some(30));
    assert_eq!(data.grade, Some("D"));
    // Port 80 was not checked in this snapshot: the grade stands, marked partial.
    assert_eq!(module.status, Status::Partial);
    for id in [
        "sec.csp.missing",
        "sec.xfo.missing",
        "sec.hsts.missing",
        "sec.xcto.missing",
    ] {
        assert!(found.contains(&id), "{id} in {found:?}");
    }
}

#[test]
fn a_hardened_site_gets_an_a_plus() {
    let mut s = site(
        &[
            (
                "content-security-policy",
                "default-src 'none'; img-src 'self'; frame-ancestors 'none'",
            ),
            (
                "strict-transport-security",
                "max-age=63072000; includeSubDomains; preload",
            ),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("cross-origin-opener-policy", "same-origin"),
            ("permissions-policy", "camera=()"),
            ("set-cookie", "__Host-sess=1; Path=/; Secure; HttpOnly; SameSite=Lax"),
        ],
        PAGE,
    );
    s.http_check = Some(HttpCheck::Response {
        status: 301,
        location: Some("https://example.com/".into()),
        route: Vec::new(),
    });
    let module = run(&s);
    assert_eq!(module.status, Status::Ok);
    let data = module.data.unwrap();
    // +10 CSP, +5 cookies, +5 XFO via CSP, +5 referrer, +10 COOP.
    assert_eq!(data.score, Some(135));
    assert_eq!(data.grade, Some("A+"));
    assert!(module.findings.is_empty(), "{:?}", ids(&run(&s)));
}

#[test]
fn csp_results() {
    let csp = |policy: &'static str| result(&header("content-security-policy", policy), "content-security-policy");
    assert_eq!(csp("default-src 'self'"), "csp-implemented-with-no-unsafe");
    assert_eq!(
        csp("default-src 'none'; script-src 'self'"),
        "csp-implemented-with-no-unsafe-default-src-none"
    );
    assert_eq!(
        csp("default-src 'self'; script-src 'self' 'unsafe-inline'"),
        "csp-implemented-with-unsafe-inline"
    );
    assert_eq!(
        csp("default-src 'self'; script-src https:"),
        "csp-implemented-with-unsafe-inline"
    );
    assert_eq!(
        csp("default-src 'self'; object-src *"),
        "csp-implemented-with-unsafe-inline"
    );
    // A nonce disables 'unsafe-inline' in browsers that know nonces.
    assert_eq!(
        csp("default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'"),
        "csp-implemented-with-no-unsafe"
    );
    assert_eq!(
        csp("script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; style-src 'self'"),
        "csp-implemented-with-no-unsafe"
    );
    assert_eq!(
        csp("default-src 'self'; script-src 'strict-dynamic'"),
        "csp-header-invalid"
    );
    assert_eq!(
        csp("default-src 'self'; script-src 'self' 'unsafe-eval'"),
        "csp-implemented-with-unsafe-eval"
    );
    assert_eq!(
        csp("default-src 'self' http://cdn.example.net"),
        "csp-implemented-with-insecure-scheme"
    );
    assert_eq!(
        csp("default-src 'self'; img-src http:"),
        "csp-implemented-with-insecure-scheme-in-passive-content-only"
    );
    assert_eq!(
        csp("default-src 'self'; style-src 'self' 'unsafe-inline'"),
        "csp-implemented-with-unsafe-inline-in-style-src-only"
    );
    assert_eq!(csp("default-src 'self'; default-src 'none'"), "csp-header-invalid");
    assert_eq!(csp("img"), "csp-header-invalid");
    assert_eq!(
        csp("default-src 'self'; report-uri /a; report-uri /b"),
        "csp-implemented-but-duplicate-directives"
    );
    // Directives are case-insensitive.
    assert_eq!(
        csp("DEFAULT-SRC 'none'"),
        "csp-implemented-with-no-unsafe-default-src-none"
    );

    let report_only = header("content-security-policy-report-only", "default-src 'self'");
    assert_eq!(
        result(&report_only, "content-security-policy"),
        "csp-not-implemented-but-reporting-enabled"
    );
    let meta = site(
        &[],
        "<html><head><meta http-equiv=Content-Security-Policy content=\"default-src 'none'\"></head></html>",
    );
    assert_eq!(
        result(&meta, "content-security-policy"),
        "csp-implemented-with-no-unsafe-default-src-none"
    );
}

#[test]
fn csp_policies_combine_by_intersection() {
    let csp = parse_csp(&["default-src 'self' https://a.example", "default-src 'self'; img-src *"]).unwrap();
    assert_eq!(csp.get("default-src").unwrap(), &["'self'"]);
    // A directive only in a later policy ends up as 'none', as in the Observatory.
    assert_eq!(csp.get("img-src").unwrap(), &["'none'"]);
    // An empty source list means 'none'.
    let csp = parse_csp(&["script-src; default-src 'self'"]).unwrap();
    assert_eq!(csp.get("script-src").unwrap(), &["'none'"]);
    assert!(path_part_match("https://a.example/js/", "https://a.example/js/app.js"));
    assert!(!path_part_match("https://a.example/js", "https://a.example/js/app.js"));
}

#[test]
fn frame_ancestors_counts_as_x_frame_options() {
    let s = header("content-security-policy", "default-src 'self'; frame-ancestors 'self'");
    assert_eq!(result(&s, "x-frame-options"), "x-frame-options-implemented-via-csp");
    let xfo = |v: &'static str| result(&header("x-frame-options", v), "x-frame-options");
    assert_eq!(xfo("SAMEORIGIN"), "x-frame-options-sameorigin-or-deny");
    assert_eq!(xfo("deny"), "x-frame-options-sameorigin-or-deny");
    assert_eq!(xfo("ALLOW-FROM https://a.example"), "x-frame-options-allow-from-origin");
    assert_eq!(xfo("allowall"), "x-frame-options-header-invalid");
}

#[test]
fn cookie_results() {
    let cookie = |raw: &'static str| result(&header("set-cookie", raw), "cookies");
    assert_eq!(result(&site(&[], PAGE), "cookies"), "cookies-not-found");
    assert_eq!(cookie("sessionid=1; Path=/"), "cookies-session-without-secure-flag");
    assert_eq!(cookie("sessionid=1; Secure"), "cookies-session-without-httponly-flag");
    assert_eq!(
        cookie("sessionid=1; Secure; HttpOnly"),
        "cookies-secure-with-httponly-sessions"
    );
    assert_eq!(
        cookie("sessionid=1; Secure; HttpOnly; SameSite=Strict"),
        "cookies-secure-with-httponly-sessions-and-samesite"
    );
    assert_eq!(cookie("theme=dark"), "cookies-without-secure-flag");
    assert_eq!(cookie("csrftoken=x; Secure"), "cookies-anticsrf-without-samesite-flag");
    assert_eq!(cookie("a=1; Secure; SameSite=Bogus"), "cookies-samesite-flag-invalid");
    assert_eq!(cookie("a=1; SameSite=None"), "cookies-samesite-flag-invalid");

    // With a passing HSTS, a missing Secure flag costs less.
    let hsts = ("strict-transport-security", "max-age=31536000");
    let s = site(&[hsts, ("set-cookie", "theme=dark; SameSite=Lax")], PAGE);
    assert_eq!(
        result(&s, "cookies"),
        "cookies-without-secure-flag-but-protected-by-hsts"
    );
    let s = site(&[hsts, ("set-cookie", "sess=1; HttpOnly; SameSite=Lax")], PAGE);
    assert_eq!(
        result(&s, "cookies"),
        "cookies-session-without-secure-flag-but-protected-by-hsts"
    );

    // The worst cookie decides; findings name the cookies.
    let s = site(
        &[
            ("set-cookie", "theme=dark; Secure"),
            ("set-cookie", "PHPSESSID=x; path=/"),
        ],
        PAGE,
    );
    let module = run(&s);
    let f = module
        .findings
        .iter()
        .find(|f| f.id == "sec.cookies.session_insecure")
        .unwrap();
    assert_eq!(f.evidence, "PHPSESSID");
}

#[test]
fn redirection_results() {
    let with = |status: u16, location: Option<&str>, route: &[&str]| {
        let mut s = site(&[], PAGE);
        s.http_check = Some(HttpCheck::Response {
            status,
            location: location.map(str::to_owned),
            route: route.iter().map(|r| r.to_string()).collect(),
        });
        result(&s, "redirection")
    };
    assert_eq!(with(301, Some("https://example.com/"), &[]), "redirection-to-https");
    assert_eq!(with(302, Some("/home"), &[]), "redirection-not-to-https");
    assert_eq!(with(200, None, &[]), "redirection-missing");
    assert_eq!(
        with(301, Some("https://www.example.com/"), &[]),
        "redirection-off-host-from-http"
    );
    assert_eq!(
        with(
            301,
            Some("http://www.example.com/"),
            &["http://www.example.com/", "https://www.example.com/"]
        ),
        "redirection-not-to-https-on-initial-redirection"
    );
    assert_eq!(
        with(301, Some("http://www.example.com/"), &["http://www.example.com/"]),
        "redirection-not-to-https"
    );

    let mut s = site(&[], PAGE);
    s.http_check = Some(HttpCheck::Failed(FetchFailure {
        kind: FailureKind::Connect,
        url: "http://example.com/".into(),
        message: "connection refused".into(),
    }));
    assert_eq!(result(&s, "redirection"), "redirection-not-needed-no-http");

    // Ending on a certificate that does not verify.
    let mut s = site(&[], PAGE);
    s.chain[0].connection = tls(Verification::Invalid {
        problem: crate::snapshot::CertProblem::Expired,
        message: "expired".into(),
    });
    s.http_check = Some(HttpCheck::Response {
        status: 301,
        location: Some("https://example.com/".into()),
        route: Vec::new(),
    });
    assert_eq!(result(&s, "redirection"), "redirection-invalid-cert");
    assert_eq!(result(&s, "strict-transport-security"), "hsts-invalid-cert");
}

#[test]
fn preloaded_domains_get_credit() {
    // Every .dev domain is on the HSTS preload list.
    let mut s = site(&[], PAGE);
    s.input = "https://insite.dev/".into();
    s.chain[0].url = "https://insite.dev/".into();
    s.http_check = Some(HttpCheck::Response {
        status: 200,
        location: None,
        route: Vec::new(),
    });
    assert_eq!(result(&s, "strict-transport-security"), "hsts-preloaded");
    assert_eq!(result(&s, "redirection"), "redirection-all-redirects-preloaded");
    // A missing Secure flag counts as protected by HSTS.
    s.chain[0]
        .headers
        .push(("set-cookie".into(), "theme=dark; SameSite=Lax".into()));
    assert_eq!(
        result(&s, "cookies"),
        "cookies-without-secure-flag-but-protected-by-hsts"
    );
    // Without HTTPS there is no credit.
    s.chain[0].url = "http://insite.dev/".into();
    s.https_fallback = Some(FetchFailure {
        kind: FailureKind::Connect,
        url: "https://insite.dev/".into(),
        message: "refused".into(),
    });
    assert_eq!(result(&s, "strict-transport-security"), "hsts-not-implemented-no-https");
}

#[test]
fn referrer_results() {
    let referrer = |v: &'static str| result(&header("referrer-policy", v), "referrer-policy");
    assert_eq!(referrer("strict-origin-when-cross-origin"), "referrer-policy-private");
    assert_eq!(referrer("no-referrer-when-downgrade"), "referrer-policy-unsafe");
    // The last valid value wins.
    assert_eq!(referrer("unsafe-url, same-origin"), "referrer-policy-private");
    assert_eq!(referrer("same-origin, bogus"), "referrer-policy-private");
    assert_eq!(referrer("bogus"), "referrer-policy-header-invalid");
    let meta = site(&[], "<html><head><meta name=referrer content=unsafe-url></head></html>");
    assert_eq!(result(&meta, "referrer-policy"), "referrer-policy-unsafe");
}

#[test]
fn hsts_results() {
    let hsts = |v: &'static str| result(&header("strict-transport-security", v), "strict-transport-security");
    assert_eq!(
        hsts("max-age=31536000; includeSubDomains"),
        "hsts-implemented-max-age-at-least-six-months"
    );
    assert_eq!(
        hsts("max-age=\"15768000\""),
        "hsts-implemented-max-age-at-least-six-months"
    );
    assert_eq!(hsts("max-age=86400"), "hsts-implemented-max-age-less-than-six-months");
    // The Observatory's six months are 180 days.
    assert_eq!(hsts("max-age=15552000"), "hsts-implemented-max-age-at-least-six-months");
    assert_eq!(
        hsts("max-age=15551999"),
        "hsts-implemented-max-age-less-than-six-months"
    );
    assert_eq!(hsts("includeSubDomains"), "hsts-header-invalid");
    assert_eq!(hsts("max-age=31536000, max-age=0"), "hsts-header-invalid");
    let mut plain = site(&[], PAGE);
    plain.chain[0].url = "http://example.com/".into();
    assert_eq!(
        result(&plain, "strict-transport-security"),
        "hsts-not-implemented-no-https"
    );
}

#[test]
fn sri_results() {
    let page = |scripts: &str| site(&[], &format!("<html><head>{scripts}</head><body></body></html>"));
    let sri = |scripts: &str| result(&page(scripts), "subresource-integrity");
    assert_eq!(sri(""), "sri-not-implemented-but-no-scripts-loaded");
    assert_eq!(
        sri("<script>var a</script>"),
        "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"
    );
    assert_eq!(
        sri("<script src=/app.js></script>"),
        "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"
    );
    assert_eq!(
        sri("<script src=https://static.example.com/a.js></script>"),
        "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"
    );
    assert_eq!(
        sri("<script src=/app.js integrity=sha384-x></script>"),
        "sri-implemented-and-all-scripts-loaded-securely"
    );
    assert_eq!(
        sri("<script src=https://cdn.other.net/a.js></script>"),
        "sri-not-implemented-but-external-scripts-loaded-securely"
    );
    assert_eq!(
        sri("<script src=https://cdn.other.net/a.js integrity=sha384-x></script>"),
        "sri-implemented-and-external-scripts-loaded-securely"
    );
    // Protocol-relative addresses count as insecure, even to the site's own domain.
    assert_eq!(
        sri("<script src=//cdn.other.net/a.js></script>"),
        "sri-not-implemented-and-external-scripts-not-loaded-securely"
    );
    assert_eq!(
        sri("<script src=http://cdn.other.net/a.js integrity=sha384-x></script>"),
        "sri-implemented-but-external-scripts-not-loaded-securely"
    );
    // The Observatory ranks "secure but no SRI" below "SRI but insecure".
    assert_eq!(
        sri("<script src=http://a.net/a.js integrity=sha384-x></script><script src=https://b.net/b.js></script>"),
        "sri-not-implemented-but-external-scripts-loaded-securely"
    );
    // An empty integrity attribute is no integrity.
    assert_eq!(
        sri("<script src=https://cdn.other.net/a.js integrity></script>"),
        "sri-not-implemented-but-external-scripts-loaded-securely"
    );
    let json = site(&[("content-type", "application/json")], "{}");
    assert_eq!(
        result(&json, "subresource-integrity"),
        "sri-not-implemented-response-not-html"
    );
}

#[test]
fn simple_header_results() {
    assert_eq!(
        result(&header("x-content-type-options", "nosniff"), "x-content-type-options"),
        "x-content-type-options-nosniff"
    );
    assert_eq!(
        result(&header("x-content-type-options", "sniff"), "x-content-type-options"),
        "x-content-type-options-header-invalid"
    );
    let corp = |v: &'static str| {
        result(
            &header("cross-origin-resource-policy", v),
            "cross-origin-resource-policy",
        )
    };
    assert_eq!(corp("same-site"), "corp-implemented-with-same-site");
    assert_eq!(corp("Same-Origin"), "corp-implemented-with-same-origin");
    assert_eq!(corp("bogus"), "corp-header-invalid");
    let coop = |v: &'static str| result(&header("cross-origin-opener-policy", v), "cross-origin-opener-policy");
    assert_eq!(coop("same-origin"), "coop-implemented-with-same-origin");
    assert_eq!(
        coop("same-origin; report-to=\"coop\""),
        "coop-implemented-with-same-origin"
    );
    // Structured-field tokens are case-sensitive.
    assert_eq!(coop("Same-Origin"), "coop-header-invalid");
    assert_eq!(coop("same-origin,"), "coop-header-invalid");
    let twice = site(
        &[
            ("cross-origin-embedder-policy", "require-corp"),
            ("cross-origin-embedder-policy", "require-corp"),
        ],
        PAGE,
    );
    assert_eq!(result(&twice, "cross-origin-embedder-policy"), "coep-header-invalid");
    let cors = header("access-control-allow-origin", "*");
    assert_eq!(
        result(&cors, "cross-origin-resource-sharing"),
        "cross-origin-resource-sharing-implemented-with-public-access"
    );
}

#[test]
fn structured_field_tokens() {
    assert_eq!(sf_token("require-corp"), Some("require-corp"));
    assert_eq!(sf_token("  credentialless  "), Some("credentialless"));
    assert_eq!(sf_token("same-origin;report-to=\"a\\\"b\""), Some("same-origin"));
    assert_eq!(
        sf_token("same-origin; a=?1; b=:AAA=:; c=-1.5; d=tok/en"),
        Some("same-origin")
    );
    assert_eq!(sf_token("\"same-origin\""), None);
    assert_eq!(sf_token("same-origin; Report=1"), None);
    assert_eq!(sf_token("same-origin junk"), None);
    assert_eq!(sf_token(""), None);
}

#[test]
fn no_grade_for_pages_that_are_not_the_site() {
    let error = {
        let mut s = site(&[], PAGE);
        s.chain[0].status = 403;
        s
    };
    let module = run(&error);
    assert_eq!(module.status, Status::Partial);
    let data = module.data.unwrap();
    assert_eq!(data.grade, None);
    assert_eq!(data.score, None);
    assert!(module.findings.is_empty());

    let challenge = site(&[("cf-mitigated", "challenge")], PAGE);
    let module = run(&challenge);
    assert_eq!(module.data.unwrap().grade, None);
    assert!(module.reason.unwrap().contains("challenge"));

    // A non-HTML response is graded, as the Observatory does.
    let json = site(&[("content-type", "application/json")], "{}");
    assert!(run(&json).data.unwrap().grade.is_some());
}

#[test]
fn findings_outside_the_grade() {
    let body = "<html><head><script src=http://cdn.example.net/a.js></script></head><body>\
                <img src=http://img.example.net/a.png><form action=http://example.com/login></form></body></html>";

    // https://example.com/ redirects to http://example.com/, which serves the page.
    let mut s = site(&[("server", "nginx/1.25.3")], body);
    let mut redirect = s.chain[0].clone();
    redirect.status = 301;
    redirect.headers = vec![("location".into(), "http://example.com/".into())];
    s.chain[0].url = "http://example.com/".into();
    s.chain[0].connection = ConnectionUse::Reused;
    s.chain.insert(0, redirect);
    let found = ids(&run(&s));
    assert!(found.contains(&"sec.https.downgrade"), "{found:?}");
    assert!(found.contains(&"sec.version_leak"), "{found:?}");
    // Mixed content only exists on HTTPS pages.
    assert!(!found.contains(&"sec.mixed_content.active"), "{found:?}");

    let module = run(&site(&[("server", "cloudflare")], body));
    let found = ids(&module);
    assert!(found.contains(&"sec.mixed_content.active"), "{found:?}");
    assert!(found.contains(&"sec.form.insecure"), "{found:?}");
    assert!(found.contains(&"sec.permissions_policy.missing"), "{found:?}");
    assert!(!found.contains(&"sec.version_leak"), "{found:?}");
    let data = module.data.unwrap();
    assert_eq!(
        data.mixed_content,
        ["http://cdn.example.net/a.js", "http://img.example.net/a.png"]
    );
}

#[test]
fn version_leaks() {
    for leak in [
        "nginx/1.25.3",
        "Apache/2.4.41 (Ubuntu)",
        "Microsoft-IIS/10.0",
        "PHP/8.2.1",
        "4.0.30319",
    ] {
        assert!(reveals_version(leak), "{leak}");
    }
    for name in ["cloudflare", "nginx", "AmazonS3", "Apache", "Next.js", "ASP.NET", "gws"] {
        assert!(!reveals_version(name), "{name}");
    }
}

#[test]
fn https_unavailable_is_one_finding() {
    let mut s = site(&[], PAGE);
    s.chain[0].url = "http://example.com/".into();
    s.chain[0].connection = ConnectionUse::Reused;
    s.https_fallback = Some(FetchFailure {
        kind: FailureKind::Connect,
        url: "https://example.com/".into(),
        message: "could not connect to example.com port 443: connection refused".into(),
    });
    s.http_check = Some(HttpCheck::Response {
        status: 200,
        location: None,
        route: Vec::new(),
    });
    let module = run(&s);
    let ids = ids(&module);
    assert!(ids.contains(&"sec.https.unavailable"), "{ids:?}");
    assert!(!ids.contains(&"sec.redirect.missing"), "{ids:?}");
    let data = module.data.unwrap();
    // The test still counts in the score.
    assert!(data.tests.iter().any(|t| t.result == "redirection-missing"));
    assert!(data.tests.iter().any(|t| t.result == "hsts-not-implemented-no-https"));
}

fn txt(status: Option<u16>, body: &str) -> AuxFile {
    AuxFile {
        requested: "https://example.com/.well-known/security.txt".into(),
        url: "https://example.com/.well-known/security.txt".into(),
        status,
        content_type: Some("text/plain".into()),
        body: body.as_bytes().to_vec(),
        truncated: false,
        redirects: 0,
        error: None,
    }
}

#[test]
fn security_txt_states() {
    let mut s = site(&[], PAGE);
    s.collected_at = UNIX_EPOCH + Duration::from_secs(1_793_212_345); // 2026-10-28T18:32:25Z
    let read = |file: AuxFile| security_txt(&file, &s);

    let found = read(txt(
        Some(200),
        "# hi\nContact: mailto:sec@example.com\nExpires: 2027-06-01T00:00:00Z\n",
    ));
    assert_eq!(found.state, "found");
    assert_eq!(found.contact, ["mailto:sec@example.com"]);
    assert!(!found.expired);
    let expired = read(txt(
        Some(200),
        "Contact: mailto:sec@example.com\nExpires: 2026-10-28T18:00:00Z\n",
    ));
    assert!(expired.expired);
    // An offset can move the moment past now.
    let later = read(txt(
        Some(200),
        "Contact: mailto:a@b.c\nExpires: 2026-10-28T18:00:00-01:00\n",
    ));
    assert!(!later.expired);
    assert_eq!(
        read(txt(Some(200), "<!doctype html><html>Contact: x</html>")).state,
        "not_security_txt"
    );
    assert_eq!(read(txt(Some(404), "")).state, "absent");
    assert_eq!(read(txt(None, "")).state, "failed");

    s.auxiliary.security_txt = Some(txt(Some(200), "Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00Z\n"));
    assert!(ids(&run(&s)).contains(&"sec.security_txt.expired"));
}

#[test]
fn rfc3339_timestamps() {
    assert_eq!(rfc3339_seconds("2026-10-28T18:32:25Z"), Some(1_793_212_345));
    assert_eq!(rfc3339_seconds("2026-10-28T19:32:25+01:00"), Some(1_793_212_345));
    assert_eq!(rfc3339_seconds("2026-10-28T18:32:25.123Z"), Some(1_793_212_345));
    assert_eq!(rfc3339_seconds("2000-02-29T00:00:00Z"), Some(951_782_400));
    assert_eq!(rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(rfc3339_seconds("2026-13-01T00:00:00Z"), None);
    assert_eq!(rfc3339_seconds("tomorrow"), None);
    assert_eq!(rfc3339_seconds("2026-10-28T18:32:25"), None);
}
