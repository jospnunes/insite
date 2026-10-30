//! Security grade, following the MDN HTTP Observatory scoring
//! (mdn/mdn-http-observatory@2776308, MPL-2.0): twelve tests, each with a score
//! modifier; every site starts at 100, penalties come off, and bonuses only count
//! when the penalized score is still 90 or more. The tests below reproduce the
//! Observatory's decisions, quirks included, so a grade here can be compared with
//! one there. A public methodology keeps the grade auditable.
//!
//! One known difference: no cross-origin request is sent, so the CORS test cannot
//! find its -50 case (a site reflecting any Origin with credentials allowed).
//!
//! Checks outside the methodology (HTTPS downgrades, mixed content, forms posting
//! over HTTP, version leaks, Permissions-Policy, security.txt) are findings that
//! leave the grade alone.

use serde::Serialize;
use url::Url;

use super::content::Content;
use super::network::opener;
use crate::collect::records::registrable;
use crate::data::hsts_preloaded;
use crate::extract::PageFacts;
use crate::findings::finding;
use crate::report::{Finding, Module, Status};
use crate::snapshot::{AuxFile, FailureKind, Hop, HttpCheck, Snapshot, Verification};

pub const METHODOLOGY: &str = "MDN HTTP Observatory scoring (mdn/mdn-http-observatory@2776308)";
/// 180 days, the Observatory's "six months".
const SIX_MONTHS: u64 = 15_552_000;
const EXTRA_CREDIT_FROM: i32 = 90;

#[derive(Debug, Clone, Serialize)]
pub struct Security {
    /// Absent when the response does not represent the site.
    pub grade: Option<&'static str>,
    pub score: Option<i32>,
    pub methodology: &'static str,
    pub tests: Vec<TestResult>,
    pub security_txt: Option<SecurityTxt>,
    /// Resources an HTTPS page loads over plain HTTP.
    pub mixed_content: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub test: &'static str,
    pub result: &'static str,
    pub modifier: i32,
    /// What the result is based on: a header value, script URLs, the HTTP route.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityTxt {
    pub url: String,
    /// `found`, `absent`, `not_security_txt` (a page without a Contact field) or `failed`.
    pub state: &'static str,
    pub contact: Vec<String>,
    pub expires: Option<String>,
    pub expired: bool,
}

/// Results that need a finding, with its id. Results without one pass, or are
/// covered by another module (an invalid certificate is a TLS finding).
const FINDINGS: &[(&str, &str)] = &[
    ("csp-not-implemented", "sec.csp.missing"),
    ("csp-not-implemented-but-reporting-enabled", "sec.csp.report_only"),
    ("csp-header-invalid", "sec.csp.invalid"),
    ("csp-implemented-with-unsafe-inline", "sec.csp.unsafe_inline"),
    ("csp-implemented-with-insecure-scheme", "sec.csp.insecure_scheme"),
    ("csp-implemented-with-unsafe-eval", "sec.csp.unsafe_eval"),
    (
        "csp-implemented-with-insecure-scheme-in-passive-content-only",
        "sec.csp.insecure_passive",
    ),
    ("cookies-session-without-secure-flag", "sec.cookies.session_insecure"),
    ("cookies-session-without-httponly-flag", "sec.cookies.session_httponly"),
    ("cookies-anticsrf-without-samesite-flag", "sec.cookies.csrf_samesite"),
    ("cookies-samesite-flag-invalid", "sec.cookies.samesite_invalid"),
    ("cookies-without-secure-flag", "sec.cookies.insecure"),
    (
        "cookies-session-without-secure-flag-but-protected-by-hsts",
        "sec.cookies.session_insecure_hsts",
    ),
    (
        "cookies-without-secure-flag-but-protected-by-hsts",
        "sec.cookies.insecure_hsts",
    ),
    ("redirection-missing", "sec.redirect.missing"),
    ("redirection-not-to-https", "sec.redirect.not_https"),
    (
        "redirection-not-to-https-on-initial-redirection",
        "sec.redirect.initial_http",
    ),
    ("redirection-off-host-from-http", "sec.redirect.off_host"),
    ("referrer-policy-unsafe", "sec.referrer.unsafe"),
    ("referrer-policy-header-invalid", "sec.referrer.invalid"),
    ("hsts-not-implemented", "sec.hsts.missing"),
    ("hsts-header-invalid", "sec.hsts.invalid"),
    ("hsts-implemented-max-age-less-than-six-months", "sec.hsts.short"),
    (
        "sri-not-implemented-but-external-scripts-loaded-securely",
        "sec.sri.missing",
    ),
    (
        "sri-implemented-but-external-scripts-not-loaded-securely",
        "sec.sri.insecure",
    ),
    (
        "sri-not-implemented-and-external-scripts-not-loaded-securely",
        "sec.sri.insecure",
    ),
    ("x-content-type-options-not-implemented", "sec.xcto.missing"),
    ("x-content-type-options-header-invalid", "sec.xcto.invalid"),
    ("x-frame-options-not-implemented", "sec.xfo.missing"),
    ("x-frame-options-header-invalid", "sec.xfo.invalid"),
    ("corp-header-invalid", "sec.corp.invalid"),
    ("coep-header-invalid", "sec.coep.invalid"),
    ("coop-header-invalid", "sec.coop.invalid"),
];

/// The Observatory's score table, for the results insite can produce.
pub fn modifier(result: &str) -> i32 {
    match result {
        "csp-implemented-with-no-unsafe-default-src-none" => 10,
        "csp-implemented-with-no-unsafe" => 5,
        "csp-implemented-with-unsafe-inline-in-style-src-only" => 0,
        "csp-implemented-with-insecure-scheme-in-passive-content-only" => -10,
        "csp-implemented-with-unsafe-eval" => -10,
        "csp-implemented-with-unsafe-inline" => -20,
        "csp-implemented-with-insecure-scheme" => -20,
        "csp-header-invalid" | "csp-not-implemented" | "csp-not-implemented-but-reporting-enabled" => -25,
        "csp-implemented-but-duplicate-directives" => 0,
        "cookies-secure-with-httponly-sessions-and-samesite" => 5,
        "cookies-secure-with-httponly-sessions" | "cookies-not-found" => 0,
        "cookies-without-secure-flag-but-protected-by-hsts" => -5,
        "cookies-session-without-secure-flag-but-protected-by-hsts" => -10,
        "cookies-without-secure-flag" | "cookies-samesite-flag-invalid" | "cookies-anticsrf-without-samesite-flag" => {
            -20
        }
        "cookies-session-without-httponly-flag" => -30,
        "cookies-session-without-secure-flag" => -40,
        "cross-origin-resource-sharing-implemented-with-universal-access" => -50,
        "redirection-off-host-from-http" => -5,
        "redirection-not-to-https-on-initial-redirection" => -10,
        "redirection-not-to-https" | "redirection-missing" | "redirection-invalid-cert" => -20,
        "referrer-policy-private" => 5,
        "referrer-policy-unsafe" | "referrer-policy-header-invalid" => -5,
        "hsts-preloaded" => 5,
        "hsts-implemented-max-age-less-than-six-months" => -10,
        "hsts-not-implemented" | "hsts-header-invalid" | "hsts-not-implemented-no-https" | "hsts-invalid-cert" => -20,
        "sri-implemented-and-all-scripts-loaded-securely" | "sri-implemented-and-external-scripts-loaded-securely" => 5,
        "sri-not-implemented-but-external-scripts-loaded-securely" => -5,
        "sri-implemented-but-external-scripts-not-loaded-securely" => -20,
        "sri-not-implemented-and-external-scripts-not-loaded-securely" => -50,
        "x-content-type-options-not-implemented" | "x-content-type-options-header-invalid" => -5,
        "x-frame-options-implemented-via-csp" | "x-frame-options-sameorigin-or-deny" => 5,
        "x-frame-options-not-implemented" | "x-frame-options-header-invalid" => -20,
        "corp-implemented-with-same-origin" | "corp-implemented-with-same-site" => 10,
        "coep-implemented-with-require-corp" | "coep-implemented-with-credentialless" => 10,
        "coop-implemented-with-same-origin"
        | "coop-implemented-with-same-origin-allow-popups"
        | "coop-implemented-with-noopener-allow-popups" => 10,
        "corp-header-invalid" | "coep-header-invalid" | "coop-header-invalid" => -5,
        _ => 0,
    }
}

pub fn grade(score: i32) -> &'static str {
    match score {
        100.. => "A+",
        90..=99 => "A",
        85..=89 => "A-",
        80..=84 => "B+",
        70..=79 => "B",
        65..=69 => "B-",
        60..=64 => "C+",
        50..=59 => "C",
        45..=49 => "C-",
        40..=44 => "D+",
        30..=39 => "D",
        25..=29 => "D-",
        _ => "F",
    }
}

/// Penalties always count; bonuses only from 90 up. Never below zero.
pub fn score(modifiers: impl IntoIterator<Item = i32>) -> i32 {
    let (mut penalized, mut total) = (100, 100);
    for m in modifiers {
        total += m;
        penalized += m.min(0);
    }
    (if penalized >= EXTRA_CREDIT_FROM {
        total
    } else {
        penalized
    })
    .max(0)
}

/// What the tests read: the final response ("auto" in the Observatory), its page
/// and how it was reached.
struct Inputs<'a> {
    snapshot: &'a Snapshot,
    last: &'a Hop,
    facts: Option<&'a PageFacts>,
    page: Option<Url>,
    https: bool,
    verified: bool,
    /// HTTPS answered for the input address (the Observatory's "https" response).
    https_reached: bool,
    /// The host the user asked for, which the HSTS preload check looks up.
    input_host: Option<String>,
}

impl<'a> Inputs<'a> {
    /// Values of a header, repeated ones joined with ", " as Node's HTTP client
    /// (and so the Observatory) sees them.
    fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self.headers(name);
        (!values.is_empty()).then(|| values.join(", "))
    }

    fn headers(&self, name: &str) -> Vec<&'a str> {
        self.last
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// `<meta http-equiv="content-security-policy">` contents.
    fn meta_csp(&self) -> Vec<&'a str> {
        let Some(facts) = self.facts else { return Vec::new() };
        facts
            .metas
            .iter()
            .filter(|m| {
                m.http_equiv
                    .as_deref()
                    .is_some_and(|h| h.trim().eq_ignore_ascii_case("content-security-policy"))
            })
            .filter_map(|m| m.content.as_deref().filter(|c| !c.is_empty()))
            .collect()
    }

    /// The last `<meta name="referrer">`, which the Observatory treats as a header.
    fn meta_referrer(&self) -> Option<&'a str> {
        self.facts?
            .metas
            .iter()
            .filter(|m| {
                m.name
                    .as_deref()
                    .is_some_and(|n| n.trim().eq_ignore_ascii_case("referrer"))
            })
            .filter_map(|m| m.content.as_deref().filter(|c| !c.is_empty()))
            .next_back()
    }
}

pub fn analyze(snapshot: &Snapshot, content: &Result<Content, String>) -> Module<Security> {
    let Some(last) = snapshot.chain.last() else {
        return Module {
            status: Status::Skipped,
            reason: Some("there is no response to grade".into()),
            data: None,
            findings: Vec::new(),
        };
    };
    let page = Url::parse(&last.url).ok();
    let https = page.as_ref().is_some_and(|u| u.scheme() == "https");
    let input = Inputs {
        snapshot,
        last,
        facts: content.as_ref().ok().map(|c| &c.facts),
        verified: hop_verified(snapshot, last),
        page,
        https,
        https_reached: snapshot.https_fallback.is_none()
            && snapshot.chain.iter().any(|h| h.url.starts_with("https://")),
        input_host: Url::parse(&snapshot.input)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned)),
    };

    let hsts = hsts_test(&input);
    let csp = csp_test(&input);
    let tests = vec![
        cookies_test(
            &input,
            matches!(
                hsts.result,
                "hsts-implemented-max-age-at-least-six-months" | "hsts-preloaded"
            ),
        ),
        xfo_test(&input, &csp),
        csp.test,
        cors_test(&input),
        redirection_test(&input),
        referrer_test(&input),
        hsts,
        sri_test(&input),
        xcto_test(&input),
        corp_test(&input),
        token_policy_test(&input, COEP),
        token_policy_test(&input, COOP),
    ];
    let score = score(tests.iter().map(|t| t.modifier));

    // A grade describes the site only when the response is a real page of it: not
    // an error, not a bot challenge. A non-HTML response is graded as the
    // Observatory grades it.
    let challenge = super::infra::challenge(snapshot).is_some();
    let (mut status, mut reason, representative) = match content {
        Ok(c) => (
            if c.limitation.is_some() {
                Status::Partial
            } else {
                Status::Ok
            },
            c.limitation.clone(),
            c.findings_allowed,
        ),
        Err(_) if !challenge && last.status < 400 && snapshot.page.is_some() => (Status::Ok, None, true),
        Err(why) => (Status::Partial, Some(format!("no grade: {why}")), false),
    };
    if representative && tests.iter().any(|t| t.result == "redirection-not-checked") {
        status = Status::Partial;
        reason.get_or_insert_with(|| "the plain HTTP redirection was not checked".into());
    }

    let mut findings = Vec::new();
    for t in &tests {
        if let Some((_, id)) = FINDINGS.iter().find(|(r, _)| *r == t.result) {
            findings.push(finding(id, &[("value", t.evidence.clone())], t.evidence.clone()));
        }
    }
    let mixed_content = input.facts.map(|f| mixed_content(f, https)).unwrap_or_default();
    extras(&input, &mixed_content, &mut findings);
    if !representative {
        // Only what does not depend on the page itself.
        findings.retain(|f| {
            ["sec.https.", "sec.redirect.", "sec.security_txt."]
                .iter()
                .any(|p| f.id.starts_with(p))
        });
    }
    let security_txt = snapshot
        .auxiliary
        .security_txt
        .as_ref()
        .map(|f| security_txt(f, snapshot));
    if let Some(txt) = security_txt.as_ref().filter(|t| t.expired) {
        let date = txt.expires.clone().unwrap_or_default();
        findings.push(finding(
            "sec.security_txt.expired",
            &[("date", date.clone())],
            format!("Expires: {date}"),
        ));
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(b.id)));
    findings.dedup_by(|a, b| a.id == b.id);

    Module {
        status,
        reason,
        data: Some(Security {
            grade: representative.then(|| grade(score)),
            score: representative.then_some(score),
            methodology: METHODOLOGY,
            tests,
            security_txt,
            mixed_content,
        }),
        findings,
    }
}

fn test(test: &'static str, result: &'static str, evidence: impl Into<String>) -> TestResult {
    TestResult {
        test,
        result,
        modifier: modifier(result),
        evidence: evidence.into(),
    }
}

/// Whether the TLS connection that served `hop` had a valid certificate.
fn hop_verified(snapshot: &Snapshot, hop: &Hop) -> bool {
    opener(&snapshot.chain, hop)
        .and_then(|c| c.tls.as_ref())
        .is_some_and(|t| t.verification == Verification::Valid)
}

// ---- Content Security Policy ------------------------------------------------

const DANGEROUSLY_BROAD: &[&str] = &[
    "ftp:",
    "http:",
    "https:",
    "*",
    "http://*",
    "http://*.*",
    "https://*",
    "https://*.*",
];
const UNSAFE_INLINE: &[&str] = &["'unsafe-inline'", "data:"];
const NONCES_HASHES: &[&str] = &["'sha256-", "'sha384-", "'sha512-", "'nonce-"];
const SHORTEST_POLICY: usize = 6;

#[derive(Debug, Default)]
struct Csp {
    /// Directive and its sources, lowercase, in order of appearance.
    directives: Vec<(String, Vec<String>)>,
    /// A repeated report-uri or report-to, the only repetition tolerated.
    duplicate_reports: bool,
}

impl Csp {
    fn get(&self, name: &str) -> Option<&Vec<String>> {
        self.directives.iter().find(|(d, _)| d == name).map(|(_, s)| s)
    }

    fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }
}

/// Parses and combines policies the way the Observatory does: a directive
/// repeated within one policy makes it invalid, and later policies can only keep
/// sources an earlier one allows (a directive first seen in a later policy ends
/// up as `'none'`). `None` when a policy is invalid.
fn parse_csp(policies: &[&str]) -> Option<Csp> {
    let clean: Vec<String> = policies
        .iter()
        .map(|p| p.replace(['\r', '\n'], "").trim().to_owned())
        .collect();
    if clean.iter().any(|p| p.chars().count() < SHORTEST_POLICY) {
        return None;
    }
    let mut csp = Csp::default();
    for (index, policy) in clean.iter().enumerate() {
        let mut seen: Vec<String> = Vec::new();
        for entry in policy.split(';') {
            let mut words = entry.split_whitespace();
            let Some(directive) = words.next() else { continue };
            let directive = directive.to_ascii_lowercase();
            if seen.contains(&directive) {
                if directive == "report-uri" || directive == "report-to" {
                    csp.duplicate_reports = true;
                } else {
                    return None;
                }
            } else {
                seen.push(directive.clone());
            }
            let mut sources: Vec<String> = words.map(str::to_lowercase).collect();
            if sources.is_empty() && directive.ends_with("-src") {
                sources.push("'none'".into());
            }
            if index == 0 {
                // Within a policy, a source that extends the previous one adds nothing.
                sources.sort();
                let mut kept: Vec<String> = Vec::new();
                for (i, s) in sources.iter().enumerate() {
                    if i == 0 || !s.starts_with(sources[i - 1].as_str()) {
                        kept.push(s.clone());
                    }
                }
                match csp.directives.iter_mut().find(|(d, _)| *d == directive) {
                    Some((_, existing)) => *existing = kept,
                    None => csp.directives.push((directive, kept)),
                }
            } else {
                match csp.directives.iter_mut().find(|(d, _)| *d == directive) {
                    Some((_, existing)) => {
                        let mut both: Vec<String> = sources
                            .iter()
                            .filter(|s| existing.iter().any(|e| path_part_match(e, s)))
                            .chain(
                                existing
                                    .iter()
                                    .filter(|e| sources.iter().any(|s| path_part_match(s, e))),
                            )
                            .cloned()
                            .collect();
                        both.sort();
                        both.dedup();
                        *existing = both;
                    }
                    None => csp.directives.push((directive, Vec::new())),
                }
            }
        }
    }
    for (_, sources) in &mut csp.directives {
        if sources.is_empty() {
            sources.push("'none'".into());
        }
    }
    Some(csp)
}

/// Whether source `a` covers source `b`: equal, or a path prefix ending in `/`.
fn path_part_match(a: &str, b: &str) -> bool {
    if a.is_empty() || (a == "/" && b.is_empty()) {
        return true;
    }
    let exact = !a.ends_with('/');
    let mut left: Vec<&str> = a.split('/').collect();
    let right: Vec<&str> = b.split('/').collect();
    if left.len() > right.len() || (exact && left.len() != right.len()) {
        return false;
    }
    if !exact {
        left.pop();
    }
    left.iter().zip(&right).all(|(x, y)| x == y)
}

struct CspOutcome {
    test: TestResult,
    /// The combined policy has a frame-ancestors directive (any value), which the
    /// Observatory's X-Frame-Options test accepts in place of the header.
    frame_ancestors: bool,
}

fn csp_test(input: &Inputs) -> CspOutcome {
    const NAME: &str = "content-security-policy";
    let split = |values: Vec<&str>| -> Vec<String> {
        values
            .iter()
            .flat_map(|v| v.split(','))
            .map(|s| s.trim().to_owned())
            .collect()
    };
    let http = split(input.headers("content-security-policy"));
    let meta = split(input.meta_csp());
    let all: Vec<&str> = http.iter().chain(&meta).map(String::as_str).collect();
    let evidence = all.join(" | ");
    let done = |result, frame_ancestors| CspOutcome {
        test: test(NAME, result, evidence.clone()),
        frame_ancestors,
    };

    let Some(csp) = parse_csp(&all) else {
        return done("csp-header-invalid", false);
    };
    let header_only = parse_csp(&http.iter().map(String::as_str).collect::<Vec<_>>()).unwrap_or_default();
    let meta_only = parse_csp(&meta.iter().map(String::as_str).collect::<Vec<_>>())
        .map(|mut c| {
            // Directives a <meta> policy cannot carry.
            c.directives
                .retain(|(d, _)| !matches!(d.as_str(), "frame-ancestors" | "report-uri" | "sandbox"));
            c
        })
        .unwrap_or_default();
    if header_only.is_empty() && meta_only.is_empty() {
        let report_only = input
            .header("content-security-policy-report-only")
            .filter(|v| !v.is_empty());
        let result = if report_only.is_some() {
            "csp-not-implemented-but-reporting-enabled"
        } else {
            "csp-not-implemented"
        };
        return CspOutcome {
            test: test(NAME, result, report_only.unwrap_or_default()),
            frame_ancestors: false,
        };
    }

    let star = || vec!["*".to_owned()];
    let fallback = |name: &str| {
        csp.get(name)
            .or_else(|| csp.get("default-src"))
            .cloned()
            .unwrap_or_else(star)
    };
    let mut script_src = fallback("script-src");
    let mut style_src = fallback("style-src");
    let object_src = fallback("object-src");
    let nonce_or_hash = |list: &[String]| list.iter().any(|s| NONCES_HASHES.iter().any(|p| s.starts_with(p)));
    for list in [&mut script_src, &mut style_src] {
        if nonce_or_hash(list) {
            list.retain(|s| s != "'unsafe-inline'");
        }
    }
    let mut result: Option<&'static str> = None;
    let strict_dynamic = script_src.iter().any(|s| s == "'strict-dynamic'");
    if strict_dynamic && nonce_or_hash(&script_src) {
        script_src.retain(|s| {
            !(DANGEROUSLY_BROAD.iter().any(|b| s.starts_with(b)) || s == "'self'" || s == "'unsafe-inline'")
        });
    } else if strict_dynamic {
        result = Some("csp-header-invalid");
    }
    let any_of = |list: &[String], set: &[&str]| list.iter().any(|s| set.contains(&s.as_str()));
    let insecure = |s: &String| s.starts_with("http:") || s.starts_with("ftp:");
    let active: Vec<&String> = csp
        .directives
        .iter()
        .filter(|(d, _)| !matches!(d.as_str(), "img-src" | "media-src" | "script-src"))
        .flat_map(|(_, s)| s)
        .chain(&script_src)
        .collect();
    let passive: Vec<String> = ["img-src", "media-src"]
        .iter()
        .flat_map(|d| {
            csp.get(d)
                .or_else(|| csp.get("default-src"))
                .cloned()
                .unwrap_or_default()
        })
        .collect();

    let mut first = |r: &'static str| {
        result.get_or_insert(r);
    };
    if any_of(&script_src, DANGEROUSLY_BROAD)
        || any_of(&script_src, UNSAFE_INLINE)
        || any_of(&object_src, DANGEROUSLY_BROAD)
    {
        first("csp-implemented-with-unsafe-inline");
    }
    if input.https && active.iter().any(|s| insecure(s)) {
        first("csp-implemented-with-insecure-scheme");
    }
    if script_src.iter().chain(&style_src).any(|s| s == "'unsafe-eval'") {
        first("csp-implemented-with-unsafe-eval");
    }
    if input.https && passive.iter().any(insecure) {
        first("csp-implemented-with-insecure-scheme-in-passive-content-only");
    }
    if any_of(&style_src, DANGEROUSLY_BROAD) || any_of(&style_src, UNSAFE_INLINE) {
        first("csp-implemented-with-unsafe-inline-in-style-src-only");
    }
    if csp.get("default-src").is_some_and(|d| d.len() == 1 && d[0] == "'none'") {
        first("csp-implemented-with-no-unsafe-default-src-none");
    }
    first("csp-implemented-with-no-unsafe");
    let mut result = result.unwrap_or("csp-implemented-with-no-unsafe");
    let passing = [
        "csp-implemented-with-no-unsafe",
        "csp-implemented-with-no-unsafe-default-src-none",
        "csp-implemented-with-unsafe-inline-in-style-src-only",
        "csp-implemented-with-insecure-scheme-in-passive-content-only",
    ];
    if csp.duplicate_reports && passing.contains(&result) {
        result = "csp-implemented-but-duplicate-directives";
    }
    done(result, csp.get("frame-ancestors").is_some())
}

// ---- Cookies ------------------------------------------------------------------

struct Cookie {
    name: String,
    secure: bool,
    http_only: bool,
    /// `None` when absent or not one of lax, strict, none.
    same_site: Option<String>,
}

fn parse_cookie(raw: &str) -> Option<Cookie> {
    let mut parts = raw.split(';');
    let (name, _) = parts.next()?.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut cookie = Cookie {
        name: name.to_owned(),
        secure: false,
        http_only: false,
        same_site: None,
    };
    for attr in parts {
        let (key, value) = attr.split_once('=').unwrap_or((attr, ""));
        match key.trim().to_ascii_lowercase().as_str() {
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => {
                let value = value.trim().to_ascii_lowercase();
                cookie.same_site = matches!(value.as_str(), "lax" | "strict" | "none").then_some(value);
            }
            _ => {}
        }
    }
    Some(cookie)
}

/// A `SameSite` attribute with a missing or unknown value.
fn invalid_same_site(raw: &str) -> bool {
    raw.trim().split(';').any(|part| {
        let mut kv = part.trim().splitn(3, '=');
        let key = kv.next().unwrap_or_default();
        key.trim().eq_ignore_ascii_case("samesite")
            && kv
                .next()
                .is_none_or(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "lax" | "strict" | "none"))
    })
}

fn cookies_test(input: &Inputs, hsts: bool) -> TestResult {
    const NAME: &str = "cookies";
    // From least to most severe, as the Observatory ranks them.
    const ORDER: &[&str] = &[
        "cookies-without-secure-flag-but-protected-by-hsts",
        "cookies-without-secure-flag",
        "cookies-session-without-secure-flag-but-protected-by-hsts",
        "cookies-samesite-flag-invalid",
        "cookies-anticsrf-without-samesite-flag",
        "cookies-session-without-httponly-flag",
        "cookies-session-without-secure-flag",
    ];
    let mut worst: Option<usize> = None;
    let mut names: Vec<String> = Vec::new();
    let mut flag = |result: &str, name: &str| {
        let rank = ORDER.iter().position(|r| *r == result).expect("ranked result");
        if worst.is_none_or(|w| rank > w) {
            worst = Some(rank);
        }
        if !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    };
    for raw in input.headers("set-cookie") {
        if invalid_same_site(raw) {
            let name = raw.split(['=', ';']).next().unwrap_or_default().trim();
            flag("cookies-samesite-flag-invalid", name);
        }
    }
    // The cookie jar after the whole chain: a later cookie replaces an earlier one.
    let mut jar: Vec<Cookie> = Vec::new();
    let set_cookies = input
        .snapshot
        .chain
        .iter()
        .flat_map(|h| &h.headers)
        .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"));
    for (_, raw) in set_cookies {
        if let Some(cookie) = parse_cookie(raw) {
            jar.retain(|c| c.name != cookie.name);
            jar.push(cookie);
        }
    }
    if jar.is_empty() {
        return match worst {
            Some(rank) => test(NAME, ORDER[rank], names.join(", ")),
            None => test(NAME, "cookies-not-found", ""),
        };
    }
    let mut missing_same_site = false;
    for c in &jar {
        // Upstream skips Heroku's session affinity cookie altogether.
        if c.name == "heroku-session-affinity" {
            continue;
        }
        let lower = c.name.to_ascii_lowercase();
        let session = lower.contains("login") || lower.contains("sess");
        if !c.secure && c.same_site.as_deref() == Some("none") {
            flag("cookies-samesite-flag-invalid", &c.name);
        }
        if !c.secure {
            flag(if hsts { ORDER[0] } else { ORDER[1] }, &c.name);
        }
        if lower.contains("csrf") && c.same_site.is_none() {
            flag("cookies-anticsrf-without-samesite-flag", &c.name);
        }
        if session && !c.secure {
            flag(if hsts { ORDER[2] } else { ORDER[6] }, &c.name);
        }
        if session && !c.http_only {
            flag("cookies-session-without-httponly-flag", &c.name);
        }
        missing_same_site |= c.same_site.is_none();
    }
    let all: Vec<&str> = jar.iter().map(|c| c.name.as_str()).collect();
    match worst {
        Some(rank) => test(NAME, ORDER[rank], names.join(", ")),
        None if missing_same_site => test(NAME, "cookies-secure-with-httponly-sessions", all.join(", ")),
        None => test(
            NAME,
            "cookies-secure-with-httponly-sessions-and-samesite",
            all.join(", "),
        ),
    }
}

// ---- CORS, redirection, referrer ---------------------------------------------

/// Passive only: the Observatory's -50 case needs a request with an `Origin`.
fn cors_test(input: &Inputs) -> TestResult {
    const NAME: &str = "cross-origin-resource-sharing";
    match input.header("access-control-allow-origin") {
        Some(v) if v.trim() == "*" => test(NAME, "cross-origin-resource-sharing-implemented-with-public-access", v),
        Some(v) if !v.trim().is_empty() => test(
            NAME,
            "cross-origin-resource-sharing-implemented-with-restricted-access",
            v,
        ),
        _ => test(NAME, "cross-origin-resource-sharing-not-implemented", ""),
    }
}

fn redirection_test(input: &Inputs) -> TestResult {
    const NAME: &str = "redirection";
    let snapshot = input.snapshot;
    // The plain HTTP route, starting at the http:// address: from the port 80
    // check, or from the chain itself when the input was http://.
    let route: Vec<Url> = match &snapshot.http_check {
        Some(HttpCheck::Response {
            status,
            location,
            route,
        }) => {
            let Some(start) = Url::parse(&snapshot.input)
                .ok()
                .and_then(|mut u| u.set_scheme("http").ok().map(|_| u))
            else {
                return test(NAME, "redirection-not-checked", "");
            };
            let mut urls = vec![start.clone()];
            if route.is_empty() {
                let next = location
                    .as_deref()
                    .filter(|_| (300..400).contains(status))
                    .and_then(|l| start.join(l).ok());
                urls.extend(next);
            } else {
                urls.extend(route.iter().filter_map(|u| Url::parse(u).ok()));
            }
            urls
        }
        Some(HttpCheck::Failed(f)) if f.kind == FailureKind::Connect => {
            return test(NAME, "redirection-not-needed-no-http", f.message.clone());
        }
        Some(HttpCheck::Failed(f)) => return test(NAME, "redirection-not-checked", f.message.clone()),
        None if snapshot.chain.first().is_some_and(|h| h.url.starts_with("http://")) => {
            snapshot.chain.iter().filter_map(|h| Url::parse(&h.url).ok()).collect()
        }
        None => return test(NAME, "redirection-not-checked", "port 80 was not checked"),
    };
    let evidence = route.iter().map(Url::as_str).collect::<Vec<_>>().join(" → ");
    let Some(last) = route.last() else {
        return test(NAME, "redirection-not-checked", "");
    };
    // The certificate where the route ends, when it ends on HTTPS.
    if last.scheme() == "https" {
        let hop = snapshot
            .chain
            .iter()
            .find(|h| h.url == last.as_str())
            .or(snapshot.chain.last());
        if hop.is_some_and(|h| !hop_verified(snapshot, h)) {
            return test(NAME, "redirection-invalid-cert", evidence);
        }
    }
    let result = if route.iter().all(|u| u.host_str().is_some_and(hsts_preloaded)) {
        // Browsers never send the plain HTTP request for preloaded hosts.
        "redirection-all-redirects-preloaded"
    } else if route.len() == 1 {
        "redirection-missing"
    } else if last.scheme() != "https" {
        "redirection-not-to-https"
    } else if route[1].scheme() == "http" {
        "redirection-not-to-https-on-initial-redirection"
    } else if route[0].host_str() != route[1].host_str() {
        "redirection-off-host-from-http"
    } else {
        "redirection-to-https"
    };
    test(NAME, result, evidence)
}

fn referrer_test(input: &Inputs) -> TestResult {
    const NAME: &str = "referrer-policy";
    const GOOD: &[&str] = &[
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ];
    const BAD: &[&str] = &[
        "origin",
        "origin-when-cross-origin",
        "unsafe-url",
        "no-referrer-when-downgrade",
    ];
    let mut values: Vec<&str> = input.headers("referrer-policy");
    values.extend(input.meta_referrer());
    if values.is_empty() {
        return test(NAME, "referrer-policy-not-implemented", "");
    }
    let joined = values.join(", ");
    // The last valid token wins, as in browsers.
    let policy = joined
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .rfind(|p| GOOD.contains(&p.as_str()) || BAD.contains(&p.as_str()))
        .unwrap_or_default();
    let result = if GOOD.contains(&policy.as_str()) {
        "referrer-policy-private"
    } else if BAD.contains(&policy.as_str()) {
        "referrer-policy-unsafe"
    } else {
        "referrer-policy-header-invalid"
    };
    test(NAME, result, joined)
}

// ---- HSTS, SRI, XCTO, XFO and cross-origin policies --------------------------

fn hsts_test(input: &Inputs) -> TestResult {
    const NAME: &str = "strict-transport-security";
    // Preloading wins over whatever the header says, once HTTPS answers.
    if input.https_reached && input.input_host.as_deref().is_some_and(hsts_preloaded) {
        let value = input.header("strict-transport-security").unwrap_or_default();
        return test(NAME, "hsts-preloaded", value);
    }
    if !input.https {
        return test(NAME, "hsts-not-implemented-no-https", "");
    }
    if !input.verified {
        return test(NAME, "hsts-invalid-cert", "");
    }
    let Some(value) = input.header("strict-transport-security") else {
        return test(NAME, "hsts-not-implemented", "");
    };
    // A comma means the header was sent more than once.
    let max_age = (!value.contains(',')).then(|| {
        value.split(';').map(|d| d.trim().to_ascii_lowercase()).find_map(|d| {
            let v = d.strip_prefix("max-age=")?.to_owned();
            Some(js_parse_int(v.trim_matches('"')))
        })
    });
    let result = match max_age.flatten() {
        None => "hsts-header-invalid",
        // Upstream quirk: `parseInt` gives NaN for `max-age=abc` or an empty value, NaN is
        // not null and `NaN < 15552000` is false, so the Observatory scores it as "at
        // least six months". Reproduced on purpose.
        Some(None) => "hsts-implemented-max-age-at-least-six-months",
        Some(Some(age)) if age >= i128::from(SIX_MONTHS) => "hsts-implemented-max-age-at-least-six-months",
        Some(Some(_)) => "hsts-implemented-max-age-less-than-six-months",
    };
    test(NAME, result, value)
}

/// JavaScript `parseInt(s, 10)`: optional sign and the leading digits, ignoring whatever
/// follows. `None` stands for NaN (no digits). Huge values saturate.
fn js_parse_int(s: &str) -> Option<i128> {
    let s = s.trim_start();
    let (negative, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit);
    let mut value: Option<i128> = None;
    for d in digits {
        let v = value
            .unwrap_or(0)
            .saturating_mul(10)
            .saturating_add(i128::from(d - b'0'));
        value = Some(v);
    }
    value.map(|v| if negative { -v } else { v })
}

fn sri_test(input: &Inputs) -> TestResult {
    const NAME: &str = "subresource-integrity";
    // From best to worst, as the Observatory ranks them.
    const ORDER: &[&str] = &[
        "sri-implemented-and-all-scripts-loaded-securely",
        "sri-implemented-and-external-scripts-loaded-securely",
        "sri-implemented-but-external-scripts-not-loaded-securely",
        "sri-not-implemented-but-external-scripts-loaded-securely",
        "sri-not-implemented-and-external-scripts-not-loaded-securely",
    ];
    let mime = input.header("content-type").unwrap_or_default();
    let mime = mime.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    if !mime.is_empty() && mime != "text/html" && mime != "application/xhtml+xml" {
        return test(NAME, "sri-not-implemented-response-not-html", mime);
    }
    let (Some(facts), Some(page)) = (input.facts, input.page.as_ref()) else {
        return test(NAME, "sri-not-implemented-but-no-scripts-loaded", "");
    };
    // Every <script>, inline ones included, counts as a script for the last step.
    if facts.scripts.is_empty() {
        return test(NAME, "sri-not-implemented-but-no-scripts-loaded", "");
    }
    let own = page.host_str().map(registrable).unwrap_or_default();
    let mut result: Option<usize> = None;
    let mut foreign = Vec::new();
    for script in &facts.scripts {
        let Some(src) = script.src_attr.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        let lower = src.to_ascii_lowercase();
        let protocol_relative = src.starts_with("//") && !src.starts_with("///");
        let absolute = lower.starts_with("http://") || lower.starts_with("https://");
        let relative = !protocol_relative && !absolute;
        let same_domain = !absolute
            || Url::parse(src)
                .ok()
                .and_then(|u| u.host_str().map(registrable))
                .is_some_and(|d| d == own);
        let secure_origin = relative || (same_domain && !protocol_relative);
        let secure_scheme = if relative {
            page.scheme() == "https"
        } else {
            lower.starts_with("https://")
        };
        if secure_origin {
            // The bonus also goes to SRI on same-origin scripts.
            if script.integrity && secure_scheme && result.is_none() {
                result = Some(0);
            }
            continue;
        }
        foreign.push(src.to_owned());
        let rank = match (script.integrity, secure_scheme) {
            (true, false) => 2,
            (false, true) => 3,
            (false, false) => 4,
            (true, true) => continue,
        };
        if result.is_none_or(|current| rank > current) {
            result = Some(rank);
        }
    }
    let evidence = foreign.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    match result {
        Some(r) => test(NAME, ORDER[r], evidence),
        None if !foreign.is_empty() => test(NAME, ORDER[1], evidence),
        None => test(
            NAME,
            "sri-not-implemented-but-all-scripts-loaded-from-secure-origin",
            "",
        ),
    }
}

fn xcto_test(input: &Inputs) -> TestResult {
    const NAME: &str = "x-content-type-options";
    match input.header("x-content-type-options") {
        Some(v) if v.trim().eq_ignore_ascii_case("nosniff") => test(NAME, "x-content-type-options-nosniff", v),
        Some(v) => test(NAME, "x-content-type-options-header-invalid", v),
        None => test(NAME, "x-content-type-options-not-implemented", ""),
    }
}

fn xfo_test(input: &Inputs, csp: &CspOutcome) -> TestResult {
    const NAME: &str = "x-frame-options";
    if csp.frame_ancestors {
        return test(NAME, "x-frame-options-implemented-via-csp", "frame-ancestors");
    }
    match input.header("x-frame-options") {
        Some(v) => {
            let lower = v.trim().to_ascii_lowercase();
            let result = if lower == "deny" || lower == "sameorigin" {
                "x-frame-options-sameorigin-or-deny"
            } else if lower.starts_with("allow-from") {
                "x-frame-options-allow-from-origin"
            } else {
                "x-frame-options-header-invalid"
            };
            test(NAME, result, v)
        }
        None => test(NAME, "x-frame-options-not-implemented", ""),
    }
}

fn corp_test(input: &Inputs) -> TestResult {
    const NAME: &str = "cross-origin-resource-policy";
    let Some(v) = input.header("cross-origin-resource-policy").filter(|v| !v.is_empty()) else {
        return test(NAME, "corp-not-implemented", "");
    };
    let result = match v.trim().to_ascii_lowercase().as_str() {
        "same-site" => "corp-implemented-with-same-site",
        "same-origin" => "corp-implemented-with-same-origin",
        "cross-origin" => "corp-implemented-with-cross-origin",
        _ => "corp-header-invalid",
    };
    test(NAME, result, v)
}

struct TokenPolicy {
    name: &'static str,
    missing: &'static str,
    invalid: &'static str,
    values: &'static [(&'static str, &'static str)],
}

const COEP: TokenPolicy = TokenPolicy {
    name: "cross-origin-embedder-policy",
    missing: "coep-not-implemented",
    invalid: "coep-header-invalid",
    values: &[
        ("require-corp", "coep-implemented-with-require-corp"),
        ("credentialless", "coep-implemented-with-credentialless"),
        ("unsafe-none", "coep-implemented-with-unsafe-none"),
    ],
};

const COOP: TokenPolicy = TokenPolicy {
    name: "cross-origin-opener-policy",
    missing: "coop-not-implemented",
    invalid: "coop-header-invalid",
    values: &[
        ("same-origin", "coop-implemented-with-same-origin"),
        (
            "same-origin-allow-popups",
            "coop-implemented-with-same-origin-allow-popups",
        ),
        ("noopener-allow-popups", "coop-implemented-with-noopener-allow-popups"),
        ("unsafe-none", "coop-implemented-with-unsafe-none"),
    ],
};

/// COEP and COOP are structured-field tokens (RFC 8941): case-sensitive, with
/// optional parameters; a value that does not parse is invalid, and so is a
/// repeated header.
fn token_policy_test(input: &Inputs, policy: TokenPolicy) -> TestResult {
    let values = input.headers(policy.name);
    let [value] = values.as_slice() else {
        return match values.len() {
            0 => test(policy.name, policy.missing, ""),
            _ => test(policy.name, policy.invalid, values.join(", ")),
        };
    };
    let result = sf_token(value)
        .and_then(|t| policy.values.iter().find(|(v, _)| *v == t))
        .map_or(policy.invalid, |(_, r)| r);
    test(policy.name, result, *value)
}

const TCHAR_EXTRA: &str = "!#$%&'*+-.^_`|~:/";

/// The bare item of an RFC 8941 item when it is a token; `None` otherwise.
fn sf_token(value: &str) -> Option<&str> {
    let value = value.trim_matches(' ');
    if !value.starts_with(|c: char| c.is_ascii_alphabetic() || c == '*') {
        return None;
    }
    let end = value
        .find(|c: char| !(c.is_ascii_alphanumeric() || TCHAR_EXTRA.contains(c)))
        .unwrap_or(value.len());
    let (token, mut rest) = value.split_at(end);
    while !rest.is_empty() {
        rest = rest.strip_prefix(';')?.trim_start_matches(' ');
        if !rest.starts_with(|c: char| c.is_ascii_lowercase() || c == '*') {
            return None;
        }
        let key_end = rest
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || "_-.*".contains(c)))
            .unwrap_or(rest.len());
        rest = &rest[key_end..];
        if let Some(after) = rest.strip_prefix('=') {
            rest = sf_bare_item(after)?;
        }
    }
    Some(token)
}

/// Skips one bare item, returning what follows it.
fn sf_bare_item(text: &str) -> Option<&str> {
    let first = text.chars().next()?;
    let end = match first {
        '"' => {
            let mut escaped = false;
            let close = text[1..].char_indices().find(|&(_, c)| {
                let done = c == '"' && !escaped;
                escaped = c == '\\' && !escaped;
                done
            })?;
            close.0 + 2
        }
        '?' if text[1..].starts_with(['0', '1']) => 2,
        ':' => text[1..].find(':')? + 2,
        c if c.is_ascii_digit() || c == '-' => text[1..]
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .map_or(text.len(), |i| i + 1),
        c if c.is_ascii_alphabetic() || c == '*' => text
            .find(|c: char| !(c.is_ascii_alphanumeric() || TCHAR_EXTRA.contains(c)))
            .unwrap_or(text.len()),
        _ => return None,
    };
    Some(&text[end..])
}

// ---- Beyond the methodology ----------------------------------------------------

/// Scripts, stylesheets, frames and images an HTTPS page requests over HTTP.
fn mixed_content(facts: &PageFacts, https: bool) -> Vec<String> {
    if !https {
        return Vec::new();
    }
    let mut urls: Vec<String> = active_resources(facts)
        .chain(facts.images.iter().filter_map(|i| i.src.as_ref()))
        .filter(|u| u.starts_with("http://"))
        .cloned()
        .collect();
    urls.sort();
    urls.dedup();
    urls
}

fn active_resources(facts: &PageFacts) -> impl Iterator<Item = &String> {
    facts
        .scripts
        .iter()
        .filter_map(|s| s.src.as_ref())
        .chain(facts.links_with_rel("stylesheet").filter_map(|l| l.href.as_ref()))
        .chain(facts.iframes.iter())
}

fn extras(input: &Inputs, mixed: &[String], findings: &mut Vec<Finding>) {
    let snapshot = input.snapshot;
    if let Some(f) = &snapshot.https_fallback {
        // One finding for the missing HTTPS, not three.
        findings.retain(|f| !matches!(f.id, "sec.redirect.missing" | "sec.redirect.not_https"));
        findings.push(finding(
            "sec.https.unavailable",
            &[("reason", f.message.clone())],
            f.message.clone(),
        ));
    }
    // Leaving HTTPS for HTTP on the way exposes the visitor.
    let downgrade = snapshot
        .chain
        .windows(2)
        .find(|w| w[0].url.starts_with("https://") && w[1].url.starts_with("http://"));
    if let Some(pair) = downgrade {
        findings.push(finding(
            "sec.https.downgrade",
            &[("from", pair[0].url.clone()), ("to", pair[1].url.clone())],
            format!("{} → {}", pair[0].url, pair[1].url),
        ));
    }
    let shown = |urls: &[&String]| urls.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
    if let Some(facts) = input.facts.filter(|_| input.https) {
        let active: Vec<&String> = active_resources(facts).filter(|u| u.starts_with("http://")).collect();
        if !active.is_empty() {
            let count = active.len().to_string();
            findings.push(finding("sec.mixed_content.active", &[("count", count)], shown(&active)));
        } else if !mixed.is_empty() {
            let count = mixed.len().to_string();
            findings.push(finding(
                "sec.mixed_content.passive",
                &[("count", count)],
                shown(&mixed.iter().collect::<Vec<_>>()),
            ));
        }
        let forms: Vec<&String> = facts
            .forms
            .iter()
            .filter_map(|f| f.action.as_ref())
            .filter(|a| a.starts_with("http://"))
            .collect();
        if let Some(first) = forms.first() {
            findings.push(finding(
                "sec.form.insecure",
                &[("action", (*first).clone())],
                shown(&forms),
            ));
        }
        if input.header("permissions-policy").is_none() {
            findings.push(finding("sec.permissions_policy.missing", &[], String::new()));
        }
    }
    for name in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"] {
        if let Some(value) = input.header(name).filter(|v| reveals_version(v)) {
            let evidence = format!("{name}: {value}");
            findings.push(finding(
                "sec.version_leak",
                &[("header", name.to_owned()), ("value", value)],
                evidence,
            ));
            break;
        }
    }
}

/// `nginx/1.25.3`, `PHP/8.2.1`, `4.0.30319`: a product version, not just a name.
fn reveals_version(value: &str) -> bool {
    value
        .split(|c: char| c.is_whitespace() || matches!(c, '/' | '(' | ')' | ','))
        .any(|part| {
            let mut pieces = part.split('.');
            let numeric = |p: Option<&str>| p.is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
            numeric(pieces.next()) && numeric(pieces.next())
        })
}

fn security_txt(file: &AuxFile, snapshot: &Snapshot) -> SecurityTxt {
    let body = String::from_utf8_lossy(&file.body);
    let field = |name: &str| -> Vec<String> {
        body.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_owned())
            .collect()
    };
    let contact = field("contact");
    let expires = field("expires").into_iter().next();
    let state = match file.status {
        None => "failed",
        Some(200..=299) if !contact.is_empty() && !crate::extract::sniff_html(&file.body) => "found",
        Some(200..=299) => "not_security_txt",
        Some(_) => "absent",
    };
    let now = snapshot
        .collected_at
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let expired = state == "found" && expires.as_deref().and_then(rfc3339_seconds).is_some_and(|t| t < now);
    SecurityTxt {
        url: file.url.clone(),
        state,
        contact: if state == "found" { contact } else { Vec::new() },
        expires,
        expired,
    }
}

/// An RFC 3339 timestamp (`2026-12-31T23:59:59Z`, `...+02:00`) as Unix seconds.
fn rfc3339_seconds(text: &str) -> Option<i64> {
    let text = text.trim();
    let num = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !matches!(text.as_bytes().get(10), Some(b'T' | b't' | b' ')) || !(1..=12).contains(&mo) || !(1..=31).contains(&d)
    {
        return None;
    }
    let zone = text[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let offset = match zone {
        "Z" | "z" => 0,
        _ => {
            let sign = match zone.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let oh = zone.get(1..3)?.parse::<i64>().ok()?;
            let om = zone.get(4..6)?.parse::<i64>().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    // Days from civil, by Howard Hinnant.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s - offset)
}

#[cfg(test)]
mod tests;
