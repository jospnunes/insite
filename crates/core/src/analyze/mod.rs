//! Analysis: pure functions from `Snapshot` to `Report`. No network, no clock.

pub mod browser;
pub mod content;
pub mod dns;
pub mod infra;
pub mod network;
pub mod security;
pub mod seo;
pub mod spf;
pub mod stack;
pub mod tls;
pub mod weight;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

use crate::collect::target::display_host;
use crate::report::{Module, ModuleName, Modules, Outcome, Report, SCHEMA_VERSION, Selection, Status, TargetInfo};
use crate::snapshot::Snapshot;

pub fn analyze(snapshot: &Snapshot) -> Report {
    analyze_selected(snapshot, Selection::all())
}

/// Analyzes the modules in `selection`; the others are reported as skipped.
/// Each analyzer runs isolated: a panic becomes a `failed` module, not a crash.
pub fn analyze_selected(snapshot: &Snapshot, selection: Selection) -> Report {
    let content = guarded("content", || content::content(snapshot))
        .unwrap_or_else(|e| Err(format!("the page could not be analyzed: {e}")));
    let network = run(selection, ModuleName::Network, || network::analyze(snapshot));
    let final_url = network.data.as_ref().and_then(|n| n.final_url.clone()).or_else(|| {
        snapshot
            .chain
            .last()
            .filter(|h| !h.is_redirect() && snapshot.page.is_some())
            .map(|h| h.url.clone())
    });
    let stack = run(selection, ModuleName::Stack, || stack::analyze(snapshot, &content));
    let mut weight = run(selection, ModuleName::Weight, || weight::analyze(snapshot, &content));
    if let (Some(w), Some(s)) = (weight.data.as_mut(), stack.data.as_ref()) {
        name_third_parties(w, s);
    }
    let modules = Modules {
        tls: run(selection, ModuleName::Tls, || tls::analyze(snapshot)),
        dns: run(selection, ModuleName::Dns, || dns::analyze(snapshot)),
        infra: run(selection, ModuleName::Infra, || infra::analyze(snapshot)),
        security: run(selection, ModuleName::Security, || {
            security::analyze(snapshot, &content)
        }),
        stack,
        browser: run(selection, ModuleName::Browser, || browser::analyze(snapshot)),
        seo: run(selection, ModuleName::Seo, || seo::analyze(snapshot, &content)),
        weight,
        network,
    };
    let outcome = outcome(
        snapshot,
        &[
            ("network", modules.network.status),
            ("tls", modules.tls.status),
            ("dns", modules.dns.status),
            ("infra", modules.infra.status),
            ("security", modules.security.status),
            ("stack", modules.stack.status),
            ("seo", modules.seo.status),
            ("weight", modules.weight.status),
            ("browser", modules.browser.status),
        ],
    );

    Report {
        schema_version: SCHEMA_VERSION,
        collector_version: snapshot.collector_version.clone(),
        analyzer_version: env!("CARGO_PKG_VERSION"),
        target: TargetInfo {
            input: snapshot.input.clone(),
            display_host: Url::parse(&snapshot.input)
                .map(|u| display_host(&u))
                .unwrap_or_default(),
            final_url,
        },
        started_at: rfc3339(snapshot.collected_at),
        duration_ms: network::ms(snapshot.duration),
        outcome,
        phase: None,
        sources: crate::data::sources(
            selection
                .contains(ModuleName::Stack)
                .then(|| crate::detect::engine().provenance()),
        ),
        modules,
    }
}

/// Names third-party domains after the technologies detected from them: a
/// script from `www.googletagmanager.com` is Google Tag Manager.
fn name_third_parties(weight: &mut weight::Weight, stack: &stack::Stack) {
    for party in &mut weight.third_parties {
        for tech in &stack.technologies {
            let from_domain = tech.evidence.iter().any(|e| {
                matches!(e.field, "scriptSrc" | "url" | "html" | "dom") && mentions_domain(&e.value, &party.domain)
            });
            if from_domain && !party.technologies.contains(&tech.name) {
                party.technologies.push(tech.name.clone());
            }
        }
    }
}

/// Whether `text` (often part of a URL) names `domain` on label boundaries.
fn mentions_domain(text: &str, domain: &str) -> bool {
    let label_char = |c: char| c.is_ascii_alphanumeric() || c == '-';
    text.match_indices(domain).any(|(at, _)| {
        !text[..at].chars().next_back().is_some_and(label_char)
            && !text[at + domain.len()..].chars().next().is_some_and(label_char)
    })
}

fn run<T>(selection: Selection, name: ModuleName, analyzer: impl FnOnce() -> Module<T>) -> Module<T> {
    if !selection.contains(name) {
        return Module::skipped("not selected");
    }
    guarded(name.as_str(), analyzer).unwrap_or_else(|e| Module {
        status: Status::Failed,
        reason: Some(format!(
            "internal error in the {} analyzer ({e}); please report it with the snapshot from --save",
            name.as_str()
        )),
        data: None,
        findings: Vec::new(),
    })
}

/// Runs `f`, turning a panic into its message.
fn guarded<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|panic| {
        let message = panic
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_owned());
        format!("{what}: {message}")
    })
}

fn outcome(snapshot: &Snapshot, modules: &[(&str, Status)]) -> Outcome {
    if snapshot.chain.is_empty() {
        let reason = snapshot
            .failure
            .as_ref()
            .map_or_else(|| "no HTTP response".to_owned(), |f| f.message.clone());
        return Outcome::Unreachable { reason };
    }
    let mut reasons = Vec::new();
    for (name, status) in modules {
        match status {
            Status::Timeout => reasons.push(format!("{name}: deadline reached")),
            Status::Failed => reasons.push(format!("{name}: failed")),
            _ => {}
        }
    }
    if let Some(failure) = &snapshot.failure {
        reasons.push(failure.message.clone());
    } else if let Some(last) = snapshot.chain.last()
        && last.status >= 400
    {
        reasons.push(format!(
            "the page answered {}, so it does not represent the site",
            last.status
        ));
    }
    if let Some(c) = infra::challenge(snapshot) {
        reasons.push(format!("{} answered with a bot challenge, not the page", c.name));
    }
    if snapshot.page.as_ref().is_some_and(|p| p.truncated) {
        reasons.push("the page body was cut".to_owned());
    }
    if snapshot.interrupted {
        reasons.push("interrupted before collection finished".to_owned());
    } else if snapshot.deadline_hit && !reasons.iter().any(|r| r.contains("deadline")) {
        reasons.push("deadline reached before collection finished".to_owned());
    }
    if reasons.is_empty() {
        Outcome::Complete
    } else {
        Outcome::Partial { reasons }
    }
}

/// UTC, millisecond precision. Days-to-civil conversion by Howard Hinnant.
pub fn rfc3339(t: SystemTime) -> String {
    let since = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn domains_are_matched_on_label_boundaries() {
        assert!(mentions_domain(
            "//www.googletagmanager.com/gtm.js",
            "googletagmanager.com"
        ));
        assert!(mentions_domain("googletagmanager.com", "googletagmanager.com"));
        assert!(!mentions_domain("notgoogletagmanager.com/x", "googletagmanager.com"));
        assert!(!mentions_domain(
            "googletagmanager.com-evil.net",
            "googletagmanager.com"
        ));
    }

    #[test]
    fn panics_become_failed_modules() {
        let module: Module<()> = run(Selection::all(), ModuleName::Tls, || panic!("boom"));
        assert_eq!(module.status, Status::Failed);
        assert!(module.reason.unwrap().contains("boom"));
        let skipped: Module<()> = run(Selection::parse("dns").unwrap(), ModuleName::Tls, || unreachable!());
        assert_eq!(skipped.status, Status::Skipped);
    }

    #[test]
    fn formats_rfc3339() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_793_212_345_678);
        assert_eq!(rfc3339(t), "2026-10-28T18:32:25.678Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00.000Z");
    }
}
