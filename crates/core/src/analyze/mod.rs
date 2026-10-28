//! Analysis: pure functions from `Snapshot` to `Report`. No network, no clock.

pub mod content;
pub mod dns;
pub mod infra;
pub mod network;
pub mod seo;
pub mod spf;
pub mod tls;
pub mod weight;

use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

use crate::collect::target::display_host;
use crate::report::{Modules, Outcome, Report, SCHEMA_VERSION, Status, TargetInfo};
use crate::snapshot::Snapshot;

pub fn analyze(snapshot: &Snapshot) -> Report {
    let network = network::analyze(snapshot);
    let final_url = network.data.as_ref().and_then(|n| n.final_url.clone());
    let tls = tls::analyze(snapshot);
    let dns = dns::analyze(snapshot);
    let infra = infra::analyze(snapshot);
    let content = content::content(snapshot);
    let seo = seo::analyze(snapshot, &content);
    let weight = weight::analyze(snapshot, &content);
    let outcome = outcome(
        snapshot,
        &[
            ("network", network.status),
            ("tls", tls.status),
            ("dns", dns.status),
            ("infra", infra.status),
            ("seo", seo.status),
            ("weight", weight.status),
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
        modules: Modules {
            network,
            tls,
            dns,
            infra,
            seo,
            weight,
        },
    }
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
    if snapshot.deadline_hit && !reasons.iter().any(|r| r.contains("deadline")) {
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
    fn formats_rfc3339() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_793_212_345_678);
        assert_eq!(rfc3339(t), "2026-10-28T18:32:25.678Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00.000Z");
    }
}
