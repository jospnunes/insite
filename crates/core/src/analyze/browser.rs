//! What the browser saw: lab Core Web Vitals, every resource, console errors.
//! Every metric carries the profile it was measured with: an LCP measured
//! without throttling is not the PageSpeed one.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::collect::records::registrable;
use crate::findings::finding;
use crate::report::{Module, Status};
use crate::snapshot::{BrowserData, Snapshot};

#[derive(Debug, Clone, Serialize)]
pub struct Browser {
    pub product: String,
    /// `mobile` or `desktop`, and `throttled` (Lighthouse's mobile Slow 4G and
    /// 4x CPU, devtools method) or `unthrottled` (this connection and machine).
    pub profile: String,
    pub url: String,
    pub metrics: Vec<Metric>,
    pub requests: usize,
    pub transferred_bytes: u64,
    pub by_type: Vec<TypeTotal>,
    pub heaviest: Vec<Heavy>,
    pub third_party_bytes: u64,
    pub third_party_share: f64,
    pub failed: Vec<String>,
    pub console_errors: Vec<String>,
    pub load_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Metric {
    /// `lcp`, `cls`, `tbt` or `fcp`.
    pub name: &'static str,
    pub value: f64,
    /// `good`, `needs_improvement` or `poor`, by the Core Web Vitals and
    /// Lighthouse thresholds.
    pub rating: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeTotal {
    pub kind: String,
    pub count: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Heavy {
    pub url: String,
    pub kind: String,
    pub bytes: u64,
}

/// Thresholds: good up to the first, poor above the second.
const LCP: (f64, f64) = (2500.0, 4000.0);
const CLS: (f64, f64) = (0.1, 0.25);
const TBT: (f64, f64) = (200.0, 600.0);
const FCP: (f64, f64) = (1800.0, 3000.0);

fn rating(value: f64, (good, poor): (f64, f64)) -> &'static str {
    if value <= good {
        "good"
    } else if value <= poor {
        "needs_improvement"
    } else {
        "poor"
    }
}

pub fn analyze(snapshot: &Snapshot) -> Module<Browser> {
    let Some(b) = &snapshot.browser else {
        return Module::skipped("run with --browser to load the page in a browser");
    };
    if b.metrics.is_none() && b.resources.is_empty() {
        return Module {
            status: Status::Failed,
            reason: Some(b.error.clone().unwrap_or_else(|| "the browser returned nothing".into())),
            data: None,
            findings: Vec::new(),
        };
    }
    let profile = format!(
        "{}, {}",
        if b.mobile { "mobile" } else { "desktop" },
        if b.throttled { "throttled" } else { "unthrottled" }
    );
    let data = report(b, profile.clone());
    let mut findings = Vec::new();
    for m in data.metrics.iter().filter(|m| m.rating == "poor" && m.name != "fcp") {
        let (id, value) = match m.name {
            "lcp" => ("perf.lcp.poor", format!("{:.1} s", m.value / 1000.0)),
            "cls" => ("perf.cls.poor", format!("{:.2}", m.value)),
            _ => ("perf.tbt.poor", format!("{:.0} ms", m.value)),
        };
        let evidence = format!("{} = {value} ({profile})", m.name.to_uppercase());
        findings.push(finding(id, &[("value", value), ("profile", profile.clone())], evidence));
    }
    if !data.console_errors.is_empty() {
        let shown = data
            .console_errors
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(" | ");
        findings.push(finding(
            "browser.console_errors",
            &[("count", data.console_errors.len().to_string())],
            shown,
        ));
    }
    if !data.failed.is_empty() {
        let shown = data.failed.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
        findings.push(finding(
            "browser.requests_failed",
            &[("count", data.failed.len().to_string())],
            shown,
        ));
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(b.id)));

    let mut reasons = Vec::new();
    if let Some(e) = &b.error {
        reasons.push(e.clone());
    }
    if !b.quiet {
        reasons.push("the page never went quiet, so it was read before it finished".into());
    }
    if b.html_truncated {
        reasons.push("the rendered HTML was cut at 5 MB".into());
    }
    Module {
        status: if reasons.is_empty() {
            Status::Ok
        } else {
            Status::Partial
        },
        reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
        data: Some(data),
        findings,
    }
}

fn report(b: &BrowserData, profile: String) -> Browser {
    let mut metrics = Vec::new();
    if let Some(m) = &b.metrics {
        if let Some(lcp) = m.lcp_ms {
            metrics.push(Metric {
                name: "lcp",
                value: lcp,
                rating: rating(lcp, LCP),
            });
        }
        metrics.push(Metric {
            name: "cls",
            value: m.cls,
            rating: rating(m.cls, CLS),
        });
        // TBT needs a first paint to start from.
        if m.fcp_ms.is_some() {
            metrics.push(Metric {
                name: "tbt",
                value: m.tbt_ms,
                rating: rating(m.tbt_ms, TBT),
            });
        }
        if let Some(fcp) = m.fcp_ms {
            metrics.push(Metric {
                name: "fcp",
                value: fcp,
                rating: rating(fcp, FCP),
            });
        }
    }

    let own = url::Url::parse(&b.url)
        .ok()
        .and_then(|u| u.host_str().map(registrable))
        .unwrap_or_default();
    let mut by_type: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    let mut third_party_bytes = 0;
    let mut failed = Vec::new();
    for r in &b.resources {
        let entry = by_type.entry(r.kind.clone()).or_default();
        entry.0 += 1;
        entry.1 += r.transferred;
        let host = url::Url::parse(&r.url).ok().and_then(|u| u.host_str().map(registrable));
        if host.is_some_and(|h| h != own) {
            third_party_bytes += r.transferred;
        }
        match (&r.failed, r.status) {
            // A navigation or script cancelling a request is not an error.
            (Some(e), _) if e.contains("ERR_ABORTED") => {}
            (Some(e), _) => failed.push(format!("{} ({e})", r.url)),
            (None, Some(status)) if status >= 400 => failed.push(format!("{} ({status})", r.url)),
            _ => {}
        }
    }
    let transferred_bytes: u64 = b.resources.iter().map(|r| r.transferred).sum();
    let mut by_type: Vec<TypeTotal> = by_type
        .into_iter()
        .map(|(kind, (count, bytes))| TypeTotal { kind, count, bytes })
        .collect();
    by_type.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.kind.cmp(&b.kind)));
    let mut heaviest: Vec<Heavy> = b
        .resources
        .iter()
        .filter(|r| r.transferred > 0)
        .map(|r| Heavy {
            url: r.url.clone(),
            kind: r.kind.clone(),
            bytes: r.transferred,
        })
        .collect();
    heaviest.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.url.cmp(&b.url)));
    heaviest.truncate(10);

    Browser {
        product: b.product.clone(),
        profile,
        url: b.url.clone(),
        metrics,
        requests: b.resources.len(),
        transferred_bytes,
        by_type,
        heaviest,
        third_party_bytes,
        third_party_share: if transferred_bytes > 0 {
            third_party_bytes as f64 / transferred_bytes as f64
        } else {
            0.0
        },
        failed,
        console_errors: b.console.clone(),
        load_ms: b.load_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::infra::tests::snapshot_with;
    use crate::snapshot::{BrowserMetrics, BrowserResource};

    fn resource(url: &str, kind: &str, bytes: u64, status: u16) -> BrowserResource {
        BrowserResource {
            url: url.into(),
            kind: kind.into(),
            status: Some(status),
            transferred: bytes,
            ..Default::default()
        }
    }

    fn with_browser(data: BrowserData) -> Snapshot {
        let mut s = snapshot_with(200, &[], "");
        s.browser = Some(data);
        s
    }

    #[test]
    fn ratings_follow_the_thresholds() {
        assert_eq!(rating(2500.0, LCP), "good");
        assert_eq!(rating(2501.0, LCP), "needs_improvement");
        assert_eq!(rating(4001.0, LCP), "poor");
        assert_eq!(rating(0.1, CLS), "good");
        assert_eq!(rating(0.3, CLS), "poor");
    }

    #[test]
    fn totals_heaviest_and_third_parties() {
        let module = analyze(&with_browser(BrowserData {
            url: "https://www.example.com/".into(),
            quiet: true,
            metrics: Some(BrowserMetrics {
                fcp_ms: Some(900.0),
                lcp_ms: Some(5200.0),
                cls: 0.02,
                tbt_ms: 80.0,
                ..Default::default()
            }),
            resources: vec![
                resource("https://www.example.com/", "Document", 30_000, 200),
                resource("https://static.example.com/app.js", "Script", 200_000, 200),
                resource("https://cdn.other.net/lib.js", "Script", 100_000, 200),
                resource("https://www.example.com/missing.png", "Image", 500, 404),
                BrowserResource {
                    url: "https://ads.net/x".into(),
                    kind: "Script".into(),
                    failed: Some("net::ERR_ABORTED".into()),
                    ..Default::default()
                },
            ],
            console: vec!["Uncaught TypeError: x is undefined".into()],
            ..Default::default()
        }));
        assert_eq!(module.status, Status::Ok);
        let data = module.data.unwrap();
        assert_eq!(data.profile, "desktop, unthrottled");
        assert_eq!(data.requests, 5);
        assert_eq!(data.transferred_bytes, 330_500);
        assert_eq!(data.third_party_bytes, 100_000);
        assert_eq!(data.by_type[0].kind, "Script");
        assert_eq!((data.by_type[0].count, data.by_type[0].bytes), (3, 300_000));
        assert_eq!(data.heaviest[0].url, "https://static.example.com/app.js");
        // Cancelled requests are not failures; 404s are.
        assert_eq!(data.failed, ["https://www.example.com/missing.png (404)"]);
        let ids: Vec<&str> = module.findings.iter().map(|f| f.id).collect();
        assert_eq!(
            ids,
            ["perf.lcp.poor", "browser.console_errors", "browser.requests_failed"]
        );
    }

    #[test]
    fn without_the_browser_the_module_is_skipped() {
        let module = analyze(&snapshot_with(200, &[], ""));
        assert_eq!(module.status, Status::Skipped);
        let failed = analyze(&with_browser(BrowserData {
            error: Some("no Chrome".into()),
            ..Default::default()
        }));
        assert_eq!(failed.status, Status::Failed);
        assert_eq!(failed.reason.as_deref(), Some("no Chrome"));
    }
}
