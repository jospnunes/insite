//! Terminal rendering of a `Report`: a first screen that answers the essentials
//! without scrolling, and with `-v` every section in full, with evidence.

use std::fmt::Write;

use insite_core::analyze::dns::DomainReport;
use insite_core::analyze::network::{HttpsEnforcement, Network};
use insite_core::report::{Finding, Module, Outcome, Report, Severity, Status, format_bytes};

use crate::style::{Style, neutralize, wrap_items};

/// Width of the section labels on the first screen.
const LABEL: usize = 10;

/// The report for a terminal. Everything a page, a DNS record or a certificate
/// supplied is neutralized here, at the one place all of it passes through, so
/// no title, evidence or console message can write an escape sequence.
pub fn terminal(report: &Report, color: bool, verbose: bool, width: usize) -> String {
    neutralize(&terminal_text(report, color, verbose, width), color)
}

fn terminal_text(report: &Report, color: bool, verbose: bool, width: usize) -> String {
    let s = Style::new(color);
    let mut out = String::new();
    let host = s.bold(&report.target.display_host);
    let m = &report.modules;

    if let Outcome::Unreachable { reason } = &report.outcome {
        let _ = writeln!(out, "{host}  {}  {reason}", s.red("unreachable"));
        return out;
    }
    if let Some(net) = &m.network.data {
        headline(&mut out, &s, &host, net, report);
    } else {
        let _ = writeln!(out, "{host}");
    }
    out.push('\n');

    for (label, text) in summary_lines(report, &s, width) {
        let _ = writeln!(out, "{}{}", s.bold(&format!("{label:<LABEL$}")), text);
    }

    if verbose {
        details(&mut out, report, &s, width);
    }

    let mut findings: Vec<&Finding> = [
        &m.network.findings,
        &m.tls.findings,
        &m.dns.findings,
        &m.infra.findings,
        &m.security.findings,
        &m.stack.findings,
        &m.seo.findings,
        &m.weight.findings,
    ]
    .into_iter()
    .flatten()
    .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let hidden = if verbose {
        0
    } else {
        findings.iter().filter(|f| f.severity == Severity::Info).count()
    };
    if !findings.is_empty() {
        out.push('\n');
        for f in findings.iter().filter(|f| verbose || f.severity > Severity::Info) {
            let label = severity_column(f.severity);
            let label = match f.severity {
                Severity::High | Severity::Critical => s.red(&label),
                Severity::Medium => s.yellow(&label),
                _ => s.dim(&label),
            };
            let _ = writeln!(out, "  {label}{}  {}", f.title, s.dim(f.id));
            if verbose {
                let evidence = clip(&f.evidence, 300);
                for (prefix, text) in [
                    ("", f.detail.as_str()),
                    ("fix: ", f.fix.as_str()),
                    ("evidence: ", evidence.as_str()),
                ] {
                    if !text.is_empty() {
                        let _ = writeln!(out, "{}", indent(&format!("{prefix}{text}"), 10, width));
                    }
                }
            }
        }
        if hidden > 0 {
            let _ = writeln!(out, "  {}", s.dim(&format!("+{hidden} info (-v shows them)")));
        }
    }

    let mut notes = Vec::new();
    if let Outcome::Partial { reasons } = &report.outcome {
        notes.extend(reasons.iter().map(|r| s.yellow(&format!("partial: {r}"))));
    }
    if !notes.is_empty() {
        out.push('\n');
        for n in notes {
            let _ = writeln!(out, "{n}");
        }
    }
    out
}

/// The first screen's sections: label and one line of text each.
pub fn summary_lines(report: &Report, s: &Style, width: usize) -> Vec<(&'static str, String)> {
    let m = &report.modules;
    let mut lines = Vec::new();
    if let Some(text) = summary(&m.stack, s, |stack| {
        let names: Vec<String> = stack
            .technologies
            .iter()
            .map(|t| {
                let mut name = t.name.clone();
                if let Some(v) = &t.version {
                    name = format!("{name} {v}");
                }
                if t.confidence < 100 {
                    s.dim(&format!("{name}?"))
                } else {
                    name
                }
            })
            .collect();
        if names.is_empty() {
            s.dim("nothing recognized")
        } else {
            wrap_items(&names, " · ", width, LABEL)
        }
    }) {
        lines.push(("stack", text));
    }
    if let Some(text) = summary(&m.security, s, |sec| match (sec.grade, sec.score) {
        (Some(grade), Some(score)) => {
            let painted = match grade.as_bytes()[0] {
                b'A' => s.green(&format!("{grade:<2}")),
                b'B' | b'C' => s.yellow(&format!("{grade:<2}")),
                _ => s.red(&format!("{grade:<2}")),
            };
            let mut parts = vec![format!("{painted}  score {score}")];
            parts.extend(issues(&m.security.findings));
            parts.join(" · ")
        }
        _ => s.dim(&format!(
            "no grade: {}",
            m.security.reason.as_deref().unwrap_or("not representative")
        )),
    }) {
        lines.push(("security", text));
    }
    if let Some(text) = summary(&m.tls, s, |tls| {
        let mut parts = Vec::new();
        if let Some(c) = &tls.certificate {
            parts.push(c.issuer_organization.clone().unwrap_or_else(|| c.issuer.clone()));
        }
        parts.push(tls.version.replace("TLSv", "TLS "));
        if let Some(c) = &tls.certificate {
            parts.push(match c.days_remaining {
                d if d < 0 => s.red(&format!("expired {} days ago", -d)),
                d if d < 14 => s.yellow(&format!("expires in {d} days")),
                d => format!("expires in {d} days"),
            });
        }
        if !tls.trusted {
            parts.push(s.red("not trusted"));
        }
        parts.join(" · ")
    }) {
        lines.push(("tls", text));
    }
    if let Some(dns) = m.dns.data.as_ref().filter(|_| m.dns.status != Status::Skipped) {
        if let Some(input) = dns.domains.first() {
            lines.push(("email", email(input, s)));
            lines.push(("dns", dns_line(input, s)));
        }
    } else if let Some(text) = summary(&m.dns, s, |_| String::new()) {
        lines.push(("dns", text));
    }
    if let Some(infra) = m
        .infra
        .data
        .as_ref()
        .filter(|i| i.challenge.is_some() || i.hosting.is_some() || !i.cdn.is_empty())
    {
        let mut parts = Vec::new();
        if let Some(h) = &infra.hosting {
            parts.push(format!("hosted on {h}"));
        }
        if !infra.cdn.is_empty() {
            parts.push(format!(
                "CDN {}",
                infra.cdn.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        if let Some(c) = &infra.challenge {
            parts.push(s.yellow(&format!("{} bot challenge", c.name)));
        }
        lines.push(("infra", parts.join(" · ")));
    }
    if let Some(text) = summary(&m.seo, s, |seo| {
        let mut parts = vec![if seo.indexable {
            "indexable".to_owned()
        } else {
            s.red("not indexable")
        }];
        parts.extend(issues(&m.seo.findings));
        parts.join(" · ")
    }) {
        lines.push(("seo", text));
    }
    if let Some(text) = summary(&m.weight, s, |w| {
        let mut size = bytes(w.html_transferred_bytes);
        if w.html_bytes != w.html_transferred_bytes {
            size = format!("{size} ({} uncompressed)", bytes(w.html_bytes));
        }
        let mut parts = vec![format!("HTML {size}"), plural(w.scripts_external, "script")];
        if !w.render_blocking_scripts.is_empty() {
            parts.push(format!("{} render-blocking", w.render_blocking_scripts.len()));
        }
        parts.push(plural(w.third_parties.len(), "third party").replace("partys", "parties"));
        parts.join(" · ")
    }) {
        lines.push(("weight", text));
    }
    let still_loading = m.browser.reason.as_deref() == Some(STILL_LOADING);
    if (m.browser.status != Status::Skipped || still_loading)
        && let Some(text) = summary(&m.browser, s, |b| browser_line(b, s))
    {
        {
            lines.push((
                "browser",
                if still_loading {
                    s.dim("loading the page…")
                } else {
                    text
                },
            ));
        }
    }
    lines
}

/// What the fast phase says while the browser works.
const STILL_LOADING: &str = "the browser is still loading the page";

fn browser_line(b: &insite_core::analyze::browser::Browser, s: &Style) -> String {
    let mut parts: Vec<String> = b
        .metrics
        .iter()
        .filter(|m| m.name != "fcp")
        .map(|m| {
            let text = format!("{} {}", m.name.to_uppercase(), metric_value(m.name, m.value));
            match m.rating {
                "good" => s.green(&text),
                "needs_improvement" => s.yellow(&text),
                _ => s.red(&text),
            }
        })
        .collect();
    parts.push(format!("{} requests, {}", b.requests, bytes(b.transferred_bytes)));
    if b.third_party_bytes > 0 {
        parts.push(format!("{:.0}% third-party", b.third_party_share * 100.0));
    }
    parts.push(s.dim(&b.profile));
    parts.join(" · ")
}

fn metric_value(name: &str, value: f64) -> String {
    match name {
        "cls" => format!("{value:.2}"),
        "tbt" => format!("{value:.0} ms"),
        _ => format!("{:.1} s", value / 1000.0),
    }
}

/// After a progressive fast report: the browser line, the stack as the browser
/// completed it, and the browser's findings.
pub fn browser_update(report: &Report, color: bool, verbose: bool, width: usize) -> String {
    neutralize(&browser_update_text(report, color, verbose, width), color)
}

fn browser_update_text(report: &Report, color: bool, verbose: bool, width: usize) -> String {
    let s = Style::new(color);
    let mut out = String::from("\n");
    for (label, text) in summary_lines(report, &s, width) {
        if label == "browser" || label == "stack" {
            let _ = writeln!(out, "{}{}", s.bold(&format!("{label:<LABEL$}")), text);
        }
    }
    if verbose {
        browser_details(&mut out, report, &s, width);
    }
    let findings: Vec<&Finding> = report
        .modules
        .browser
        .findings
        .iter()
        .filter(|f| verbose || f.severity > Severity::Info)
        .collect();
    if !findings.is_empty() {
        out.push('\n');
        for f in findings {
            let _ = writeln!(
                out,
                "  {}{}  {}",
                s.dim(&severity_column(f.severity)),
                f.title,
                s.dim(f.id)
            );
        }
    }
    if let Some(reason) = report
        .modules
        .browser
        .reason
        .as_deref()
        .filter(|_| report.modules.browser.status != Status::Ok)
    {
        let _ = writeln!(out, "\n{}", s.yellow(&format!("browser: {reason}")));
    }
    out
}

fn browser_details(out: &mut String, report: &Report, s: &Style, width: usize) {
    let Some(b) = &report.modules.browser.data else { return };
    let row = |out: &mut String, key: &str, value: &str| {
        if !value.is_empty() {
            let _ = writeln!(
                out,
                "  {}{}",
                s.dim(&format!("{key:<13}")),
                indent(value, 15, width).trim_start()
            );
        }
    };
    let _ = writeln!(out, "\n{}", s.bold("browser"));
    row(out, "browser", &format!("{} ({})", b.product, b.profile));
    row(out, "page", &b.url);
    for m in &b.metrics {
        row(
            out,
            &m.name.to_uppercase(),
            &format!("{} ({})", metric_value(m.name, m.value), m.rating.replace('_', " ")),
        );
    }
    if let Some(load) = b.load_ms {
        row(out, "load event", &format!("{} ms", ms(load)));
    }
    let types: Vec<String> = b
        .by_type
        .iter()
        .map(|t| format!("{} {} ({})", t.kind, t.count, bytes(t.bytes)))
        .collect();
    row(out, "requests", &format!("{} · {}", b.requests, types.join(", ")));
    for h in &b.heaviest {
        row(
            out,
            "heavy",
            &format!("{} · {} · {}", bytes(h.bytes), h.kind, clip(&h.url, 100)),
        );
    }
    if b.third_party_bytes > 0 {
        row(
            out,
            "third-party",
            &format!("{} ({:.0}%)", bytes(b.third_party_bytes), b.third_party_share * 100.0),
        );
    }
    for f in &b.failed {
        row(out, "failed", f);
    }
    for c in &b.console_errors {
        row(out, "console", c);
    }
    if let Some(r) = report.modules.stack.data.as_ref().and_then(|st| st.rendered.as_ref()) {
        let names: Vec<String> = r.technologies.iter().map(|t| t.name.clone()).collect();
        row(out, "stack", &format!("{} → {}", r.url, names.join(", ")));
    }
}

/// The module's summary text, or its status when it did not run normally.
/// Unselected modules print nothing.
fn summary<T>(module: &Module<T>, s: &Style, text: impl FnOnce(&T) -> String) -> Option<String> {
    let reason = module.reason.as_deref().unwrap_or_default();
    match (module.status, &module.data) {
        (Status::Skipped, _) if reason == "not selected" => None,
        (Status::Skipped, _) => Some(s.dim(&format!("skipped: {reason}"))),
        (Status::Timeout, _) => Some(s.yellow(&format!("timeout: {reason}"))),
        (Status::Failed, _) => Some(s.red(&format!("failed: {reason}"))),
        (_, Some(data)) => Some(text(data)),
        (_, None) => Some(s.dim(reason)),
    }
}

/// "2 issues" counted from the findings worth attention (low and above).
fn issues(findings: &[Finding]) -> Option<String> {
    let n = findings.iter().filter(|f| f.severity > Severity::Info).count();
    (n > 0).then(|| plural(n, "issue"))
}

fn headline(out: &mut String, s: &Style, host: &str, net: &Network, report: &Report) {
    let status = net.status.map_or_else(String::new, |code| {
        let text = code.to_string();
        match code {
            200..=299 => s.green(&text),
            300..=399 => s.yellow(&text),
            _ => s.red(&text),
        }
    });
    let _ = writeln!(
        out,
        "{host} → {}  {status}  {}  {}",
        net.final_url.as_deref().unwrap_or("?"),
        net.protocol.unwrap_or(""),
        net.total_ms.map(|t| format!("{} ms", ms(t))).unwrap_or_default(),
    );

    let mut timing = Vec::new();
    if !net.redirects.is_empty() {
        timing.push(format!(
            "redirects {} ({} ms)",
            net.redirects.len(),
            ms(net.redirects_ms)
        ));
    }
    if let Some(p) = &net.phases {
        if p.connection_reused {
            timing.push("connection reused".to_owned());
        }
        match (p.dns_ms, net.dns_source) {
            (Some(dns), _) => timing.push(format!("dns {}", ms(dns))),
            (None, Some("system")) if !p.connection_reused => timing.push("dns by system".to_owned()),
            _ => {}
        }
        if let Some(tcp) = p.tcp_ms {
            timing.push(format!("tcp {}", ms(tcp)));
        }
        if let Some(tls) = p.tls_ms {
            timing.push(format!("tls {}", ms(tls)));
        }
        timing.push(format!("ttfb {}", ms(p.ttfb_ms)));
        timing.push(format!("download {}", ms(p.download_ms)));
    }
    if !timing.is_empty() {
        let _ = writeln!(out, "  {}", s.dim(&timing.join(" · ")));
    }

    let mut facts = Vec::new();
    if let Some(peer) = &net.peer {
        let owner = report.modules.infra.data.as_ref().and_then(|i| {
            let name = i.hosting.clone().or_else(|| i.as_name.as_deref().map(short_as_name))?;
            Some(match i.asn {
                Some(asn) => format!("AS{asn} {name}"),
                None => name,
            })
        });
        facts.push(match owner {
            Some(o) => format!("{peer} ({o})"),
            None => peer.clone(),
        });
    }
    if let Some(proxy) = &net.proxy {
        facts.push(format!("via proxy {proxy}"));
    }
    if let Some(v6) = net.ipv6 {
        facts.push(format!("IPv6 {}", if v6 { "yes" } else { "no" }));
    }
    match net.https {
        HttpsEnforcement::Redirects => facts.push("HTTPS enforced".to_owned()),
        HttpsEnforcement::NoHttpListener => facts.push("HTTPS only".to_owned()),
        HttpsEnforcement::ServesHttp => facts.push(s.yellow("HTTP not redirected")),
        HttpsEnforcement::RedirectsToHttp => facts.push(s.yellow("port 80 redirects to HTTP")),
        HttpsEnforcement::HttpsUnavailable => facts.push(s.red("no HTTPS")),
        HttpsEnforcement::NotChecked => {}
    }
    if net.retries > 0 {
        facts.push(format!(
            "{} network retr{}",
            net.retries,
            if net.retries == 1 { "y" } else { "ies" }
        ));
    }
    if !facts.is_empty() {
        let _ = writeln!(out, "  {}", facts.join(" · "));
    }
}

/// `CLOUDFLARENET, US` reads as `CLOUDFLARENET`.
fn short_as_name(name: &str) -> String {
    match name.rsplit_once(", ") {
        Some((head, cc)) if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_uppercase()) => head.to_owned(),
        _ => name.to_owned(),
    }
}

fn email(d: &DomainReport, s: &Style) -> String {
    let reg = d.domain.as_str();
    let dmarc_at = format!("_dmarc.{reg}");
    let mut parts = Vec::new();
    let mut unknown = Vec::new();
    match d.mx.first() {
        Some(_) if d.null_mx => parts.push("null MX".to_owned()),
        Some(mx) => parts.push(
            d.mail_provider
                .clone()
                .or_else(|| d.primary_mx_host().map(str::to_owned))
                .unwrap_or_else(|| mx.trim_end_matches('.').to_owned()),
        ),
        None if d.absence_known(reg, "MX") => parts.push("no MX".to_owned()),
        None => unknown.push("MX"),
    }
    match &d.spf {
        Some(spf) => parts.push(
            spf.all
                .as_ref()
                .map_or_else(|| "SPF".to_owned(), |all| format!("SPF {all}")),
        ),
        None if d.absence_known(reg, "TXT") => parts.push(s.yellow("no SPF")),
        None => unknown.push("SPF"),
    }
    match &d.dmarc {
        Some(dmarc) => parts.push(match dmarc.policy.as_deref() {
            Some("none") => s.yellow("DMARC p=none"),
            Some(p) => format!("DMARC p={p}"),
            None => "DMARC".to_owned(),
        }),
        None if d.absence_known(&dmarc_at, "TXT") => parts.push(s.yellow("no DMARC")),
        None => unknown.push("DMARC"),
    }
    if !d.dkim_selectors_found.is_empty() {
        parts.push(format!("DKIM {}", d.dkim_selectors_found.join(", ")));
    }
    if !unknown.is_empty() {
        parts.push(s.dim(&format!("{} not measured", unknown.join(", "))));
    }
    parts.join(" · ")
}

fn dns_line(d: &DomainReport, s: &Style) -> String {
    let reg = d.domain.as_str();
    let mut parts = Vec::new();
    match (&d.dns_provider, d.ns.first()) {
        (Some(p), _) => parts.push(p.clone()),
        (None, Some(ns)) => parts.push(ns.trim_end_matches('.').to_owned()),
        (None, None) => {}
    }
    let mut unknown = Vec::new();
    match (d.dnssec, d.absence_known(reg, "DS")) {
        (true, _) => parts.push("DNSSEC".to_owned()),
        (false, true) => parts.push("no DNSSEC".to_owned()),
        (false, false) => unknown.push("DNSSEC"),
    }
    match (d.caa.is_empty(), d.caa_absence_known()) {
        (false, _) => parts.push("CAA".to_owned()),
        (true, true) => parts.push("no CAA".to_owned()),
        (true, false) => unknown.push("CAA"),
    }
    if !unknown.is_empty() {
        parts.push(s.dim(&format!("{} not measured", unknown.join(", "))));
    }
    parts.join(" · ")
}

// ---- -v: every section in full ---------------------------------------------

fn details(out: &mut String, report: &Report, s: &Style, width: usize) {
    let m = &report.modules;
    let section = |out: &mut String, name: &str, status: Status, reason: Option<&str>| {
        let _ = writeln!(out, "\n{}", s.bold(name));
        let state = match status {
            Status::Ok => return,
            Status::Partial => "partial",
            Status::Timeout => "timeout",
            Status::Failed => "failed",
            Status::Skipped => "skipped",
        };
        let note = reason.map_or_else(|| state.to_owned(), |r| format!("{state}: {r}"));
        let _ = writeln!(out, "{}", s.dim(&indent(&note, 2, width)));
    };
    let row = |out: &mut String, key: &str, value: &str| {
        if !value.is_empty() {
            let _ = writeln!(
                out,
                "  {}{}",
                s.dim(&format!("{key:<13}")),
                indent(value, 15, width).trim_start()
            );
        }
    };

    if let Some(net) = &m.network.data {
        section(out, "network", m.network.status, m.network.reason.as_deref());
        for r in &net.redirects {
            row(
                out,
                "redirect",
                &format!("{} → {} {} ({} ms)", r.url, r.status, r.location, ms(r.ms)),
            );
        }
        if let Some(p) = &net.page {
            let mut text = format!(
                "{} transferred, {} decoded",
                bytes(p.transferred_bytes),
                bytes(p.size_bytes)
            );
            if let Some(e) = &p.content_encoding {
                text.push_str(&format!(" ({e})"));
            }
            if p.truncated {
                text.push_str(", cut at the limit");
            }
            row(out, "page", &text);
        }
        if let Some(source) = net.dns_source {
            row(out, "resolved by", source);
        }
    }

    if let Some(tls) = &m.tls.data {
        section(out, "tls", m.tls.status, m.tls.reason.as_deref());
        let mut connection = vec![tls.version.clone(), tls.cipher_suite.clone()];
        connection.extend(tls.key_exchange.clone());
        connection.extend(tls.alpn.clone());
        row(out, "connection", &connection.join(" · "));
        if let Some(c) = &tls.certificate {
            row(out, "subject", &c.subject);
            row(out, "issuer", &c.issuer);
            row(
                out,
                "valid",
                &format!(
                    "{} → {} ({} days, {} left)",
                    c.not_before, c.not_after, c.lifetime_days, c.days_remaining
                ),
            );
            row(out, "names", &c.names.join(", "));
            row(
                out,
                "key",
                &format!("{} · {} · {} SCTs", c.key, c.signature_algorithm, c.sct_count),
            );
        }
        let chain: Vec<&str> = tls.chain.iter().map(|e| e.subject.as_str()).collect();
        row(out, "chain", &chain.join(" → "));
        row(out, "OCSP stapled", if tls.ocsp_stapled { "yes" } else { "no" });
        if let Some(e) = &tls.verification_error {
            row(out, "error", e);
        }
    }

    if let Some(dns) = &m.dns.data {
        for d in &dns.domains {
            section(out, &format!("dns {}", d.domain), m.dns.status, m.dns.reason.as_deref());
            row(out, "A", &d.a.join(", "));
            row(out, "AAAA", &d.aaaa.join(", "));
            row(out, "CNAME", &d.cname.join(", "));
            let provider = d.dns_provider.as_ref().map(|p| format!(" ({p})")).unwrap_or_default();
            row(out, "NS", format!("{}{provider}", d.ns.join(", ")).trim());
            let mail = match &d.mail_provider {
                Some(p) => format!(" ({p})"),
                None if d.null_mx => " (null MX: accepts no mail)".to_owned(),
                None => String::new(),
            };
            row(out, "MX", format!("{}{mail}", d.mx.join(", ")).trim());
            if let Some(spf) = &d.spf {
                let incomplete = if spf.lookups_incomplete { "+" } else { "" };
                row(
                    out,
                    "SPF",
                    &format!("{} ({}{incomplete} lookups)", spf.record, spf.lookups),
                );
            }
            if let Some(dmarc) = &d.dmarc {
                row(out, "DMARC", &format!("{} (at {})", dmarc.record, dmarc.found_at));
            }
            row(out, "DKIM", &d.dkim_selectors_found.join(", "));
            row(out, "CAA", &d.caa.join(", "));
            let yes = |b: bool| if b { "yes" } else { "no" };
            row(
                out,
                "policies",
                &format!(
                    "DNSSEC {} · MTA-STS {} · TLS-RPT {} · BIMI {}",
                    yes(d.dnssec),
                    yes(d.mta_sts),
                    yes(d.tls_rpt),
                    yes(d.bimi)
                ),
            );
            if !d.failed_queries.is_empty() {
                row(out, "failed", &d.failed_queries.join(", "));
            }
            if !d.authoritative_queries.is_empty() {
                row(out, "direct", &d.authoritative_queries.join(", "));
            }
        }
    }

    if let Some(infra) = &m.infra.data {
        section(out, "infra", m.infra.status, m.infra.reason.as_deref());
        row(out, "IP", infra.ip.as_deref().unwrap_or_default());
        let asn = infra
            .asn
            .map(|a| format!("AS{a} {}", infra.as_name.as_deref().unwrap_or_default()));
        row(out, "AS", asn.as_deref().unwrap_or_default());
        row(out, "prefix", infra.prefix.as_deref().unwrap_or_default());
        row(out, "country", infra.country.as_deref().unwrap_or_default());
        row(out, "hosting", infra.hosting.as_deref().unwrap_or_default());
        for c in &infra.cdn {
            row(out, "CDN", &format!("{} ({})", c.name, c.evidence));
        }
        row(out, "server", infra.server.as_deref().unwrap_or_default());
        if let Some(c) = &infra.challenge {
            row(out, "challenge", &format!("{} ({})", c.name, c.evidence));
        }
    }

    if let Some(sec) = &m.security.data {
        section(out, "security", m.security.status, m.security.reason.as_deref());
        row(out, "method", sec.methodology);
        for t in &sec.tests {
            let modifier = if t.modifier == 0 {
                "  0".to_owned()
            } else {
                format!("{:+3}", t.modifier)
            };
            let modifier = match t.modifier {
                m if m < 0 => s.red(&modifier),
                m if m > 0 => s.green(&modifier),
                _ => s.dim(&modifier),
            };
            let _ = writeln!(out, "  {} {modifier}  {}", s.dim(&format!("{:<30}", t.test)), t.result);
        }
        if let Some(txt) = &sec.security_txt {
            let mut text = txt.state.to_owned();
            if !txt.contact.is_empty() {
                text.push_str(&format!(" · {}", txt.contact.join(", ")));
            }
            if let Some(e) = &txt.expires {
                text.push_str(&format!(" · expires {e}"));
            }
            row(out, "security.txt", &text);
        }
    }

    if let Some(stack) = &m.stack.data {
        section(out, "stack", m.stack.status, m.stack.reason.as_deref());
        for t in &stack.technologies {
            let mut name = s.bold(&t.name);
            if let Some(v) = &t.version {
                name = format!("{name} {v}");
            }
            let confidence = if t.confidence < 100 {
                format!(" {}%", t.confidence)
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "  {name}{}  {}",
                s.yellow(&confidence),
                s.dim(&t.categories.join(", "))
            );
            let evidence: Vec<String> = match &t.implied_by {
                Some(by) => vec![format!("implied by {by}")],
                None => t.evidence.iter().map(evidence_text).collect(),
            };
            for e in evidence.iter().take(3) {
                let _ = writeln!(out, "{}", s.dim(&indent(e, 6, width)));
            }
        }
        row(out, "signatures", &stack.signatures);
    }

    if let Some(seo) = &m.seo.data {
        section(out, "seo", m.seo.status, m.seo.reason.as_deref());
        row(
            out,
            "title",
            &seo.title
                .as_ref()
                .map(|t| format!("{t} ({} chars)", seo.title_length))
                .unwrap_or_default(),
        );
        row(
            out,
            "description",
            &seo.description
                .as_ref()
                .map(|d| format!("{d} ({} chars)", seo.description_length))
                .unwrap_or_default(),
        );
        row(out, "canonical", &seo.canonical.join(", "));
        row(out, "robots meta", seo.meta_robots.as_deref().unwrap_or_default());
        row(out, "X-Robots-Tag", &seo.x_robots_tag.join(", "));
        row(out, "lang", seo.lang.as_deref().unwrap_or_default());
        row(out, "viewport", if seo.viewport { "yes" } else { "no" });
        let h: Vec<String> = seo
            .headings
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(i, n)| format!("h{} {n}", i + 1))
            .collect();
        row(out, "headings", &h.join(" · "));
        row(out, "Open Graph", &seo.open_graph.join(", "));
        row(out, "structured", &seo.structured_data.join(", "));
        row(out, "hreflang", &seo.hreflang.join(", "));
        if seo.images > 0 {
            row(
                out,
                "images",
                &format!("{} ({} without alt)", seo.images, seo.images_without_alt),
            );
        }
        if let Some(r) = &seo.robots_txt {
            let blocks = if r.blocks_all { " · blocks everything" } else { "" };
            row(out, "robots.txt", &format!("{}{blocks}", r.state));
        }
        if let Some(sm) = &seo.sitemap {
            row(
                out,
                "sitemap",
                &format!("{} · {} ({} entries)", sm.url, sm.state, sm.entries),
            );
        }
    }

    browser_details(out, report, s, width);

    if let Some(w) = &m.weight.data {
        section(out, "weight", m.weight.status, m.weight.reason.as_deref());
        let compression = w.compression.as_deref().unwrap_or("none");
        row(
            out,
            "HTML",
            &format!(
                "{} transferred, {} decoded, compression {compression}",
                bytes(w.html_transferred_bytes),
                bytes(w.html_bytes)
            ),
        );
        row(
            out,
            "scripts",
            &format!(
                "{} external, {} inline ({})",
                w.scripts_external,
                w.scripts_inline,
                bytes(w.inline_script_bytes as u64)
            ),
        );
        row(out, "blocking", &w.render_blocking_scripts.join(", "));
        row(
            out,
            "styles",
            &format!(
                "{} stylesheets, {} inline ({})",
                w.stylesheets,
                w.inline_styles,
                bytes(w.inline_style_bytes as u64)
            ),
        );
        if w.images > 0 {
            let formats: Vec<String> = w.image_formats.iter().map(|(f, n)| format!("{f} {n}")).collect();
            row(
                out,
                "images",
                &format!(
                    "{} ({}) · {} lazy · {} without dimensions",
                    w.images,
                    formats.join(", "),
                    w.images_lazy,
                    w.images_without_dimensions
                ),
            );
        }
        if w.iframes > 0 {
            row(out, "iframes", &w.iframes.to_string());
        }
        for t in &w.third_parties {
            let names = if t.technologies.is_empty() {
                String::new()
            } else {
                format!(" · {}", t.technologies.join(", "))
            };
            row(
                out,
                "third party",
                &format!("{} · {} ({}){names}", t.domain, t.resources, t.kinds.join(", ")),
            );
        }
    }
}

/// What a signature matched: `headers[x-powered-by]: Next.js`, or the selector
/// for a DOM match, which has no value of its own.
pub fn evidence_text(e: &insite_core::detect::Evidence) -> String {
    match &e.key {
        Some(k) if e.value.is_empty() => format!("{}: {k}", e.field),
        Some(k) => format!("{}[{k}]: {}", e.field, e.value),
        None => format!("{}: {}", e.field, e.value),
    }
}

/// At most `max` characters, with an ellipsis when cut.
pub fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_owned(),
    }
}

/// Wraps `text` to `width`, every line indented by `by` spaces.
fn indent(text: &str, by: usize, width: usize) -> String {
    let room = width.saturating_sub(by).max(30);
    let mut lines = Vec::new();
    for paragraph in text.lines() {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > room {
                lines.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        lines.push(line);
    }
    let pad = " ".repeat(by);
    lines.iter().map(|l| format!("{pad}{l}")).collect::<Vec<_>>().join("\n")
}

/// Whole milliseconds, or one decimal below 10 ms.
pub fn ms(value: f64) -> String {
    if value < 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.0}")
    }
}

/// The one size formatter, shared with the findings (see `format_bytes`).
pub fn bytes(n: u64) -> String {
    format_bytes(n)
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// Width of the longest severity label (`critical`) plus one separating space.
pub const SEVERITY_COLUMN: usize = 9;

/// The severity padded to a column one wider than the longest label, so the
/// text that follows never runs into it.
pub fn severity_column(s: Severity) -> String {
    format!("{:<w$}", severity(s), w = SEVERITY_COLUMN)
}

pub fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use insite_core::report::{Modules, TargetInfo};
    use std::collections::BTreeMap;

    pub(crate) const HOSTILE: &str = "\x1b[2J\x1b]0;pwned\x07\u{9b}2J";

    pub(crate) fn hostile_report() -> Report {
        let mut modules = Modules {
            network: Module::skipped("not selected"),
            tls: Module::skipped("not selected"),
            dns: Module::skipped("not selected"),
            infra: Module::skipped("not selected"),
            security: Module::skipped("not selected"),
            stack: Module::skipped("not selected"),
            seo: Module::skipped("not selected"),
            weight: Module::skipped("not selected"),
            browser: Module::skipped("not selected"),
        };
        modules.seo.findings.push(Finding {
            id: "seo.title.missing",
            severity: Severity::Medium,
            params: BTreeMap::new(),
            evidence: format!("<title>{HOSTILE}</title>"),
            title: format!("Title {HOSTILE}"),
            detail: format!("detail {HOSTILE}"),
            fix: format!("fix {HOSTILE}"),
        });
        Report {
            schema_version: "0.1.0",
            collector_version: String::new(),
            analyzer_version: "test",
            target: TargetInfo {
                input: "https://example.com/".to_owned(),
                display_host: format!("example.com{HOSTILE}"),
                final_url: None,
            },
            started_at: "2026-01-01T00:00:00Z".to_owned(),
            duration_ms: 0.0,
            outcome: Outcome::Partial {
                reasons: vec![format!("reason {HOSTILE}")],
            },
            sources: Vec::new(),
            phase: None,
            modules,
        }
    }

    #[test]
    fn page_text_cannot_write_escape_sequences() {
        let report = hostile_report();
        for color in [false, true] {
            for text in [
                terminal(&report, color, true, 80),
                browser_update(&report, color, true, 80),
            ] {
                // Style's own colours may carry an ESC; nothing else may.
                let mut rest = text.clone();
                for code in ["0", "1", "2", "31", "32", "33"] {
                    rest = rest.replace(&format!("\x1b[{code}m"), "");
                }
                assert!(!rest.contains('\x1b'), "{text:?}");
                assert!(
                    !text.contains("\x1b[2J") && !text.contains("\x1b]") && !text.contains('\x07'),
                    "{text:?}"
                );
                assert!(!text.contains('\u{9b}'), "{text:?}");
            }
        }
        let plain = terminal(&report, false, true, 80);
        assert!(!plain.contains('\x1b'), "{plain:?}");
        assert!(plain.contains("example.com\u{fffd}[2J"), "{plain:?}");
    }

    #[test]
    fn severity_column_always_leaves_a_separator() {
        let all = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let longest = all.iter().map(|s| severity(*s).len()).max().unwrap();
        assert_eq!(SEVERITY_COLUMN, longest + 1);
        for sev in all {
            let col = severity_column(sev);
            assert_eq!(col.len(), SEVERITY_COLUMN);
            assert!(col.ends_with(' '), "{col:?}");
        }
    }

    #[test]
    fn critical_finding_is_separated_from_its_title() {
        let mut report = hostile_report();
        report.modules.seo.findings[0].severity = Severity::Critical;
        report.modules.seo.findings[0].title = "Certificate expired".to_owned();
        let text = terminal(&report, false, false, 80);
        assert!(text.contains("critical Certificate expired"), "{text}");
        assert!(!text.contains("criticalCertificate"), "{text}");
    }

    #[test]
    fn sizes_and_names() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(86_400), "86 KB");
        assert_eq!(bytes(1_250_000), "1.2 MB");
        assert_eq!(bytes(999_999), "1.0 MB");
        assert_eq!(short_as_name("CLOUDFLARENET, US"), "CLOUDFLARENET");
        assert_eq!(short_as_name("Some Org, Inc"), "Some Org, Inc");
        assert_eq!(plural(1, "issue"), "1 issue");
        assert_eq!(plural(3, "third party").replace("partys", "parties"), "3 third parties");
    }

    #[test]
    fn clips_long_text() {
        assert_eq!(clip("abcdef", 3), "abc…");
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("ação", 2), "aç…");
    }

    #[test]
    fn indent_wraps_words() {
        assert_eq!(indent("one two three", 2, 40), "  one two three");
        let wrapped = indent(&"word ".repeat(20), 4, 40);
        assert!(
            wrapped.lines().all(|l| l.len() <= 40 && l.starts_with("    ")),
            "{wrapped}"
        );
    }

    fn domain_report(mx: &[&str], mail_provider: Option<&str>) -> DomainReport {
        DomainReport {
            domain: "exemplo.com.br".into(),
            role: "input",
            host: "exemplo.com.br".into(),
            a: Vec::new(),
            aaaa: Vec::new(),
            cname: Vec::new(),
            ns: Vec::new(),
            dns_provider: None,
            mx: mx.iter().map(|m| (*m).to_owned()).collect(),
            null_mx: false,
            mail_provider: mail_provider.map(str::to_owned),
            caa: Vec::new(),
            dnssec: false,
            spf: None,
            dmarc: None,
            dkim_selectors_found: Vec::new(),
            mta_sts: false,
            tls_rpt: false,
            bimi: false,
            failed_queries: Vec::new(),
            authoritative_queries: Vec::new(),
            absences_reliable: true,
        }
    }

    #[test]
    fn email_line_never_prints_the_mx_preference() {
        let s = Style::new(false);
        // Known provider: its name.
        let known = domain_report(&["32456 smtp.globo.com"], Some("Globo"));
        assert!(email(&known, &s).starts_with("Globo"), "{}", email(&known, &s));
        // Unknown provider: the host of the lowest preference, with no number.
        let unknown = domain_report(&["28 route2.mx.cloudflare.net.", "5 route1.mx.cloudflare.net."], None);
        let line = email(&unknown, &s);
        assert!(line.starts_with("route1.mx.cloudflare.net ·"), "{line}");
        assert!(!line.contains("28") && !line.contains(" 5 "), "{line}");
    }
}
