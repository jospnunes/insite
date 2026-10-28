//! Terminal rendering of a `Report`. ANSI colors written by hand.

use std::fmt::Write;

use insite_core::analyze::network::{HttpsEnforcement, Network};
use insite_core::report::{Outcome, Report, Severity};

struct Style {
    color: bool,
}

impl Style {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
    fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
    fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }
    fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
}

pub fn terminal(report: &Report, color: bool) -> String {
    let s = Style { color };
    let mut out = String::new();
    let host = s.bold(&report.target.display_host);

    if let Outcome::Unreachable { reason } = &report.outcome {
        let _ = writeln!(out, "{host}  {}  {reason}", s.red("unreachable"));
        return out;
    }

    if let Some(net) = &report.modules.network.data {
        headline(&mut out, &s, &host, net);
    }

    if let Some(stack) = &report.modules.stack.data {
        let names: Vec<String> = stack
            .technologies
            .iter()
            .map(|t| {
                let mut name = t.name.clone();
                if let Some(v) = &t.version {
                    name.push(' ');
                    name.push_str(v);
                }
                if t.confidence < 100 {
                    name.push('?');
                }
                name
            })
            .collect();
        if !names.is_empty() {
            let _ = writeln!(out, "\n{}  {}", s.bold("stack"), names.join(" · "));
        }
    }

    let findings: Vec<_> = report
        .modules
        .network
        .findings
        .iter()
        .chain(&report.modules.tls.findings)
        .chain(&report.modules.dns.findings)
        .chain(&report.modules.infra.findings)
        .chain(&report.modules.seo.findings)
        .chain(&report.modules.weight.findings)
        .collect();
    if !findings.is_empty() {
        out.push('\n');
        for f in findings {
            let label = format!("{:<8}", severity(f.severity));
            let label = match f.severity {
                Severity::High | Severity::Critical => s.red(&label),
                Severity::Medium => s.yellow(&label),
                _ => s.dim(&label),
            };
            let _ = writeln!(out, "  {label}{}  {}", f.title, s.dim(f.id));
        }
    }

    if let Outcome::Partial { reasons } = &report.outcome {
        out.push('\n');
        for reason in reasons {
            let _ = writeln!(out, "{} {reason}", s.yellow("partial:"));
        }
    }
    out
}

fn headline(out: &mut String, s: &Style, host: &str, net: &Network) {
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
    let _ = writeln!(out, "  {}", s.dim(&timing.join(" · ")));

    let mut facts = Vec::new();
    if let Some(peer) = &net.peer {
        facts.push(peer.clone());
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

/// Whole milliseconds, or one decimal below 10 ms.
fn ms(value: f64) -> String {
    if value < 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.0}")
    }
}

fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
