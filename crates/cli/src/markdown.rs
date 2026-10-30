//! Markdown rendering: a report to paste into an e-mail or a proposal.

use std::fmt::Write;

use insite_core::report::{Finding, Outcome, Report, Severity};

use crate::render::{clip, evidence_text, ms, severity, summary_lines};
use crate::style::{Style, neutralize, visible_len};

/// The report as Markdown. Control characters from the page are neutralized, so
/// pasting the result cannot carry an escape sequence into a terminal.
pub fn render(report: &Report) -> String {
    neutralize(&markdown(report), false)
}

fn markdown(report: &Report) -> String {
    let plain = Style::new(false);
    let m = &report.modules;
    let mut out = String::new();
    let _ = writeln!(out, "# {}\n", escape(&report.target.display_host));

    let when = report
        .started_at
        .get(..16)
        .unwrap_or(&report.started_at)
        .replace('T', " ");
    let mut about = vec![format!(
        "Analyzed with insite {} on {when} UTC",
        report.analyzer_version
    )];
    if let Some(net) = &m.network.data
        && let Some(url) = &net.final_url
    {
        let mut facts: Vec<String> = net.status.map(|s| s.to_string()).into_iter().collect();
        facts.extend(net.protocol.map(str::to_owned));
        facts.extend(net.total_ms.map(|t| format!("{} ms", ms(t))));
        about.push(format!("final address <{url}> ({})", facts.join(", ")));
    }
    let _ = writeln!(out, "{}.\n", about.join(" · "));

    if let Outcome::Unreachable { reason } = &report.outcome {
        let _ = writeln!(out, "**The site could not be reached:** {}\n", escape(reason));
        return out;
    }

    let lines = summary_lines(report, &plain, usize::MAX);
    if !lines.is_empty() {
        out.push_str("| Area | Result |\n| --- | --- |\n");
        for (label, text) in lines {
            let label = match label {
                "tls" | "dns" | "seo" => label.to_ascii_uppercase(),
                "email" => "E-mail".to_owned(),
                other => capitalize(other),
            };
            let text = if label == "Security" {
                bold_grade(&text)
            } else {
                escape(&text)
            };
            let _ = writeln!(out, "| {label} | {} |", text.replace('\n', " "));
        }
        out.push('\n');
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
    .filter(|f| f.severity > Severity::Info)
    .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    if !findings.is_empty() {
        out.push_str("## What to fix\n");
        let mut current = None;
        for f in findings {
            if current != Some(f.severity) {
                current = Some(f.severity);
                let _ = writeln!(out, "\n### {}\n", capitalize(severity(f.severity)));
            }
            let _ = writeln!(out, "**{}** (`{}`)  ", escape(&f.title), f.id);
            let _ = writeln!(out, "{}  ", f.detail);
            let _ = writeln!(out, "*How to fix:* {}", f.fix);
            if !f.evidence.is_empty() {
                let _ = writeln!(out, "\n> Evidence: `{}`", clip(&f.evidence, 300).replace('`', "'"));
            }
            out.push('\n');
        }
    }

    if let Some(stack) = m.stack.data.as_ref().filter(|s| !s.technologies.is_empty()) {
        out.push_str(
            "## Technologies\n\n| Technology | Version | Category | Detected from |\n| --- | --- | --- | --- |\n",
        );
        for t in &stack.technologies {
            let mut name = escape(&t.name);
            if t.confidence < 100 {
                name.push_str(&format!(" (probable, {}%)", t.confidence));
            }
            let evidence = match &t.implied_by {
                Some(by) => format!("implied by {}", escape(by)),
                None => t
                    .evidence
                    .first()
                    .map(|e| format!("`{}`", clip(&evidence_text(e), 120).replace('`', "'")))
                    .unwrap_or_default(),
            };
            let _ = writeln!(
                out,
                "| {name} | {} | {} | {} |",
                escape(t.version.as_deref().unwrap_or("")),
                escape(&t.categories.join(", ")),
                evidence.replace('|', "\\|")
            );
        }
        out.push('\n');
    }

    if let Some(sec) = m.security.data.as_ref().filter(|s| s.grade.is_some()) {
        out.push_str("## Security headers\n\n| Test | Result | Points |\n| --- | --- | ---: |\n");
        for t in &sec.tests {
            let _ = writeln!(out, "| {} | {} | {:+} |", t.test, t.result, t.modifier);
        }
        let _ = writeln!(out, "\nGrade computed with the {}.\n", sec.methodology);
    }

    if let Outcome::Partial { reasons } = &report.outcome {
        out.push_str("## Limits of this report\n\n");
        for r in reasons {
            let _ = writeln!(out, "- {}", escape(r));
        }
        out.push('\n');
    }
    out
}

/// Characters that would break a table cell or start formatting.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('*', "\\*")
        .replace('_', "\\_")
}

/// The security line starts with the letter grade; make it stand out.
fn bold_grade(text: &str) -> String {
    match text.split_once(' ') {
        Some((grade, rest)) if visible_len(grade) <= 2 && grade.starts_with(|c: char| c.is_ascii_uppercase()) => {
            format!("**{grade}** {}", escape(rest.trim_start()))
        }
        _ => escape(text),
    }
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_text_cannot_write_escape_sequences() {
        let text = render(&crate::render::tests::hostile_report());
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'), "{text:?}");
        assert!(text.contains('\u{fffd}'), "{text:?}");
    }

    #[test]
    fn cells_are_escaped() {
        assert_eq!(escape("a|b *c* d_e"), "a\\|b \\*c\\* d\\_e");
        assert_eq!(bold_grade("C   score 55 · 2 issues"), "**C** score 55 · 2 issues");
        assert_eq!(bold_grade("no grade: challenge"), "no grade: challenge");
        assert_eq!(capitalize("security"), "Security");
    }
}
