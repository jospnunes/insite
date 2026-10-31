//! The one-site view: progress events and the final report turned into frame lines.
//! It never touches the terminal; the region writer draws what it returns.

use std::collections::BTreeMap;

use insite_core::collect::progress::{Part, Phase, Progress};
use insite_core::report::{Finding, Module, ModuleName, Outcome, Report, Selection, Severity, Status};
use insite_core::snapshot::DomainRole;

use super::theme::{Corner, Glyph, MeterColor, Theme, clean};
use crate::render::{clip, details_text, indent, ms, severity, short_as_name, summary_lines};
use crate::style::{Style, display_width, neutralize};

/// Below this many columns the phase bars go away.
const COMPACT: usize = 60;
/// Width of a row label: the longest one, `security`.
const LABEL: usize = 8;
/// Where a module's text starts: glyph, space, label, two spaces.
const TEXT_AT: usize = LABEL + 4;
/// The findings block stops adding low findings at this many lines.
const FINDING_LINES: usize = 8;

/// The module rows in display order: label, the module it belongs to and the parts
/// that must be done before its data is collected.
const ROWS: [(&str, ModuleName, &[Part]); 9] = [
    ("tls", ModuleName::Tls, &[Part::Page]),
    ("dns", ModuleName::Dns, &[Part::Records(DomainRole::Final)]),
    ("email", ModuleName::Dns, &[Part::Records(DomainRole::Final)]),
    ("security", ModuleName::Security, &[Part::Page, Part::HttpCheck]),
    ("stack", ModuleName::Stack, &[Part::Page, Part::Auxiliary]),
    ("services", ModuleName::Stack, &[Part::Page, Part::Auxiliary]),
    ("seo", ModuleName::Seo, &[Part::Page, Part::Auxiliary]),
    ("weight", ModuleName::Weight, &[Part::Page, Part::Auxiliary]),
    ("infra", ModuleName::Infra, &[Part::Asn]),
];

const PHASES: [(Phase, &str); 5] = [
    (Phase::Dns, "dns"),
    (Phase::Tcp, "tcp"),
    (Phase::Tls, "tls"),
    (Phase::Ttfb, "ttfb"),
    (Phase::Download, "download"),
];

/// A redirect, as the hop line shows it.
#[derive(Clone)]
struct Hop {
    from: String,
    to: String,
    status: u16,
    ms: f64,
}

/// What a live site has told us so far; the report, once it arrives, replaces all of it.
pub(crate) struct SiteView {
    host: String,
    selection: Selection,
    hops: BTreeMap<usize, Hop>,
    /// Milliseconds per phase (in `PHASES` order), by hop; the last event wins.
    phases: BTreeMap<usize, [Option<f64>; 5]>,
    done: Vec<Part>,
    report: Option<Report>,
}

impl SiteView {
    pub(crate) fn new(input: &str, selection: Selection) -> Self {
        let host = input.split_once("://").map_or(input, |(_, rest)| rest);
        let host = host.split(['/', '?', '#']).next().unwrap_or(host);
        SiteView {
            host: safe(host),
            selection,
            hops: BTreeMap::new(),
            phases: BTreeMap::new(),
            done: Vec::new(),
            report: None,
        }
    }

    pub(crate) fn on_progress(&mut self, event: &Progress) {
        match event {
            Progress::Phase { hop, phase, took } => {
                let slot = PHASES.iter().position(|(p, _)| p == phase);
                if let Some(slot) = slot {
                    self.phases.entry(*hop).or_default()[slot] = Some(took.as_secs_f64() * 1000.0);
                }
            }
            Progress::Redirect {
                hop,
                from,
                to,
                status,
                took,
            } => {
                self.hops.insert(
                    *hop,
                    Hop {
                        from: safe(from),
                        to: safe(to),
                        status: *status,
                        ms: took.as_secs_f64() * 1000.0,
                    },
                );
            }
            Progress::Done(part) => {
                if !self.done.contains(part) {
                    self.done.push(*part);
                }
            }
            // The browser's second act belongs to its own view.
            Progress::Browser(_) => {}
        }
    }

    pub(crate) fn on_report(&mut self, report: &Report) {
        self.report = Some(report.clone());
    }

    /// The lines to draw now. Once the report is in, they are the final lines.
    pub(crate) fn frame(&self, tick: usize, width: usize, theme: &Theme) -> Vec<String> {
        if let Some(report) = &self.report {
            return final_lines(report, width, theme, false);
        }
        // The hop being fetched is the one after the last redirect seen.
        let current = self.hops.keys().next_back().map_or(0, |h| h + 1);
        let hops: Vec<Hop> = self.hops.values().cloned().collect();
        let phases = self.phases.get(&current).copied().unwrap_or_default();
        let start: f64 = hops.iter().map(|h| h.ms).sum();
        let block = Timeline {
            hops,
            phases,
            reused: false,
            start,
            scale: start + phases.iter().flatten().sum::<f64>(),
            closing: None,
        };
        let rows = ROWS
            .iter()
            .filter(|(_, module, _)| self.selection.contains(*module))
            .map(|(label, _, needs)| {
                let (glyph, text) = if needs.iter().all(|p| self.done.contains(p)) {
                    (theme.dim(theme.glyph(Glyph::Neutral)), theme.dim("collected"))
                } else {
                    (theme.cyan(theme.spinner(tick)), String::new())
                };
                module_row(theme, &glyph, label, &text)
            })
            .collect();
        join_sections([header(&self.host, width, theme), block.rows(width, theme), rows])
    }
}

/// The finished view of one report: a pure function of it, also used for saved snapshots.
pub(crate) fn final_lines(report: &Report, width: usize, theme: &Theme, verbose: bool) -> Vec<String> {
    let mut head = header(&safe(&report.target.display_host), width, theme);
    let mut network = Vec::new();
    if let Outcome::Unreachable { reason } = &report.outcome {
        let text = format!("{} unreachable: {}", theme.glyph(Glyph::Bad), safe(reason));
        head.push(format!("  {}", theme.red(&text)));
    } else if let Some(timeline) = Timeline::of(report, theme) {
        network = timeline.rows(width, theme);
    }
    let mut notes = findings_block(report, width, theme, verbose);
    if let Outcome::Partial { reasons } = &report.outcome {
        let partial = reasons
            .iter()
            .map(|r| format!("  {}", theme.yellow(&format!("partial: {}", safe(r)))));
        notes.extend(partial);
    }
    let mut lines = join_sections([
        head,
        network,
        final_rows(report, width, theme, verbose),
        notes,
        hint(report, verbose, theme),
    ]);
    if verbose {
        lines.extend(details_text(report, true, width).lines().map(str::to_owned));
    }
    lines
}

/// Page-controlled text that is safe to color and stays on one line.
fn safe(text: &str) -> String {
    clean(text).replace('\n', " ")
}

/// Sections one blank line apart; empty ones vanish.
fn join_sections<const N: usize>(sections: [Vec<String>; N]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for section in sections.into_iter().filter(|s| !s.is_empty()) {
        if !out.is_empty() {
            out.push(String::new());
        }
        out.extend(section);
    }
    out
}

/// At most `cols` columns, with an ellipsis when cut.
fn fit(text: &str, cols: usize, theme: &Theme) -> String {
    if display_width(text) <= cols {
        return text.to_owned();
    }
    let dots = if theme.unicode { "…" } else { "~" };
    let mut out = String::new();
    for c in text.chars() {
        if display_width(&out) + display_width(&c.to_string()) + 1 > cols {
            break;
        }
        out.push(c);
    }
    out + dots
}

/// `left`, then `right` flush against column `width - 2`, at least two spaces apart.
fn spread(left: &str, right: &str, width: usize) -> String {
    let gap = (width.saturating_sub(2))
        .saturating_sub(display_width(left) + display_width(right))
        .max(2);
    format!("{left}{}{right}", " ".repeat(gap))
}

/// `◆ insite <version>` and the host on the right.
fn header(host: &str, width: usize, theme: &Theme) -> Vec<String> {
    let left = format!(
        "{} {}",
        theme.brand(&format!("{} insite", theme.glyph(Glyph::Brand))),
        theme.dim(env!("CARGO_PKG_VERSION"))
    );
    let room = width.saturating_sub(4 + display_width(&left));
    vec![spread(&left, &theme.bold(&fit(host, room, theme)), width)]
}

/// Everything the network block draws, from events or from the report.
struct Timeline {
    hops: Vec<Hop>,
    /// Milliseconds of the final hop per phase, in `PHASES` order.
    phases: [Option<f64>; 5],
    reused: bool,
    /// Time spent before the final hop started.
    start: f64,
    /// The time the bars share the width of; at least 1 ms.
    scale: f64,
    /// The summary line, once the report knows it.
    closing: Option<String>,
}

impl Timeline {
    fn of(report: &Report, theme: &Theme) -> Option<Timeline> {
        let net = report.modules.network.data.as_ref()?;
        let phases = net.phases.as_ref();
        let phases_ms = phases.map_or([None; 5], |p| {
            [p.dns_ms, p.tcp_ms, p.tls_ms, Some(p.ttfb_ms), Some(p.download_ms)]
        });
        let start = net.redirects_ms;
        let facts = [
            net.protocol.map(str::to_owned),
            net.ipv6.map(|v6| if v6 { "IPv6" } else { "no IPv6" }.to_owned()),
            net.peer.clone(),
            report.modules.infra.data.as_ref().and_then(|i| {
                let name = i.hosting.clone().or_else(|| i.as_name.as_deref().map(short_as_name))?;
                Some(i.asn.map_or(name.clone(), |asn| format!("AS{asn} {name}")))
            }),
        ];
        let facts: Vec<String> = facts.into_iter().flatten().map(|f| safe(&f)).collect();
        let mut closing = Vec::new();
        if let Some(total) = net.total_ms {
            closing.push(theme.bold(&format!("{} ms", ms(total))));
        }
        if let Some(code) = net.status {
            let text = code.to_string();
            closing.push(match code {
                200..=299 => theme.green(&text),
                300..=399 => theme.yellow(&text),
                _ => theme.red(&text),
            });
        }
        let closing = match (closing.is_empty(), facts.is_empty()) {
            (true, true) => None,
            (_, true) => Some(closing.join("  ")),
            (true, false) => Some(theme.dim(&facts.join(" · "))),
            (false, false) => Some(format!(
                "{} {}",
                closing.join("  "),
                theme.dim(&format!("· {}", facts.join(" · ")))
            )),
        };
        Some(Timeline {
            hops: net
                .redirects
                .iter()
                .map(|r| Hop {
                    from: safe(&r.url),
                    to: safe(&r.location),
                    status: r.status,
                    ms: r.ms,
                })
                .collect(),
            phases: phases_ms,
            reused: phases.is_some_and(|p| p.connection_reused),
            start,
            scale: net.total_ms.unwrap_or(start + phases_ms.iter().flatten().sum::<f64>()),
            closing,
        })
    }

    /// Hop lines, phase rows (bars on one time scale, each starting where the time
    /// before it ended) and the closing line, framed by corners.
    fn rows(&self, width: usize, theme: &Theme) -> Vec<String> {
        let compact = width < COMPACT;
        let mut rows: Vec<String> = self.hops.iter().map(|h| hop_line(h, width, theme)).collect();
        if compact {
            let times: Vec<String> = PHASES
                .iter()
                .zip(self.phases)
                .filter_map(|((_, name), t)| {
                    // `download` is the one name too long for a compact line.
                    let name = if *name == "download" { "dl" } else { name };
                    t.map(|t| format!("{name} {}", ms(t)))
                })
                .collect();
            if self.reused {
                rows.push(theme.dim("connection reused"));
            }
            if !times.is_empty() {
                rows.push(theme.dim(&fit(&times.join(" · "), width.saturating_sub(4), theme)));
            }
        } else {
            self.phase_rows(width, theme, &mut rows);
        }
        let closing = self.closing.is_some();
        rows.extend(self.closing.clone());
        let last = rows.len().saturating_sub(1);
        rows.iter()
            .enumerate()
            .map(|(i, row)| {
                if compact {
                    return format!("  {row}");
                }
                let corner = match i {
                    _ if closing && i == last => theme.glyph(Glyph::Corner(Corner::Bottom)),
                    0 => theme.glyph(Glyph::Corner(Corner::Top)),
                    _ => theme.glyph(Glyph::Pipe),
                };
                format!("  {} {row}", theme.dim(corner))
            })
            .collect()
    }

    fn phase_rows(&self, width: usize, theme: &Theme, rows: &mut Vec<String>) {
        let area = width.saturating_sub(30).max(10);
        let scale = self.scale.max(1.0);
        let mut at = self.start;
        for (i, ((_, name), took)) in PHASES.iter().zip(self.phases).enumerate() {
            if i == 3 && self.reused {
                rows.push(theme.dim("connection reused"));
            }
            let Some(took) = took else { continue };
            let paint = |text: &str| match i {
                3 => theme.magenta(text),
                4 => theme.green(text),
                _ => theme.cyan(text),
            };
            let mut bar = theme.bar(took / scale * area as f64);
            if bar.is_empty() && took > 0.0 {
                // Never an empty bar for time that passed: the smallest visible cell.
                bar = theme.bar(if theme.unicode { 0.125 } else { 1.0 });
            }
            let bar_width = display_width(&bar);
            let offset = ((at / scale * area as f64) as usize).min(area.saturating_sub(bar_width));
            rows.push(format!(
                "{} {}{}{} {}",
                theme.dim(&format!("{name:<8}")),
                " ".repeat(offset),
                paint(&bar),
                " ".repeat(area.saturating_sub(offset + bar_width)),
                paint(&format!("{:>5} ms", ms(took)))
            ));
            at += took;
        }
    }
}

/// `origin --301--> destination` with the hop's time on the right.
fn hop_line(hop: &Hop, width: usize, theme: &Theme) -> String {
    let lead = if theme.unicode { "──" } else { "--" };
    let arrow = format!("{lead}{}{}", hop.status, theme.glyph(Glyph::Arrow));
    let time = format!("{} ms", ms(hop.ms));
    let right = if width < COMPACT {
        theme.cyan(&time)
    } else {
        format!("{} {}", theme.dim("redirect"), theme.cyan(&time))
    };
    // 4 columns of frame, two gaps around the arrow and two before the time.
    let room = width.saturating_sub(4 + 2 + 2 + display_width(&arrow) + display_width(&right) + 2);
    let side = (room / 2).max(6);
    let left = format!(
        "{} {} {}",
        short_url(&hop.from, side, theme),
        theme.dim(&arrow),
        short_url(&hop.to, side, theme)
    );
    spread(&left, &right, width.saturating_sub(4))
}

/// A URL without its scheme or the root slash, cut to `cols` columns.
fn short_url(url: &str, cols: usize, theme: &Theme) -> String {
    let url = url.split_once("://").map_or(url, |(_, rest)| rest);
    fit(url.trim_end_matches('/'), cols, theme)
}

fn module_row(theme: &Theme, glyph: &str, label: &str, text: &str) -> String {
    let mut parts = text.split('\n');
    let first = format!(
        "{glyph} {}  {}",
        theme.bold(&format!("{label:<LABEL$}")),
        parts.next().unwrap_or("")
    );
    let rest = parts.map(|p| format!("{}{}", " ".repeat(TEXT_AT), p.trim_start()));
    std::iter::once(first).chain(rest).collect::<Vec<_>>().join("\n")
}

/// How a module ended, from its status and its worst finding.
enum Mark {
    Ok,
    Warn,
    Bad,
    Skipped,
}

fn mark<T>(module: &Module<T>) -> Mark {
    let worst = module.findings.iter().map(|f| f.severity).max();
    match module.status {
        Status::Skipped => Mark::Skipped,
        Status::Failed | Status::Timeout => Mark::Bad,
        _ if worst >= Some(Severity::High) => Mark::Bad,
        Status::Partial => Mark::Warn,
        _ if worst == Some(Severity::Medium) => Mark::Warn,
        _ => Mark::Ok,
    }
}

fn final_rows(report: &Report, width: usize, theme: &Theme, verbose: bool) -> Vec<String> {
    let m = &report.modules;
    // The summaries keep their own 16-colour text; page-controlled parts are neutralized.
    let summaries = summary_lines(report, &Style::new(true), width.saturating_sub(2), verbose);
    let mut rows = Vec::new();
    for (label, _, _) in ROWS {
        let Some((_, text)) = summaries.iter().find(|(l, _)| *l == label) else {
            continue;
        };
        let mark = match label {
            "services" => None,
            "tls" => Some(mark(&m.tls)),
            "dns" | "email" => Some(mark(&m.dns)),
            "security" => Some(mark(&m.security)),
            "stack" => Some(mark(&m.stack)),
            "seo" => Some(mark(&m.seo)),
            "weight" => Some(mark(&m.weight)),
            _ => Some(mark(&m.infra)),
        };
        let glyph = match mark {
            None => theme.dim(theme.glyph(Glyph::Neutral)),
            Some(Mark::Ok) => theme.green(theme.glyph(Glyph::Ok)),
            Some(Mark::Warn) => theme.yellow(theme.glyph(Glyph::Warn)),
            Some(Mark::Bad) => theme.red(theme.glyph(Glyph::Bad)),
            Some(Mark::Skipped) => theme.dim(theme.glyph(Glyph::Skipped)),
        };
        let text = match graded(report, label, width, theme) {
            Some(grade) => grade,
            None => neutralize(text, true),
        };
        rows.push(module_row(theme, &glyph, label, &text));
    }
    rows
}

/// The security row: the grade as a badge, a 0-100 meter and the score.
fn graded(report: &Report, label: &str, width: usize, theme: &Theme) -> Option<String> {
    let security = &report.modules.security;
    let data = security.data.as_ref().filter(|_| label == "security")?;
    if matches!(security.status, Status::Skipped | Status::Failed | Status::Timeout) {
        return None;
    }
    let (grade, score) = (data.grade?, data.score?);
    let tone = match grade.chars().next() {
        Some('A' | 'B') => MeterColor::Good,
        Some('C') => MeterColor::Warn,
        _ => MeterColor::Poor,
    };
    let meter = if width < COMPACT {
        String::new()
    } else {
        format!("{} ", theme.meter(f64::from(score) / 100.0, 12, tone))
    };
    Some(format!(
        "{} {meter}{}{}",
        theme.badge(grade),
        theme.bold(&score.to_string()),
        theme.dim("/100")
    ))
}

fn all_findings(report: &Report) -> Vec<&Finding> {
    let m = &report.modules;
    let mut all: Vec<&Finding> = [
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
    all.sort_by_key(|f| std::cmp::Reverse(f.severity));
    all
}

/// "N things to look at": medium and above always, then low ones up to a screenful.
/// Verbose shows everything, with each finding's detail, fix and evidence.
fn findings_block(report: &Report, width: usize, theme: &Theme, verbose: bool) -> Vec<String> {
    let all = all_findings(report);
    let shown = if verbose {
        all.len()
    } else {
        let medium_up = all.iter().filter(|f| f.severity >= Severity::Medium).count();
        let lows = all.iter().filter(|f| f.severity == Severity::Low).count();
        medium_up + lows.min(FINDING_LINES.saturating_sub(medium_up))
    };
    let mut out = Vec::new();
    if shown > 0 {
        out.push(format!(
            "  {}",
            theme.bold(&format!(
                "{shown} thing{} to look at",
                if shown == 1 { "" } else { "s" }
            ))
        ));
    }
    let id_width = all[..shown].iter().map(|f| f.id.len()).max().unwrap_or(0);
    // The frame's 14 columns (indent, glyph, label, gap), then the title, two spaces, the id.
    let title_room = width
        .saturating_sub(if width < COMPACT { 15 } else { 17 + id_width })
        .max(10);
    let titles: Vec<String> = all[..shown].iter().map(|f| safe(&f.title)).collect();
    let longest = titles.iter().map(|t| display_width(t)).max().unwrap_or(0);
    for (f, title) in all.iter().zip(&titles) {
        let (glyph, paint): (_, fn(&Theme, &str) -> String) = match f.severity {
            Severity::High | Severity::Critical => (Glyph::Bad, Theme::red),
            Severity::Medium => (Glyph::Warn, Theme::yellow),
            _ => (Glyph::Neutral, Theme::dim),
        };
        let label = paint(
            theme,
            &format!("{} {:<LABEL$}", theme.glyph(glyph), severity(f.severity)),
        );
        let title = fit(title, title_room, theme);
        if width < COMPACT {
            out.push(format!("  {label}  {title}"));
        } else {
            let pad = " ".repeat(longest.min(title_room).saturating_sub(display_width(&title)));
            out.push(format!("  {label}  {title}{pad}  {}", theme.dim(f.id)));
        }
        if verbose {
            let evidence = clip(&f.evidence, 300);
            for (prefix, text) in [("", &f.detail), ("fix: ", &f.fix), ("evidence: ", &evidence)] {
                if !text.is_empty() {
                    let wrapped = indent(&format!("{prefix}{}", safe(text)), 2 + 2 + LABEL + 2, width);
                    out.extend(wrapped.lines().map(|l| theme.dim(l)));
                }
            }
        }
    }
    let hidden = all.len() - shown;
    if hidden > 0 {
        out.push(format!("  {}", theme.dim(&format!("+{hidden} more · -v shows them"))));
    }
    out
}

/// The next command to try.
fn hint(report: &Report, verbose: bool, theme: &Theme) -> Vec<String> {
    let first = all_findings(report).first().map(|f| f.id);
    let mut parts = Vec::new();
    parts.extend(first.map(|id| format!("insite explain {id}")));
    if !verbose {
        parts.push("-v for evidence".to_owned());
    }
    parts.push("--json".to_owned());
    let separator = if first.is_some() { "   ·   " } else { " · " };
    vec![format!("  {}", theme.dim(&parts.join(separator)))]
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use insite_core::collect::progress::{Part, Phase};
    use insite_core::report::{Module, Outcome, Severity, Status};
    use insite_core::snapshot::DomainRole;

    use super::*;
    use crate::render::tests::{HOSTILE, finding, full_report, hostile_report};
    use crate::style::display_width;

    fn ascii() -> Theme {
        Theme::plain_ascii()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The line without its SGR sequences.
    fn strip(line: &str) -> String {
        let mut out = String::new();
        let mut escape = false;
        for c in line.chars() {
            match (escape, c) {
                (false, '\x1b') => escape = true,
                (true, 'm') => escape = false,
                (true, _) => {}
                (false, _) => out.push(c),
            }
        }
        out
    }

    fn plain(lines: &[String]) -> Vec<String> {
        lines.iter().map(|l| strip(l)).collect()
    }

    /// The phase row named `name`: a corner or pipe, the name, a bar, a time in ms.
    fn phase_row<'a>(lines: &'a [String], name: &str) -> Option<&'a String> {
        lines.iter().find(|l| {
            let l = strip(l);
            let rest = l.trim_start();
            let after: String = rest.chars().skip(1).collect();
            l.ends_with(" ms") && after.trim_start().starts_with(name)
        })
    }

    /// The module row labelled `label`: starts with its glyph, then the label.
    fn row(lines: &[String], label: &str) -> Option<String> {
        plain(lines).into_iter().find(|l| {
            l.get(1..)
                .is_some_and(|r| r.trim_start().starts_with(label) && !l.starts_with(' '))
        })
    }

    fn every_escape_is_sgr(text: &str) {
        let mut rest = text;
        while let Some(at) = rest.find('\x1b') {
            let after = &rest[at + 1..];
            let body = after.strip_prefix('[').unwrap_or_else(|| panic!("not CSI: {text:?}"));
            let end = body
                .find(|c: char| !(c.is_ascii_digit() || c == ';'))
                .unwrap_or_else(|| panic!("unterminated: {text:?}"));
            assert_eq!(&body[end..=end], "m", "not SGR: {text:?}");
            rest = &body[end + 1..];
        }
        assert!(!text.contains('\u{9b}') && !text.contains('\x07'), "{text:?}");
    }

    fn phase(hop: usize, phase: Phase, took: u64) -> Progress {
        Progress::Phase {
            hop,
            phase,
            took: ms(took),
        }
    }

    #[test]
    fn phases_appear_as_they_arrive() {
        let mut view = SiteView::new("example.com", Selection::all());
        view.on_progress(&phase(0, Phase::Dns, 7));
        let lines = view.frame(0, 100, &ascii());
        assert!(phase_row(&lines, "dns").is_some(), "{lines:#?}");
        assert!(phase_row(&lines, "tcp").is_none(), "{lines:#?}");
        view.on_progress(&phase(0, Phase::Tcp, 13));
        let lines = view.frame(0, 100, &ascii());
        assert!(phase_row(&lines, "tcp").is_some(), "{lines:#?}");
        // A bar is drawn in the row.
        assert!(strip(phase_row(&lines, "tcp").unwrap()).contains('#'));
    }

    #[test]
    fn redirect_becomes_a_hop_line() {
        let mut view = SiteView::new("example.com", Selection::all());
        view.on_progress(&phase(0, Phase::Dns, 7));
        view.on_progress(&Progress::Redirect {
            hop: 0,
            from: "https://example.com/".to_owned(),
            to: "https://www.example.com/".to_owned(),
            status: 301,
            took: ms(77),
        });
        let lines = plain(&view.frame(0, 100, &ascii()));
        let hop = lines.iter().find(|l| l.contains("--301-->")).expect("hop line");
        assert!(hop.contains("example.com --301--> www.example.com"), "{hop}");
        assert!(hop.trim_end().ends_with("77 ms"), "{hop}");
        // The redirected hop's own phases are gone; the next hop starts empty.
        assert!(phase_row(&view.frame(0, 100, &ascii()), "dns").is_none());
        view.on_progress(&phase(1, Phase::Ttfb, 199));
        assert!(phase_row(&view.frame(0, 100, &ascii()), "ttfb").is_some());
    }

    #[test]
    fn modules_spin_until_their_parts_are_done() {
        let theme = ascii();
        let mut view = SiteView::new("example.com", Selection::all());
        view.on_progress(&Progress::Done(Part::Page));
        // The ASCII spinner at tick 0 is `|`, at tick 1 `/`.
        let security = |view: &SiteView, tick| row(&view.frame(tick, 100, &theme), "security").unwrap();
        assert!(security(&view, 0).starts_with('|'), "{}", security(&view, 0));
        assert!(security(&view, 1).starts_with('/'));
        // TLS needs only the page: it is collected already.
        let tls = row(&view.frame(0, 100, &theme), "tls").unwrap();
        assert!(tls.starts_with('.') && tls.contains("collected"), "{tls}");
        // dns waits for the final domain's records.
        assert!(row(&view.frame(0, 100, &theme), "dns").unwrap().starts_with('|'));
        view.on_progress(&Progress::Done(Part::HttpCheck));
        let line = security(&view, 0);
        assert!(line.starts_with('.') && line.contains("collected"), "{line}");
        // stack needs the auxiliary files too; infra the AS lookup.
        assert!(row(&view.frame(0, 100, &theme), "stack").unwrap().starts_with('|'));
        view.on_progress(&Progress::Done(Part::Auxiliary));
        view.on_progress(&Progress::Done(Part::Records(DomainRole::Input)));
        assert!(row(&view.frame(0, 100, &theme), "stack").unwrap().starts_with('.'));
        assert!(row(&view.frame(0, 100, &theme), "dns").unwrap().starts_with('|'));
        view.on_progress(&Progress::Done(Part::Records(DomainRole::Final)));
        assert!(row(&view.frame(0, 100, &theme), "dns").unwrap().starts_with('.'));
        assert!(row(&view.frame(0, 100, &theme), "email").unwrap().starts_with('.'));
        assert!(row(&view.frame(0, 100, &theme), "infra").unwrap().starts_with('|'));
        view.on_progress(&Progress::Done(Part::Asn));
        assert!(row(&view.frame(0, 100, &theme), "infra").unwrap().starts_with('.'));
    }

    #[test]
    fn only_the_selected_modules_get_a_row() {
        let view = SiteView::new("example.com", Selection::parse("tls,dns").unwrap());
        let lines = view.frame(0, 100, &ascii());
        for label in ["tls", "dns", "email"] {
            assert!(row(&lines, label).is_some(), "{label}");
        }
        for label in ["security", "stack", "services", "seo", "weight", "infra"] {
            assert!(row(&lines, label).is_none(), "{label}");
        }
    }

    #[test]
    fn the_report_replaces_the_collected_state() {
        let report = full_report();
        let mut view = SiteView::new("example.com", Selection::all());
        view.on_progress(&Progress::Done(Part::Page));
        view.on_report(&report);
        let lines = view.frame(3, 100, &ascii());
        assert_eq!(lines, final_lines(&report, 100, &ascii(), false));
    }

    #[test]
    fn final_glyphs_follow_severity() {
        let mut report = full_report();
        report.modules.security.findings = vec![finding("sec.hsts.missing", Severity::High, "No HSTS")];
        report.modules.tls.findings = vec![finding("tls.cert.soon", Severity::Medium, "Expires soon")];
        report.modules.weight = Module::skipped("no body to measure");
        let lines = final_lines(&report, 100, &ascii(), false);
        let glyph = |label: &str| row(&lines, label).unwrap().chars().next().unwrap();
        assert_eq!(glyph("security"), 'x');
        assert_eq!(glyph("tls"), '!');
        assert_eq!(glyph("weight"), '-');
        assert!(row(&lines, "weight").unwrap().contains("no body to measure"));
        assert_eq!(glyph("seo"), '+');
        assert_eq!(glyph("dns"), '+');
        assert_eq!(glyph("email"), '+');
        assert_eq!(glyph("services"), '.');
        // Failed and partial modules.
        report.modules.seo.status = Status::Failed;
        report.modules.seo.reason = Some("parse error".to_owned());
        report.modules.stack.status = Status::Partial;
        let lines = final_lines(&report, 100, &ascii(), false);
        let glyph = |label: &str| row(&lines, label).unwrap().chars().next().unwrap();
        assert_eq!(glyph("seo"), 'x');
        assert!(row(&lines, "seo").unwrap().contains("parse error"));
        assert_eq!(glyph("stack"), '!');
    }

    #[test]
    fn security_shows_badge_meter_and_score() {
        let lines = final_lines(&full_report(), 100, &ascii(), false);
        let security = row(&lines, "security").unwrap();
        assert!(
            security.contains(" B ") && security.contains('#') && security.contains("75/100"),
            "{security}"
        );
    }

    #[test]
    fn closing_line_has_total_status_protocol_ip_and_as() {
        let lines = plain(&final_lines(&full_report(), 100, &ascii(), false));
        let close = lines.iter().find(|l| l.contains("328 ms")).expect("closing line");
        for part in ["200", "HTTP/2", "IPv6", "2606:4700::6810:7c60", "AS13335 CLOUDFLARENET"] {
            assert!(close.contains(part), "{part} in {close}");
        }
    }

    #[test]
    fn findings_block_counts_orders_and_hints() {
        let lines = plain(&final_lines(&full_report(), 100, &ascii(), false));
        let at = lines
            .iter()
            .position(|l| l.contains("3 things to look at"))
            .expect("title");
        assert!(lines[at + 1].contains("! medium") && lines[at + 1].contains("sec.csp.unsafe_inline"));
        assert!(lines[at + 2].contains("low") && lines[at + 3].contains("low"));
        let hint = lines.last().unwrap();
        assert!(
            hint.contains("insite explain sec.csp.unsafe_inline   .   -v for evidence   .   --json")
                || hint.contains("insite explain sec.csp.unsafe_inline   ·   -v for evidence   ·   --json"),
            "{hint}"
        );
    }

    #[test]
    fn low_findings_stop_at_eight_lines_with_a_count() {
        let mut report = full_report();
        report.modules.seo.findings = (0..12)
            .map(|_| finding("seo.title.short", Severity::Low, "Short title"))
            .collect();
        let lines = plain(&final_lines(&report, 100, &ascii(), false));
        assert!(lines.iter().any(|l| l.contains("8 things to look at")), "{lines:#?}");
        assert_eq!(lines.iter().filter(|l| l.contains(". low")).count(), 7);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("+7 more") && l.contains("-v shows them")),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_clean_report_has_no_findings_block() {
        let mut report = full_report();
        for m in [
            &mut report.modules.security.findings,
            &mut report.modules.weight.findings,
        ] {
            m.clear();
        }
        let lines = plain(&final_lines(&report, 100, &ascii(), false));
        assert!(!lines.iter().any(|l| l.contains("things to look at")));
        assert!(lines.last().unwrap().contains("-v for evidence"));
        assert!(!lines.last().unwrap().contains("explain"));
    }

    #[test]
    fn unreachable_has_a_red_header_and_no_phases() {
        let mut report = full_report();
        report.outcome = Outcome::Unreachable {
            reason: format!("connection refused {HOSTILE}"),
        };
        report.modules.network = Module::skipped("no response");
        let lines = final_lines(&report, 100, &ascii(), false);
        let red = lines.iter().find(|l| l.contains("unreachable")).expect("red line");
        assert!(red.starts_with("\x1b[31m") || red.contains("\x1b[31m"), "{red:?}");
        assert!(strip(red).contains("connection refused"));
        let joined = lines.join("\n");
        every_escape_is_sgr(&joined);
        assert!(phase_row(&lines, "ttfb").is_none() && phase_row(&lines, "dns").is_none());
        assert!(!strip(&joined).contains("ttfb"));
        // The modules the report still carries keep their rows.
        assert!(row(&lines, "tls").is_some());
    }

    #[test]
    fn narrow_terminal_drops_bars() {
        let wide = plain(&final_lines(&full_report(), 100, &ascii(), false));
        assert!(wide.iter().any(|l| l.contains('#')));
        let narrow = plain(&final_lines(&full_report(), 50, &ascii(), false));
        assert!(
            !narrow.iter().any(|l| l.contains('#') && !l.contains("security")),
            "{narrow:#?}"
        );
        let one = narrow
            .iter()
            .find(|l| l.contains("dns 7.0 · tcp 13 · tls 14 · ttfb 199 · dl 13"))
            .expect("one phase line");
        assert!(!one.contains("  7.0 ms"), "{one}");
        // The finding keeps its title and drops the id column.
        let finding = narrow.iter().find(|l| l.contains("Content Security Policy")).unwrap();
        assert!(!finding.contains("sec.csp.unsafe_inline"), "{finding}");
        let wide_finding = wide.iter().find(|l| l.contains("Content Security Policy")).unwrap();
        assert!(wide_finding.contains("sec.csp.unsafe_inline"));
    }

    #[test]
    fn a_reused_connection_says_so() {
        let mut report = full_report();
        let net = report.modules.network.data.as_mut().unwrap();
        let phases = net.phases.as_mut().unwrap();
        phases.connection_reused = true;
        (phases.dns_ms, phases.tcp_ms, phases.tls_ms) = (None, None, None);
        let lines = plain(&final_lines(&report, 100, &ascii(), false));
        assert!(lines.iter().any(|l| l.contains("connection reused")), "{lines:#?}");
        assert!(phase_row(&report_lines(&report), "dns").is_none());
        assert!(phase_row(&report_lines(&report), "ttfb").is_some());
    }

    fn report_lines(report: &Report) -> Vec<String> {
        final_lines(report, 100, &ascii(), false)
    }

    #[test]
    fn tiny_phases_still_get_a_cell() {
        let mut report = full_report();
        let phases = report.modules.network.data.as_mut().unwrap().phases.as_mut().unwrap();
        phases.dns_ms = Some(0.05);
        for theme in [
            ascii(),
            Theme {
                truecolor: false,
                unicode: true,
            },
        ] {
            let lines = final_lines(&report, 100, &theme, false);
            let dns = strip(phase_row(&lines, "dns").unwrap());
            assert!(dns.contains('#') || dns.contains('▏'), "{dns}");
        }
    }

    #[test]
    fn bars_share_one_time_scale() {
        let lines = final_lines(&full_report(), 100, &ascii(), false);
        let bar_len = |name: &str| strip(phase_row(&lines, name).unwrap()).matches('#').count();
        // ttfb took 199 ms against 13 ms for the download.
        assert!(bar_len("ttfb") > 5 * bar_len("download"), "{lines:#?}");
        assert!(bar_len("ttfb") > bar_len("tls"));
    }

    #[test]
    fn live_phase_rows_match_the_final_ones() {
        let mut report = full_report();
        // The scale of the live view is what arrived: make the total agree with it.
        report.modules.network.data.as_mut().unwrap().total_ms = Some(323.0);
        let mut view = SiteView::new("example.com", Selection::all());
        view.on_progress(&Progress::Redirect {
            hop: 0,
            from: "https://example.com/".to_owned(),
            to: "https://www.example.com/".to_owned(),
            status: 301,
            took: ms(77),
        });
        for (p, t) in [
            (Phase::Dns, 7),
            (Phase::Tcp, 13),
            (Phase::Tls, 14),
            (Phase::Ttfb, 199),
            (Phase::Download, 13),
        ] {
            view.on_progress(&phase(1, p, t));
        }
        let live = view.frame(0, 100, &Theme::plain_ascii());
        let done = final_lines(&report, 100, &Theme::plain_ascii(), false);
        let rows = |lines: &[String]| -> Vec<String> {
            ["dns", "tcp", "tls", "ttfb", "download"]
                .iter()
                .map(|n| phase_row(lines, n).unwrap().clone())
                .collect()
        };
        assert_eq!(rows(&live), rows(&done));
    }

    #[test]
    fn hostile_text_cannot_escape() {
        let theme = Theme {
            truecolor: true,
            unicode: true,
        };
        let lines = final_lines(&hostile_report(), 80, &theme, true);
        let joined = lines.join("\n");
        assert!(!joined.contains("\x1b[2J") && !joined.contains("\x1b]"), "{joined:?}");
        every_escape_is_sgr(&joined);

        // The live frame: hostile input, redirect URLs.
        let mut view = SiteView::new(&format!("https://{HOSTILE}/"), Selection::all());
        view.on_progress(&Progress::Redirect {
            hop: 0,
            from: format!("https://{HOSTILE}/"),
            to: format!("https://{HOSTILE}.example/"),
            status: 302,
            took: ms(5),
        });
        let joined = view.frame(0, 80, &theme).join("\n");
        assert!(!joined.contains("\x1b[2J") && !joined.contains("\x1b]"), "{joined:?}");
        every_escape_is_sgr(&joined);

        // Hostile reasons and findings in a full report.
        let mut report = full_report();
        report.outcome = Outcome::Unreachable {
            reason: HOSTILE.to_owned(),
        };
        report.modules.seo.findings = vec![finding("seo.x", Severity::High, HOSTILE)];
        report.modules.weight = Module::skipped(HOSTILE);
        let joined = final_lines(&report, 80, &theme, true).join("\n");
        assert!(!joined.contains("\x1b[2J") && !joined.contains("\x1b]"), "{joined:?}");
        every_escape_is_sgr(&joined);
    }

    #[test]
    fn no_line_holds_a_newline() {
        let mut report = full_report();
        report.modules.seo.findings = vec![finding("seo.x", Severity::Medium, "two\nlines")];
        for line in final_lines(&report, 100, &ascii(), false) {
            assert!(!line.contains('\n'), "{line:?}");
        }
    }

    #[test]
    fn verbose_appends_details() {
        let report = full_report();
        let short = final_lines(&report, 100, &ascii(), false);
        let long = final_lines(&report, 100, &ascii(), true);
        assert!(long.len() > short.len());
        // Same up to the findings, which grow their detail, fix and evidence.
        let findings = short
            .iter()
            .position(|l| strip(l).contains("things to look at"))
            .unwrap();
        assert_eq!(long[..findings], short[..findings]);
        assert!(
            plain(&long)
                .iter()
                .any(|l| l.contains("fix: fix for sec.csp.unsafe_inline"))
        );
        assert!(!plain(&short).iter().any(|l| l.contains("fix: ")));
        let text = plain(&long).join("\n");
        assert!(text.contains("OCSP stapled") && text.contains("redirect"), "{text}");
        assert!(!plain(&short).join("\n").contains("OCSP stapled"));
    }

    #[test]
    fn the_lines_that_set_the_layout_fit_the_width() {
        // Module text and the closing line are not cut here: the region clips them.
        for width in [40, 60, 80, 100, 140] {
            let lines = final_lines(&full_report(), width, &ascii(), false);
            for (i, line) in lines.iter().enumerate() {
                let text = strip(line);
                let layout = i == 0 || text.ends_with(" ms") || text.contains(". low") || text.contains("! medium");
                if layout && !text.contains("HTTP/2") {
                    assert!(display_width(line) < width, "{width}: {text:?}");
                }
            }
        }
    }
}
