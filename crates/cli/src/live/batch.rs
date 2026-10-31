//! The batch table: one row per site in input order, filled in as each analysis finishes.
//! It never touches the terminal; the region writer draws what it returns.

use std::time::Duration;

use insite_core::report::{Outcome, Report, Severity, Status};

use super::browser::{Paint, rating};
use super::site::{COMPACT, all_findings, finding_line, fit, host_of, safe, title_room};
use super::term::clip;
use super::theme::{Glyph, Theme};
use crate::render::metric_value;
use crate::stackview;
use crate::style::{Style, display_width};

/// Where every line starts.
const INDENT: usize = 2;
/// Between two columns.
const GAP: usize = 2;
/// Widths of the columns whose content has a known shape: `123.4 s`, a badge (`A+`) or a
/// `grade` header, `-123 days`.
const TIME: usize = 7;
const GRADE: usize = 5;
const TLS: usize = 9;
const LCP: usize = 7;
/// The least the stack column is worth drawing at, and the least a site name keeps.
const MIN_STACK: usize = 12;
const MIN_SITE: usize = 8;
/// Technologies the stack column lists.
const STACK_SHOWN: usize = 3;
/// A certificate with fewer days left than this is an alert.
const SOON: i64 = 30;

/// What the table and the blocks under it need from a report; the report itself is not kept.
struct Site {
    seconds: f64,
    grade: Option<&'static str>,
    /// Days until the certificate expires; negative once expired.
    tls_days: Option<i64>,
    /// LCP in ms and its rating.
    lcp: Option<(f64, &'static str)>,
    /// The first technologies of the stack, clean.
    stack: Vec<String>,
    /// Why the site did not answer, clean.
    unreachable: Option<String>,
    /// Medium and above, worst first.
    found: Vec<Found>,
}

struct Found {
    severity: Severity,
    id: &'static str,
    title: String,
}

impl Site {
    fn of(report: &Report) -> Site {
        let m = &report.modules;
        let graded = !matches!(m.security.status, Status::Skipped | Status::Failed | Status::Timeout);
        let plain = Style::new(false);
        let stack = m.stack.data.as_ref().map_or_else(Vec::new, |s| {
            stackview::view(&s.technologies, false)
                .stack
                .into_iter()
                .take(STACK_SHOWN)
                .map(|t| safe(&stackview::label(t, &plain)))
                .collect()
        });
        Site {
            seconds: report.duration_ms / 1000.0,
            grade: m.security.data.as_ref().filter(|_| graded).and_then(|s| s.grade),
            tls_days: m
                .tls
                .data
                .as_ref()
                .and_then(|t| t.certificate.as_ref())
                .map(|c| c.days_remaining),
            lcp: m
                .browser
                .data
                .as_ref()
                .and_then(|b| b.metrics.iter().find(|x| x.name == "lcp"))
                .map(|x| (x.value, x.rating)),
            stack,
            unreachable: match &report.outcome {
                Outcome::Unreachable { reason } => Some(safe(reason)),
                _ => None,
            },
            found: all_findings(report)
                .into_iter()
                .filter(|f| f.severity >= Severity::Medium)
                .map(|f| Found {
                    severity: f.severity,
                    id: f.id,
                    title: safe(&f.title),
                })
                .collect(),
        }
    }

    fn expires_soon(&self) -> bool {
        self.tls_days.is_some_and(|d| d < SOON)
    }
}

struct Row {
    /// The host as typed, clean.
    label: String,
    site: Option<Site>,
    /// Nothing more will change in the row.
    full: bool,
    /// Some event for the site has arrived.
    started: bool,
    /// Why the row ended without a report.
    end: Option<End>,
}

/// How a row ended when no report came for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum End {
    /// The analysis died after the collection.
    Gone,
    /// The run was interrupted before the site started.
    NotStarted,
    /// The run was interrupted while the site was being collected.
    Interrupted,
}

/// The batch table's state; the CLI feeds it the reports and draws what it returns.
pub(crate) struct BatchView {
    rows: Vec<Row>,
    browser: bool,
    /// Rows already handed to the scrollback by `take_finished`.
    committed: usize,
    /// The widest site name, in columns.
    widest: usize,
}

/// Which columns a width leaves room for.
struct Layout {
    site: usize,
    /// `None` when the stack column is dropped.
    stack: Option<usize>,
}

impl BatchView {
    pub(crate) fn new(inputs: &[String], browser: bool) -> Self {
        let rows: Vec<Row> = inputs
            .iter()
            .map(|input| Row {
                label: host_of(input),
                site: None,
                full: false,
                started: false,
                end: None,
            })
            .collect();
        let widest = rows.iter().map(|r| display_width(&r.label)).max().unwrap_or(0).max(4);
        BatchView {
            rows,
            browser,
            committed: 0,
            widest,
        }
    }

    /// Something happened for the site: it left the queue.
    pub(crate) fn on_started(&mut self, index: usize) {
        if let Some(row) = self.rows.get_mut(index) {
            row.started = true;
        }
    }

    /// The analysis of the site died, so no report will come. A row that already has its
    /// fast data keeps it and stops waiting for the browser.
    pub(crate) fn on_gone(&mut self, index: usize) {
        let Some(row) = self.rows.get_mut(index) else {
            return;
        };
        if row.site.is_none() {
            row.end = Some(End::Gone);
        }
        row.full = true;
    }

    /// The channel closed: every row that is not final becomes final, in place. A row with
    /// fast data keeps it (its browser never answered); one without is `interrupted` if its
    /// site had started and `not started` if not.
    pub(crate) fn end_unfinished(&mut self) {
        for row in self.rows.iter_mut().filter(|r| !r.full) {
            if row.site.is_none() {
                row.end = Some(if row.started { End::Interrupted } else { End::NotStarted });
            }
            row.full = true;
        }
    }

    /// Whether some row is still waiting for its report: a spinner is on screen.
    pub(crate) fn pending(&self) -> bool {
        self.committed < self.rows.len()
    }

    /// The report without the browser's part (or the only report, when there is no browser).
    /// With `--browser` the row waits for `on_full`: the LCP cell spins until then. A site
    /// that did not answer never gets a browser run, so its row is final right away.
    pub(crate) fn on_fast(&mut self, index: usize, report: &Report) {
        let browser = self.browser;
        let Some(row) = self.rows.get_mut(index).filter(|r| !r.full) else {
            return;
        };
        let site = Site::of(report);
        row.full = !browser || site.unreachable.is_some();
        row.site = Some(site);
    }

    /// The complete report, browser included.
    pub(crate) fn on_full(&mut self, index: usize, report: &Report) {
        let Some(row) = self.rows.get_mut(index) else {
            return;
        };
        row.site = Some(Site::of(report));
        row.full = true;
    }

    /// The rows that are final and whose predecessors are too, as permanent lines. Each row
    /// comes out once; the first call that returns anything starts with the column header.
    ///
    /// A committed row can never change, so with `--browser` a row stays here until its full
    /// report is in, even though its fast data is long final: its LCP cell is still
    /// spinning. Rows behind it wait with it, in the live region.
    pub(crate) fn take_finished(&mut self, width: usize, theme: &Theme) -> Vec<String> {
        let layout = self.layout(width);
        let mut out = Vec::new();
        while self.rows.get(self.committed).is_some_and(|r| r.full) {
            if self.committed == 0 {
                out.push(self.header(&layout, width, theme));
            }
            out.push(self.line(self.committed, 0, &layout, width, theme));
            self.committed += 1;
        }
        out
    }

    /// The live region: the header until something is committed, then the rows that are not
    /// in the scrollback, in input order. At most `height - 2` lines; rows that do not fit
    /// are counted on a last `+N waiting` line.
    pub(crate) fn frame(&self, tick: usize, width: usize, height: usize, theme: &Theme) -> Vec<String> {
        let layout = self.layout(width);
        let limit = height.saturating_sub(2).max(1);
        let mut out = Vec::new();
        if self.committed == 0 && limit >= 3 {
            out.push(self.header(&layout, width, theme));
        }
        let live = self.committed..self.rows.len();
        let room = limit - out.len();
        let shown = if live.len() <= room { live.len() } else { room - 1 };
        for i in live.start..live.start + shown {
            out.push(self.line(i, tick, &layout, width, theme));
        }
        if shown < live.len() {
            let text = format!("+{} waiting", live.len() - shown);
            out.push(clip(
                &format!("{}{}", " ".repeat(INDENT), theme.dim(&text)),
                width.saturating_sub(1),
            ));
        }
        out
    }

    /// A blank line, then `N sites in T s   grades <badges>   <alerts>`, wrapped at the width.
    /// Without the wall time (`--from` does not know it) the ` in T s` part is left out.
    pub(crate) fn summary_lines(&self, elapsed: Option<Duration>, width: usize, theme: &Theme) -> Vec<String> {
        let n = self.rows.len();
        let mut head = theme.bold(&format!("{n} site{}", if n == 1 { "" } else { "s" }));
        if let Some(elapsed) = elapsed {
            head = format!(
                "{head} {} {}",
                theme.dim("in"),
                theme.bold(&format!("{:.1} s", elapsed.as_secs_f64()))
            );
        }
        // Gap before each part, and the part. Badges sit one space apart.
        let mut parts = vec![(0, head), (3, theme.dim("grades"))];
        for row in &self.rows {
            let badge = match row.site.as_ref().and_then(|s| s.grade) {
                Some(grade) => theme.badge(grade),
                None => grade_dash(theme),
            };
            parts.push((1, badge));
        }
        let sites = || self.rows.iter().filter_map(|r| r.site.as_ref());
        let soon = sites().filter(|s| s.expires_soon()).count();
        if soon > 0 {
            let text = if soon == 1 {
                "1 certificate expires in under 30 days".to_owned()
            } else {
                format!("{soon} certificates expire in under 30 days")
            };
            parts.push((3, theme.yellow(&text)));
        }
        let unreachable = sites().filter(|s| s.unreachable.is_some()).count();
        if unreachable > 0 {
            parts.push((3, theme.red(&format!("{unreachable} unreachable"))));
        }
        let mut lines = vec![String::new()];
        lines.extend(wrap(parts, width.saturating_sub(1)));
        lines
    }

    /// A blank line, then, for each site with a Medium or worse finding, its name in bold
    /// and one line per such finding. Empty when no site has one.
    pub(crate) fn findings_lines(&self, width: usize, theme: &Theme) -> Vec<String> {
        // Findings sit two columns under their site.
        let inner = width.saturating_sub(INDENT);
        let mut out = Vec::new();
        for row in &self.rows {
            let Some(site) = row.site.as_ref().filter(|s| !s.found.is_empty()) else {
                continue;
            };
            let id_width = site.found.iter().map(|f| f.id.len()).max().unwrap_or(0);
            let room = title_room(inner, id_width);
            let titles: Vec<String> = site.found.iter().map(|f| fit(&f.title, room, theme)).collect();
            let longest = titles.iter().map(|t| display_width(t)).max().unwrap_or(0);
            let name = cut(&row.label, width.saturating_sub(INDENT + 1), theme);
            out.push(format!("{}{}", " ".repeat(INDENT), theme.bold(&name)));
            for (f, title) in site.found.iter().zip(&titles) {
                let line = finding_line(f.severity, f.id, title, longest, inner, theme);
                out.push(format!("{}{line}", " ".repeat(INDENT)));
            }
        }
        if !out.is_empty() {
            out.insert(0, String::new());
        }
        out
    }

    /// The columns that fit `width`. Below `COMPACT` the stack goes first; if the others
    /// still do not fit, the site name is cut.
    fn layout(&self, width: usize) -> Layout {
        let avail = width.saturating_sub(1);
        let mut tail = GAP + TIME + GAP + GRADE + GAP + TLS;
        if self.browser {
            tail += GAP + LCP;
        }
        let room = avail.saturating_sub(INDENT + tail);
        if width >= COMPACT && room >= self.widest.min(MIN_SITE) + GAP + MIN_STACK {
            let site = self.widest.min(room - GAP - MIN_STACK);
            Layout {
                site,
                stack: Some(room - site - GAP),
            }
        } else {
            Layout {
                site: self.widest.min(room.max(1)),
                stack: None,
            }
        }
    }

    /// The dim column names.
    fn header(&self, layout: &Layout, width: usize, theme: &Theme) -> String {
        let mut cells = vec![
            (theme.dim("site"), layout.site),
            (theme.dim("time"), TIME),
            (theme.dim("grade"), GRADE),
            (theme.dim("tls"), TLS),
        ];
        if self.browser {
            cells.push((theme.dim("LCP"), LCP));
        }
        if layout.stack.is_some() {
            cells.push((theme.dim("stack"), 0));
        }
        join(&cells, width)
    }

    /// Row `i`: a spinner in the time column while the site is pending, dashes elsewhere.
    fn line(&self, i: usize, tick: usize, layout: &Layout, width: usize, theme: &Theme) -> String {
        let row = &self.rows[i];
        let dash = || theme.dim(theme.glyph(Glyph::Skipped));
        let no_grade = || grade_dash(theme);
        let mut cells = vec![(cut(&row.label, layout.site, theme), layout.site)];
        if let Some(end) = row.end {
            // No report: the verdict spans time, grade and tls.
            let verdict = match end {
                End::Gone => analysis_failed(theme),
                End::NotStarted => theme.dim("not started"),
                End::Interrupted => theme.yellow("interrupted"),
            };
            cells.push((verdict, TIME + GAP + GRADE + GAP + TLS));
            if self.browser {
                cells.push((dash(), LCP));
            }
            if layout.stack.is_some() {
                cells.push((dash(), 0));
            }
            return join(&cells, width);
        }
        let Some(site) = &row.site else {
            cells.push((theme.cyan(theme.spinner(tick + i)), TIME));
            cells.extend([(no_grade(), GRADE), (dash(), TLS)]);
            if self.browser {
                cells.push((dash(), LCP));
            }
            if layout.stack.is_some() {
                cells.push((dash(), 0));
            }
            return join(&cells, width);
        };
        cells.push((theme.cyan(&format!("{:.1} s", site.seconds)), TIME));
        if let Some(reason) = &site.unreachable {
            // The verdict spans grade and tls; the reason takes the stack's place.
            cells.push((theme.red("unreachable"), GRADE + GAP + TLS));
            if self.browser {
                cells.push((dash(), LCP));
            }
            if let Some(room) = layout.stack {
                cells.push((theme.dim(&cut(reason, room, theme)), 0));
            }
            return join(&cells, width);
        }
        cells.push((site.grade.map_or_else(no_grade, |g| theme.badge(g)), GRADE));
        cells.push((tls_cell(site.tls_days, theme), TLS));
        if self.browser {
            let lcp = match (row.full, site.lcp) {
                (false, _) => theme.cyan(theme.spinner(tick + i)),
                (true, Some((value, quality))) => rating(quality).1(theme, &metric_value("lcp", value)),
                (true, None) => dash(),
            };
            cells.push((lcp, LCP));
        }
        if let Some(room) = layout.stack {
            let stack = if site.stack.is_empty() {
                dash()
            } else {
                cut(&site.stack.join(" · "), room, theme)
            };
            cells.push((stack, 0));
        }
        join(&cells, width)
    }
}

/// A missing grade: a dash as wide as a badge, so it sits under the badges' letters.
fn grade_dash(theme: &Theme) -> String {
    theme.dim(&format!(" {} ", theme.glyph(Glyph::Skipped)))
}

/// The red verdict for a site whose analysis died, in the table and as a line of its own.
pub(super) fn analysis_failed(theme: &Theme) -> String {
    theme.red(&format!("{} analysis failed", theme.glyph(Glyph::Bad)))
}

/// The days left on the certificate, yellow under `SOON` and red once expired.
fn tls_cell(days: Option<i64>, theme: &Theme) -> String {
    let Some(days) = days else {
        return theme.dim(theme.glyph(Glyph::Skipped));
    };
    let text = format!("{days} days");
    let paint: Option<Paint> = match days {
        d if d < 0 => Some(Theme::red),
        d if d < SOON => Some(Theme::yellow),
        _ => None,
    };
    paint.map_or(text.clone(), |p| p(theme, &text))
}

/// The cells side by side, each padded to its width (0 for the last, which is not padded),
/// and the line cut to the columns the terminal may take (never the last one).
fn join(cells: &[(String, usize)], width: usize) -> String {
    let mut out = " ".repeat(INDENT);
    for (i, (text, cols)) in cells.iter().enumerate() {
        out.push_str(text);
        if i + 1 < cells.len() {
            out.push_str(&" ".repeat(cols.saturating_sub(display_width(text)) + GAP));
        }
    }
    clip(&out, width.saturating_sub(1))
}

/// At most `cols` columns, an ellipsis in the last when cut.
fn cut(text: &str, cols: usize, theme: &Theme) -> String {
    if display_width(text) <= cols {
        return text.to_owned();
    }
    let dots = if theme.unicode { "…" } else { "..." };
    let room = cols.saturating_sub(display_width(dots));
    let mut out = String::new();
    for c in text.chars() {
        if display_width(&out) + display_width(c.encode_utf8(&mut [0; 4])) > room {
            break;
        }
        out.push(c);
    }
    out.push_str(dots);
    // Too narrow even for the dots: whatever of them fits.
    if display_width(&out) > cols {
        return dots.chars().take(cols).collect();
    }
    out
}

/// Parts (each with the gap before it) on lines of at most `limit` columns; a line that
/// continues starts at the indent.
fn wrap(parts: Vec<(usize, String)>, limit: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = " ".repeat(INDENT);
    let mut fresh = true;
    for (gap, part) in parts {
        let gap = if fresh { 0 } else { gap };
        if !fresh && display_width(&line) + gap + display_width(&part) > limit {
            lines.push(std::mem::replace(&mut line, " ".repeat(INDENT)));
            fresh = true;
        }
        line.push_str(&" ".repeat(if fresh { 0 } else { gap }));
        line.push_str(&part);
        fresh = false;
    }
    lines.push(line);
    lines
}

#[cfg(test)]
mod tests {
    use insite_core::analyze::stack::Stack;
    use insite_core::detect::TechOrigin;
    use insite_core::report::{Module, Outcome, Report, Severity, Status};

    use super::*;
    use crate::live::browser::tests::browser_report;
    use crate::live::site::tests::{every_escape_is_sgr, plain, strip};
    use crate::render::tests::{HOSTILE, finding, full_report, hostile_report};
    use crate::stackview::tests::tech;

    fn ascii() -> Theme {
        Theme::plain_ascii()
    }

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("site{i}.example")).collect()
    }

    /// A finished site: grade, days left on the certificate and duration in ms.
    fn report(grade: &'static str, days: i64, ms: f64) -> Report {
        let mut r = full_report();
        r.duration_ms = ms;
        r.modules.security.data.as_mut().unwrap().grade = Some(grade);
        r.modules
            .tls
            .data
            .as_mut()
            .unwrap()
            .certificate
            .as_mut()
            .unwrap()
            .days_remaining = days;
        r
    }

    fn unreachable(reason: &str) -> Report {
        let mut r = hostile_report();
        r.duration_ms = 1500.0;
        r.outcome = Outcome::Unreachable {
            reason: reason.to_owned(),
        };
        r
    }

    fn with_stack(mut r: Report, techs: &[&str]) -> Report {
        r.modules.stack = Module {
            status: Status::Ok,
            reason: None,
            data: Some(Stack {
                technologies: techs.iter().map(|n| tech(n, 5, TechOrigin::Page)).collect(),
                signatures: "test".to_owned(),
                rendered: None,
            }),
            findings: Vec::new(),
        };
        r
    }

    fn view(inputs: &[&str], browser: bool) -> BatchView {
        let inputs: Vec<String> = inputs.iter().map(|s| (*s).to_owned()).collect();
        BatchView::new(&inputs, browser)
    }

    #[test]
    fn a_missing_grade_is_centred_under_the_badges() {
        let theme = ascii();
        let mut graded = report("B", 60, 800.0);
        graded.modules.security.status = Status::Failed;
        let mut v = view(&["a.example", "b.example", "c.example"], false);
        v.on_fast(0, &report("B", 60, 800.0));
        v.on_fast(1, &graded);
        let rows = plain(&v.take_finished(100, &theme));
        let badge_at = rows[1].find(" B ").unwrap() + 1;
        let dash_at = rows[2].find(" - ").expect("a dash cell as wide as a badge") + 1;
        assert_eq!(badge_at, dash_at, "{rows:#?}");
        // A row still waiting has the same cell.
        let wait = plain(&v.frame(0, 100, 24, &theme));
        assert!(
            wait.iter().any(|l| l.contains("c.example") && l.contains(" - ")),
            "{wait:#?}"
        );
        let unicode = Theme {
            truecolor: false,
            unicode: true,
        };
        let mut v = view(&["a.example"], false);
        v.on_fast(0, &graded);
        assert!(plain(&v.take_finished(100, &unicode))[1].contains(" – "));
    }

    #[test]
    fn credentials_typed_in_the_url_never_reach_a_row() {
        let theme = ascii();
        let mut v = view(&["https://user:s3cret@a.example:8443/x", "b.example"], false);
        v.on_fast(0, &report("B", 60, 800.0));
        v.on_fast(1, &report("A", 60, 800.0));
        let mut all = v.take_finished(100, &theme);
        all.extend(v.summary_lines(None, 100, &theme));
        all.extend(v.findings_lines(100, &theme));
        let text = plain(&all).join("\n");
        assert!(text.contains("a.example:8443"), "{text}");
        assert!(!text.contains("s3cret") && !text.contains("user:"), "{text}");
        // Nor in the pending row of the live frame.
        let v = view(&["https://user:s3cret@a.example/"], false);
        assert!(!plain(&v.frame(0, 100, 24, &theme)).join("\n").contains("s3cret"));
    }

    #[test]
    fn rows_reach_the_scrollback_in_input_order() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com", "c.com"], false);
        v.on_fast(1, &report("B", 60, 800.0));
        assert!(v.take_finished(100, &theme).is_empty());
        v.on_fast(0, &report("A", 60, 400.0));
        let done = plain(&v.take_finished(100, &theme));
        // The header, then both rows in input order; row c is still pending.
        assert_eq!(done.len(), 3, "{done:#?}");
        assert!(done[0].contains("site") && done[0].contains("time"), "{done:#?}");
        assert!(done[1].contains("a.com") && done[2].contains("b.com"), "{done:#?}");
        // Each row is returned once.
        assert!(v.take_finished(100, &theme).is_empty());
        v.on_fast(2, &report("C", 60, 900.0));
        let done = plain(&v.take_finished(100, &theme));
        assert_eq!(done.len(), 1, "no second header: {done:#?}");
        assert!(done[0].contains("c.com"), "{done:#?}");
    }

    #[test]
    fn the_header_is_in_the_frame_until_something_is_committed() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com"], false);
        let before = plain(&v.frame(0, 100, 20, &theme));
        assert!(before[0].contains("site") && before[0].contains("grade"), "{before:#?}");
        assert_eq!(before.len(), 3);
        v.on_fast(0, &report("A", 60, 400.0));
        v.take_finished(100, &theme);
        let after = plain(&v.frame(0, 100, 20, &theme));
        assert_eq!(after.len(), 1, "{after:#?}");
        assert!(after[0].contains("b.com"), "{after:#?}");
    }

    #[test]
    fn a_pending_row_spins_in_the_time_column() {
        let theme = ascii();
        let v = view(&["a.com"], false);
        let row = |tick| plain(&v.frame(tick, 100, 20, &theme)).remove(1);
        assert!(row(0).contains("a.com  |"), "{}", row(0));
        assert!(row(1).contains("a.com  /"), "{}", row(1));
        // The other cells hold a dash.
        assert_eq!(row(0).matches('-').count(), 3, "{}", row(0));
    }

    #[test]
    fn a_finished_row_shows_time_grade_tls_and_the_first_three_technologies() {
        let theme = ascii();
        let mut v = view(&["example.com"], false);
        let r = with_stack(report("B", 85, 1400.0), &["Alpha", "Beta", "Cetus", "Delta"]);
        v.on_fast(0, &r);
        let rows = plain(&v.take_finished(100, &theme));
        let row = &rows[1];
        assert!(row.contains("1.4 s"), "{row}");
        assert!(row.contains(" B "), "{row}");
        assert!(row.contains("85 days"), "{row}");
        assert!(row.contains("Alpha · Beta · Cetus") && !row.contains("Delta"), "{row}");
    }

    #[test]
    fn certificates_turn_yellow_under_30_days_and_red_when_expired() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com", "c.com"], false);
        for (i, days) in [85, 12, -3].into_iter().enumerate() {
            v.on_fast(i, &report("B", days, 100.0));
        }
        let rows = v.take_finished(100, &theme);
        assert!(!rows[1].contains(&theme.yellow("85 days")) && !rows[1].contains(&theme.red("85 days")));
        assert!(rows[2].contains(&theme.yellow("12 days")), "{:?}", rows[2]);
        assert!(rows[3].contains(&theme.red("-3 days")), "{:?}", rows[3]);
    }

    #[test]
    fn frame_never_exceeds_the_height() {
        let theme = ascii();
        let inputs = names(200);
        let mut v = BatchView::new(&inputs, false);
        for height in [3, 5, 20, 50] {
            let lines = v.frame(0, 100, height, &theme);
            assert!(
                lines.len() <= height.saturating_sub(2).max(1),
                "{height}: {}",
                lines.len()
            );
        }
        let lines = plain(&v.frame(0, 100, 20, &theme));
        assert_eq!(lines.last().unwrap().trim(), "+184 waiting", "{lines:#?}");
        // Finished rows leave the live region; the ones behind them move up.
        for i in 0..10 {
            v.on_fast(i, &report("A", 60, 100.0));
        }
        assert_eq!(v.take_finished(100, &theme).len(), 11);
        let lines = plain(&v.frame(0, 100, 20, &theme));
        assert!(lines.len() <= 18, "{}", lines.len());
        assert!(lines[0].contains("site10."), "{lines:#?}");
        assert_eq!(lines.last().unwrap().trim(), "+173 waiting", "{lines:#?}");
        // Finished rows that wait for a predecessor count as waiting too.
        v.on_fast(12, &report("A", 60, 100.0));
        let lines = plain(&v.frame(0, 100, 20, &theme));
        assert!(lines.iter().any(|l| l.contains("site12.")), "{lines:#?}");
        assert!(v.take_finished(100, &theme).is_empty());
    }

    #[test]
    fn a_batch_that_fits_has_no_waiting_line() {
        let theme = ascii();
        let v = BatchView::new(&names(5), false);
        let lines = plain(&v.frame(0, 100, 20, &theme));
        assert_eq!(lines.len(), 6, "{lines:#?}");
        assert!(!lines.iter().any(|l| l.contains("waiting")));
    }

    #[test]
    fn browser_column_spins_until_full() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com"], true);
        let lcp = |lines: &[String], row: usize| plain(lines)[row].clone();
        // Pending rows: nothing known yet.
        let lines = v.frame(0, 100, 20, &theme);
        assert!(lcp(&lines, 0).contains("LCP"), "{lines:#?}");
        // The fast report: everything but LCP is final, and LCP spins.
        let fast = report("A", 60, 400.0);
        v.on_fast(0, &fast);
        let row = |v: &BatchView, tick| plain(&v.frame(tick, 100, 20, &theme))[1].clone();
        assert!(
            row(&v, 0).contains("0.4 s") && row(&v, 0).contains("60 days"),
            "{}",
            row(&v, 0)
        );
        assert!(row(&v, 0).contains("|"), "{}", row(&v, 0));
        assert!(row(&v, 1).contains("/"), "{}", row(&v, 1));
        // A committed row cannot change, so it stays in the live region until it is full.
        assert!(v.take_finished(100, &theme).is_empty());
        // Row b is full first, but it waits for a.
        v.on_full(1, &browser_report());
        assert!(v.take_finished(100, &theme).is_empty());
        // Full: the value replaces the spinner and both rows go down in order.
        v.on_full(0, &browser_report());
        let done = plain(&v.take_finished(100, &theme));
        assert_eq!(done.len(), 3, "{done:#?}");
        assert!(done[1].contains("a.com") && done[1].contains("1.9 s"), "{done:#?}");
        assert!(done[2].contains("b.com") && done[2].contains("1.9 s"), "{done:#?}");
        assert!(done[0].contains("LCP"), "{done:#?}");
    }

    #[test]
    fn the_lcp_value_takes_the_rating_color() {
        let theme = ascii();
        let mut v = view(&["a.com"], true);
        v.on_full(0, &browser_report());
        let row = v.take_finished(100, &theme).remove(1);
        assert!(row.contains(&theme.green("1.9 s")), "{row:?}");
    }

    #[test]
    fn an_unreachable_site_needs_no_browser() {
        let theme = ascii();
        let mut v = view(&["a.com"], true);
        v.on_fast(0, &unreachable("connection refused"));
        let done = plain(&v.take_finished(100, &theme));
        assert_eq!(done.len(), 2, "{done:#?}");
    }

    #[test]
    fn a_browser_without_lcp_shows_a_dash() {
        let theme = ascii();
        let mut v = view(&["a.com"], true);
        v.on_full(0, &report("A", 60, 400.0));
        let rows = plain(&v.take_finished(100, &theme));
        let after = rows[1].split("60 days").nth(1).unwrap();
        assert!(after.trim_start().starts_with('-'), "{rows:#?}");
    }

    #[test]
    fn the_unreachable_row_is_red_and_gives_the_reason() {
        let theme = ascii();
        let mut v = view(&["a.com"], false);
        v.on_fast(0, &unreachable("connection refused"));
        let rows = v.take_finished(100, &theme);
        let row = &rows[1];
        assert!(row.contains(&theme.red("unreachable")), "{row:?}");
        let text = strip(row);
        assert!(
            text.contains("unreachable") && text.contains("connection refused"),
            "{text}"
        );
        assert!(text.contains("1.5 s"), "{text}");
        // Without the stack column the reason goes, the verdict stays.
        let mut v = view(&["a.com"], false);
        v.on_fast(0, &unreachable("connection refused"));
        let text = plain(&v.take_finished(50, &theme)).remove(1);
        assert!(text.contains("unreachable") && !text.contains("refused"), "{text}");
    }

    #[test]
    fn narrow_terminal_drops_the_stack_column() {
        let theme = ascii();
        let build = || {
            let mut v = view(&["example.com", "other.org"], false);
            let r = with_stack(report("B", 85, 1400.0), &["Alpha", "Beta"]);
            v.on_fast(0, &r);
            v.on_fast(1, &r);
            v
        };
        let wide = plain(&build().take_finished(100, &theme));
        assert!(wide[0].contains("stack") && wide[1].contains("Alpha"), "{wide:#?}");
        let narrow = plain(&build().take_finished(59, &theme));
        assert!(
            !narrow[0].contains("stack") && !narrow[1].contains("Alpha"),
            "{narrow:#?}"
        );
        assert!(
            narrow[1].contains("example.com") && narrow[1].contains("85 days"),
            "{narrow:#?}"
        );
    }

    #[test]
    fn no_row_is_wider_than_the_terminal() {
        let theme = Theme::from_vars(None, Some("en_US.UTF-8"), None, None);
        let long = format!("https://{}.example.com/path", "very-long-host-name".repeat(4));
        let inputs = vec![long, "日本語のサイト.jp".to_owned(), "a.com".to_owned()];
        for browser in [false, true] {
            for width in [10, 24, 40, 59, 60, 61, 80, 120] {
                let mut v = BatchView::new(&inputs, browser);
                let before = v.frame(0, width, 20, &theme);
                let r = with_stack(
                    report("A+", 85, 123_400.0),
                    &["Some very long technology name", "B", "C"],
                );
                for i in 0..3 {
                    v.on_full(i, &r);
                }
                let lines = [before, v.take_finished(width, &theme), v.frame(0, width, 20, &theme)].concat();
                for line in lines {
                    assert!(
                        display_width(&line) < width.max(2),
                        "{width}: {} wide: {:?}",
                        display_width(&line),
                        strip(&line)
                    );
                }
            }
        }
    }

    #[test]
    fn a_gone_row_is_final_and_red() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com"], false);
        v.on_gone(0);
        v.on_fast(1, &report("A", 60, 400.0));
        let done = plain(&v.take_finished(100, &theme));
        assert_eq!(done.len(), 3, "{done:#?}");
        assert!(
            done[1].contains("a.com") && done[1].contains("x analysis failed"),
            "{done:#?}"
        );
        assert!(done[2].contains("b.com") && done[2].contains("0.4 s"), "{done:#?}");
        // The summary shows a skipped badge for the row with no report.
        assert!(plain(&v.summary_lines(None, 100, &theme))[1].contains("grades"));
    }

    #[test]
    fn a_gone_site_with_fast_data_keeps_it() {
        let theme = ascii();
        let mut v = view(&["a.com"], true);
        v.on_fast(0, &report("A", 60, 400.0));
        assert!(v.take_finished(100, &theme).is_empty(), "still waiting for the browser");
        v.on_gone(0);
        let done = plain(&v.take_finished(100, &theme));
        assert!(
            done[1].contains("0.4 s") && !done[1].contains("analysis failed"),
            "{done:#?}"
        );
    }

    #[test]
    fn unfinished_rows_end_as_not_started_or_interrupted_in_order() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com", "c.com", "d.com"], true);
        v.on_fast(0, &report("A", 60, 400.0));
        v.on_started(1);
        v.on_fast(3, &unreachable("refused"));
        assert!(v.pending());
        v.end_unfinished();
        let done = plain(&v.take_finished(100, &theme));
        assert_eq!(done.len(), 5, "{done:#?}");
        // Row a had fast data: it keeps it, with no spinner in the LCP column.
        assert!(done[1].contains("a.com") && done[1].contains("0.4 s"), "{done:#?}");
        assert!(
            done[2].contains("b.com") && done[2].contains("interrupted"),
            "{done:#?}"
        );
        assert!(
            done[3].contains("c.com") && done[3].contains("not started"),
            "{done:#?}"
        );
        assert!(
            done[4].contains("d.com") && done[4].contains("unreachable"),
            "{done:#?}"
        );
        assert!(!v.pending());
        assert!(v.frame(0, 100, 20, &theme).is_empty());
    }

    #[test]
    fn the_summary_without_a_time_leaves_out_the_duration() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com"], false);
        v.on_fast(0, &report("A", 60, 400.0));
        let timed = plain(&v.summary_lines(Some(Duration::from_millis(2340)), 100, &theme));
        let untimed = plain(&v.summary_lines(None, 100, &theme));
        assert!(timed[1].starts_with("  2 sites in 2.3 s"), "{timed:#?}");
        assert!(untimed[1].starts_with("  2 sites   grades"), "{untimed:#?}");
    }

    #[test]
    fn a_long_site_name_is_cut_with_an_ellipsis() {
        let ascii_theme = ascii();
        let long = format!("{}.com", "x".repeat(60));
        let mut v = BatchView::new(&[long], false);
        v.on_fast(0, &report("A", 60, 100.0));
        let row = plain(&v.take_finished(70, &ascii_theme)).remove(1);
        assert!(row.contains("xxx...") && !row.contains(".com"), "{row}");
        let unicode = Theme::from_vars(None, Some("en_US.UTF-8"), None, None);
        let mut v = BatchView::new(&["x".repeat(80)], false);
        v.on_fast(0, &report("A", 60, 100.0));
        assert!(plain(&v.take_finished(70, &unicode)).remove(1).contains("x…"));
    }

    #[test]
    fn summary_counts_grades_and_alerts() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com", "c.com", "d.com", "e.com"], false);
        v.on_fast(0, &report("B", 60, 100.0));
        v.on_fast(1, &report("C", 12, 100.0));
        v.on_fast(2, &report("F", -4, 100.0));
        v.on_fast(3, &unreachable("timeout"));
        let lines = v.summary_lines(Some(Duration::from_millis(2340)), 120, &theme);
        assert_eq!(strip(&lines[0]), "", "{lines:#?}");
        assert_eq!(
            strip(&lines[1]),
            "  5 sites in 2.3 s   grades  B   C   F   -   -    2 certificates expire in under 30 days   1 unreachable",
            "{lines:#?}"
        );
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains(&theme.badge("F")));
        assert!(lines[1].contains(&theme.yellow("2 certificates expire in under 30 days")));
        assert!(lines[1].contains(&theme.red("1 unreachable")));
    }

    #[test]
    fn a_clean_batch_has_no_alerts() {
        let theme = ascii();
        let mut v = view(&["a.com"], false);
        v.on_fast(0, &report("A", 60, 100.0));
        let lines = plain(&v.summary_lines(Some(Duration::from_secs(1)), 100, &theme));
        assert_eq!(lines[1], "  1 site in 1.0 s   grades  A ", "{lines:#?}");
        // One certificate reads in the singular.
        let mut v = view(&["a.com"], false);
        v.on_fast(0, &report("A", 5, 100.0));
        let lines = plain(&v.summary_lines(Some(Duration::from_secs(1)), 100, &theme));
        assert!(
            lines[1].ends_with("1 certificate expires in under 30 days"),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_long_summary_wraps_at_the_width() {
        let theme = ascii();
        let mut v = BatchView::new(&names(30), false);
        for i in 0..30 {
            v.on_fast(i, &report("A", 5, 100.0));
        }
        let lines = v.summary_lines(Some(Duration::from_secs(9)), 50, &theme);
        assert!(lines.len() > 3, "{lines:#?}");
        assert!(lines.iter().all(|l| display_width(l) < 50), "{lines:#?}");
        assert!(
            plain(&lines)
                .join(" ")
                .contains("30 certificates expire in under 30 days")
        );
    }

    #[test]
    fn findings_are_grouped_by_site() {
        let theme = ascii();
        let mut v = view(&["a.com", "b.com", "c.com"], false);
        let mut a = full_report();
        a.modules.seo.findings = vec![
            finding("seo.title.missing", Severity::High, "No title"),
            finding("seo.desc.missing", Severity::Low, "No description"),
        ];
        let clean = {
            let mut r = full_report();
            r.modules.security.findings.clear();
            r.modules.weight.findings.clear();
            r
        };
        // full_report already has one Medium and two Low findings.
        v.on_fast(0, &a);
        v.on_fast(1, &clean);
        v.on_fast(2, &report("A", 60, 100.0));
        let lines = plain(&v.findings_lines(100, &theme));
        assert_eq!(lines[0], "", "{lines:#?}");
        let site_a = lines.iter().position(|l| l.trim() == "a.com").expect("a.com");
        let site_c = lines.iter().position(|l| l.trim() == "c.com").expect("c.com");
        assert!(
            site_a < site_c && !lines.iter().any(|l| l.trim() == "b.com"),
            "{lines:#?}"
        );
        // Per site, highest first, Medium and above only, with the id.
        assert!(
            lines[site_a + 1].contains("high") && lines[site_a + 1].contains("seo.title.missing"),
            "{lines:#?}"
        );
        assert!(
            lines[site_a + 2].contains("medium") && lines[site_a + 2].contains("sec.csp.unsafe_inline"),
            "{lines:#?}"
        );
        for id in ["seo.desc.missing", "sec.cookies.insecure_hsts", "weight.html_large"] {
            assert!(!lines.iter().any(|l| l.contains(id)), "{id}: {lines:#?}");
        }
        assert_eq!(site_c, site_a + 3, "{lines:#?}");
        assert_eq!(lines.len(), site_c + 2, "{lines:#?}");
        // The site line is bold; the finding lines sit under it.
        let raw = v.findings_lines(100, &theme);
        assert!(raw[site_a].contains(&theme.bold("a.com")), "{:?}", raw[site_a]);
    }

    #[test]
    fn no_findings_means_no_lines() {
        let theme = ascii();
        let mut v = view(&["a.com"], false);
        let mut r = full_report();
        r.modules.security.findings.clear();
        v.on_fast(0, &r);
        assert!(v.findings_lines(100, &theme).is_empty());
        assert!(view(&["a.com"], false).findings_lines(100, &theme).is_empty());
    }

    #[test]
    fn hostile_text_cannot_escape() {
        let theme = Theme::from_vars(Some("truecolor"), Some("en_US.UTF-8"), None, None);
        let hostile = format!("https://evil{HOSTILE}.com/");
        let mut v = BatchView::new(&[hostile, "b.com".to_owned()], true);
        let a = with_stack(unreachable(HOSTILE), &[HOSTILE]);
        let b = with_stack(hostile_report(), &[HOSTILE, "Alpha"]);
        let mut all = v.frame(0, 100, 20, &theme);
        v.on_fast(0, &a);
        v.on_fast(1, &b);
        all.extend(v.frame(0, 100, 20, &theme));
        v.on_full(1, &b);
        all.extend(v.take_finished(100, &theme));
        v.on_full(0, &a);
        all.extend(v.take_finished(100, &theme));
        all.extend(v.summary_lines(Some(Duration::from_secs(1)), 100, &theme));
        all.extend(v.findings_lines(100, &theme));
        assert!(all.iter().any(|l| l.contains("Alpha")), "{all:#?}");
        for line in &all {
            every_escape_is_sgr(line);
            assert!(!line.contains('\n'), "{line:?}");
        }
        assert!(plain(&all).join("\n").contains("\u{fffd}[2J"));
    }
}
