//! The second act of `--browser`: a spinning `browser` row while Chromium works, then the
//! Core Web Vitals as meters, the request totals and the weight by type.

use insite_core::analyze::browser::{Metric, TypeTotal};
use insite_core::collect::progress::BrowserStage;
use insite_core::report::{Finding, Report, Severity, Status};

use super::site::{
    COMPACT, TEXT_AT, all_findings, finding_line, fit, fit_height, join_sections, mark, mark_glyph, module_row, safe,
    title_room,
};
use super::theme::{Glyph, MeterColor, Theme};
use crate::render::{browser_details_text, bytes, metric_value, summary_lines};
use crate::style::{Style, display_width, neutralize};

/// The least and the most cells the stacked bar gets.
const MIN_BAR: usize = 10;
const MAX_BAR: usize = 40;

/// A painter from the theme: `Theme::cyan` and the like.
pub(super) type Paint = fn(&Theme, &str) -> String;

/// The weight groups in bar order: the name and the color of its segment.
const KINDS: [(&str, Paint); 5] = [
    ("js", Theme::cyan),
    ("images", Theme::magenta),
    ("css", Theme::green),
    ("fonts", Theme::yellow),
    ("other", Theme::dim),
];

/// What the browser has reported so far, for the one spinning row.
pub(crate) struct BrowserView {
    stage: Option<BrowserStage>,
}

impl BrowserView {
    pub(crate) fn new() -> Self {
        BrowserView { stage: None }
    }

    /// Stages may skip (a load timeout goes from navigating to quiet) or stop early (a
    /// navigation error), so the latest one wins and none implies another.
    pub(crate) fn on_stage(&mut self, stage: BrowserStage) {
        self.stage = Some(stage);
    }

    /// The browser process is starting: whatever an earlier run reported no longer holds.
    pub(crate) fn launched(&mut self) {
        self.stage = None;
    }

    /// The `browser` row with a spinner and what Chromium is doing, at most `height - 1`
    /// lines. The report replaces it with `final_lines` when the browser is done.
    pub(crate) fn frame(&self, tick: usize, width: usize, height: usize, theme: &Theme) -> Vec<String> {
        let activity = match self.stage {
            None => "launching",
            Some(BrowserStage::Navigating) => "loading the page",
            Some(BrowserStage::Loaded) => "waiting for the page to settle",
            Some(BrowserStage::Quiet) => "measuring",
        };
        let text = theme.dim(&fit(activity, width.saturating_sub(TEXT_AT + 1), theme));
        fit_height(
            module_row(theme, &theme.cyan(theme.spinner(tick)), "browser", &text),
            height,
            theme,
        )
    }
}

/// What the screen shows above the act, which decides what the act must still say.
#[derive(Clone, Copy)]
pub(crate) enum Above<'a> {
    /// The site block above was drawn from this same report (a saved snapshot, a `-v` batch
    /// or a run whose fast report never came), so the stack and the findings are already
    /// there and the act leaves them out.
    Same,
    /// The site block above was frozen from `fast`, the report before the browser: the act
    /// shows the stack as the browser completed it, and the findings that only the browser
    /// made possible.
    Fast(&'a Report),
}

/// The finished act: a pure function of the report, also for saved snapshots. Empty when
/// the browser was not asked for; verbose appends today's browser details.
pub(crate) fn final_lines(
    report: &Report,
    width: usize,
    theme: &Theme,
    verbose: bool,
    above: Above<'_>,
) -> Vec<String> {
    let module = &report.modules.browser;
    let room = width.saturating_sub(TEXT_AT + 1);
    let reason = safe(module.reason.as_deref().unwrap_or_default());
    // A reason is a fact: it wraps under the label instead of being cut.
    let row = |glyph: String, text: &str, paint: Paint| {
        module_row(theme, &glyph, "browser", &wrapped(text, " ", room, |l| paint(theme, l)))
    };
    let data = match (module.status, &module.data) {
        (Status::Skipped, _) if module.reason.as_deref() == Some("not selected") => return Vec::new(),
        (Status::Skipped, _) => return row(theme.dim(theme.glyph(Glyph::Skipped)), &reason, Theme::dim),
        (Status::Failed | Status::Timeout, _) => {
            let prefix = if module.status == Status::Timeout {
                "timeout: "
            } else {
                ""
            };
            return row(
                theme.red(theme.glyph(Glyph::Bad)),
                &format!("{prefix}{reason}"),
                Theme::red,
            );
        }
        (_, Some(data)) => data,
        (_, None) => return row(mark_glyph(&mark(module), theme), &reason, Theme::dim),
    };

    let mut parts = vec![safe(&data.product), safe(&data.profile)];
    parts.retain(|p| !p.is_empty());
    if let Some(load) = data.load_ms {
        let how = if module.status == Status::Ok {
            "quiet after"
        } else {
            "loaded after"
        };
        parts.push(format!("{how} {:.1} s", load / 1000.0));
    }
    let head = module_row(
        theme,
        &mark_glyph(&mark(module), theme),
        "browser",
        &wrapped_parts(&parts, room, theme),
    );

    let mut vitals: Vec<String> = Vec::new();
    let value_width = data
        .metrics
        .iter()
        .map(|m| display_width(&metric_value(m.name, m.value)))
        .max()
        .unwrap_or(0);
    for m in &data.metrics {
        vitals.push(vital_row(m, value_width, width, theme));
    }
    let facts = totals_rows(data, width, theme);
    let weight = weight_rows(&data.by_type, width, theme);
    let rows = [vitals, facts, weight].concat();

    let stack = (matches!(above, Above::Fast(_)) && report.modules.stack.data.is_some())
        .then(|| {
            // The stack as the browser completed it, in the summary's own 16-colour text.
            let lines = summary_lines(report, &Style::new(true), width.saturating_sub(2), verbose);
            let (_, text) = lines.into_iter().find(|(label, _)| *label == "stack")?;
            let glyph = mark_glyph(&mark(&report.modules.stack), theme);
            Some(module_row(theme, &glyph, "stack", &neutralize(&text, true)))
        })
        .flatten()
        .unwrap_or_default();

    let mut notes = Vec::new();
    if module.status != Status::Ok && !reason.is_empty() {
        let text = crate::render::indent(&format!("browser: {reason}"), 2, width);
        notes.extend(text.lines().map(|l| theme.yellow(l)));
    }
    let mut lines = join_sections([
        [head, rows].concat(),
        stack,
        findings_rows(report, width, theme, verbose, above),
        notes,
    ]);
    if verbose {
        lines.extend(browser_details_text(report, true, width).lines().map(str::to_owned));
    }
    lines
}

/// Cells in a Web Vital's meter.
fn meter_width(width: usize) -> usize {
    if width < COMPACT { 8 } else { 14 }
}

/// The value at which Lighthouse calls the metric poor: where the meter is full.
fn poor_threshold(name: &str) -> Option<f64> {
    match name {
        "lcp" => Some(4000.0),
        "fcp" => Some(3000.0),
        "tbt" => Some(600.0),
        "cls" => Some(0.25),
        _ => None,
    }
}

/// A Lighthouse rating as its label, painter and meter color.
pub(super) fn rating(rating: &str) -> (&'static str, Paint, MeterColor) {
    match rating {
        "good" => ("good", Theme::green, MeterColor::Good),
        "needs_improvement" => ("needs work", Theme::yellow, MeterColor::Warn),
        _ => ("poor", Theme::red, MeterColor::Poor),
    }
}

/// `LCP  ██████░░░░  1.9 s  good`, the meter in the rating's color.
fn vital_row(m: &Metric, value_width: usize, width: usize, theme: &Theme) -> String {
    let (label, paint, color) = rating(m.rating);
    let fraction = poor_threshold(m.name).map_or(0.0, |poor| m.value / poor);
    let value = format!("{:<value_width$}", metric_value(m.name, m.value));
    format!(
        "  {}  {}  {}  {}",
        theme.bold(&format!("{:<3}", m.name.to_uppercase())),
        theme.meter(fraction, meter_width(width), color),
        theme.bold(&value),
        paint(theme, label)
    )
}

/// `requests 87   bytes 2.1 MB   third parties 15 (34% of bytes)`, wrapped when narrow.
fn totals_rows(data: &insite_core::analyze::browser::Browser, width: usize, theme: &Theme) -> Vec<String> {
    let item = |label: &str, value: &str| format!("{} {}", theme.dim(label), theme.bold(value));
    let mut third = item("third parties", &data.third_party_domains.to_string());
    if data.third_party_bytes > 0 {
        third.push_str(&format!(
            " {}",
            theme.dim(&format!("({:.0}% of bytes)", data.third_party_share * 100.0))
        ));
    }
    let items = [
        item("requests", &data.requests.to_string()),
        item("bytes", &bytes(data.transferred_bytes)),
        third,
    ];
    wrap_row(&items, "   ", width.saturating_sub(3))
        .into_iter()
        .map(|l| format!("  {l}"))
        .collect()
}

/// The group of a browser resource type: scripts, images, stylesheets and fonts by name,
/// everything else (documents, XHR, media, unknown) together.
fn group_of(kind: &str) -> usize {
    match kind.to_ascii_lowercase().as_str() {
        "script" | "js" | "javascript" => 0,
        "image" | "images" => 1,
        "stylesheet" | "css" => 2,
        "font" | "fonts" => 3,
        _ => 4,
    }
}

fn group_bytes(totals: &[TypeTotal]) -> [u64; 5] {
    let mut sums = [0u64; 5];
    for t in totals {
        sums[group_of(&t.kind)] += t.bytes;
    }
    sums
}

/// One segment per group with bytes, in the order of `KINDS`, exactly `cells` wide in all and
/// at least one cell each. Empty when there is nothing to draw.
fn stacked_bar(totals: &[TypeTotal], cells: usize, theme: &Theme) -> String {
    let sums = group_bytes(totals);
    let used: Vec<usize> = (0..KINDS.len()).filter(|&i| sums[i] > 0).collect();
    let total: u64 = sums.iter().sum();
    if used.is_empty() || cells < used.len() {
        return String::new();
    }
    // One cell each, the rest by share; the cells lost to rounding go to the largest remainders.
    let spare = (cells - used.len()) as f64;
    let exact: Vec<f64> = used.iter().map(|&i| sums[i] as f64 / total as f64 * spare).collect();
    let mut widths: Vec<usize> = exact.iter().map(|e| 1 + e.floor() as usize).collect();
    let mut order: Vec<usize> = (0..used.len()).collect();
    order.sort_by(|&a, &b| (exact[b].fract()).total_cmp(&exact[a].fract()));
    let left = cells - widths.iter().sum::<usize>();
    for &at in order.iter().cycle().take(left) {
        widths[at] += 1;
    }
    let cell = if theme.unicode { "█" } else { "#" };
    used.iter()
        .zip(&widths)
        .map(|(&i, &w)| KINDS[i].1(theme, &cell.repeat(w)))
        .collect()
}

/// The stacked bar and its legend: side by side when they fit with a bar of at least
/// `MIN_BAR` cells, else the bar and the legend wrapped under it.
fn weight_rows(by_type: &[TypeTotal], width: usize, theme: &Theme) -> Vec<String> {
    let sums = group_bytes(by_type);
    let total: u64 = sums.iter().sum();
    if total == 0 {
        return Vec::new();
    }
    let marker = if theme.unicode { "■" } else { "*" };
    let legend: Vec<String> = (0..KINDS.len())
        .filter(|&i| sums[i] > 0)
        .map(|i| {
            let share = sums[i] as f64 / total as f64 * 100.0;
            let pct = if share < 0.5 {
                "<1".to_owned()
            } else {
                format!("{share:.0}")
            };
            KINDS[i].1(theme, &format!("{marker} {} {pct}%", KINDS[i].0))
        })
        .collect();
    let legend_width = legend.iter().map(|l| display_width(l)).sum::<usize>() + 2 * (legend.len() - 1);
    // Two columns of indent, two of gap, and the last column stays free.
    let beside = width.saturating_sub(1 + 2 + 2 + legend_width);
    if beside >= MIN_BAR {
        let bar = stacked_bar(by_type, beside.min(MAX_BAR), theme);
        return vec![format!("  {bar}  {}", legend.join("  "))];
    }
    let bar = stacked_bar(by_type, width.saturating_sub(5).clamp(MIN_BAR, MAX_BAR), theme);
    let mut rows = vec![format!("  {bar}")];
    rows.extend(
        wrap_row(&legend, "  ", width.saturating_sub(3))
            .into_iter()
            .map(|l| format!("  {l}")),
    );
    rows
}

/// Words of `text` broken into lines of at most `room` columns, each line painted, joined by
/// newlines for `module_row` to turn into continuation rows.
fn wrapped(text: &str, gap: &str, room: usize, paint: impl Fn(&str) -> String) -> String {
    let words: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
    let lines = wrap_row(&words, gap, room);
    lines.iter().map(|l| paint(l)).collect::<Vec<_>>().join("\n")
}

/// The header's parts joined by dim dots, wrapped between parts when the row is narrow.
fn wrapped_parts(parts: &[String], room: usize, theme: &Theme) -> String {
    let lines = wrap_row(parts, " · ", room);
    lines.iter().map(|l| theme.dim(l)).collect::<Vec<_>>().join("\n")
}

/// `items` joined by `gap`, broken into lines of at most `room` columns.
fn wrap_row(items: &[String], gap: &str, room: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut used = 0;
    for item in items {
        let len = display_width(item);
        match lines.last_mut() {
            Some(line) if used + display_width(gap) + len <= room => {
                line.push_str(gap);
                line.push_str(item);
                used += display_width(gap) + len;
            }
            _ => {
                lines.push(item.clone());
                used = len;
            }
        }
    }
    lines
}

/// The browser's own findings: the ones that matter, or all of them with `-v`. After them,
/// the findings of the other modules that the frozen fast report did not have (a library
/// version only the page's JavaScript reports, say), so that every mark in the act has its
/// finding on screen.
fn findings_rows(report: &Report, width: usize, theme: &Theme, verbose: bool, above: Above<'_>) -> Vec<String> {
    let matters = |f: &&Finding| verbose || f.severity > Severity::Info;
    let mut shown: Vec<&Finding> = report.modules.browser.findings.iter().filter(matters).collect();
    if let Above::Fast(fast) = above {
        let known: Vec<&str> = all_findings(fast).iter().map(|f| f.id).collect();
        let new = |f: &&Finding| !known.contains(&f.id) && (verbose || f.severity >= Severity::Medium);
        shown.extend(all_findings(report).into_iter().filter(new));
    }
    let id_width = shown.iter().map(|f| f.id.len()).max().unwrap_or(0);
    let room = title_room(width, id_width);
    let titles: Vec<String> = shown.iter().map(|f| fit(&safe(&f.title), room, theme)).collect();
    let longest = titles.iter().map(|t| display_width(t)).max().unwrap_or(0);
    shown
        .iter()
        .zip(&titles)
        .map(|(f, title)| finding_line(f.severity, f.id, title, longest, width, theme))
        .collect()
}

#[cfg(test)]
pub(super) mod tests {
    use insite_core::analyze::browser::{Browser, Metric, TypeTotal};
    use insite_core::report::{Module, Severity, Status};

    use super::*;
    use crate::live::site::tests::{every_escape_is_sgr, plain, strip};
    use crate::render::tests::{HOSTILE, finding, full_report};
    use crate::style::display_width;

    /// A height no test frame reaches.
    const TALL: usize = 100;

    fn ascii() -> Theme {
        Theme::plain_ascii()
    }

    /// The act as it follows a frozen fast report that already had everything.
    fn final_lines(report: &Report, width: usize, theme: &Theme, verbose: bool) -> Vec<String> {
        super::final_lines(report, width, theme, verbose, Above::Fast(report))
    }

    fn metric(name: &'static str, value: f64, rating: &'static str) -> Metric {
        Metric { name, value, rating }
    }

    fn totals(parts: &[(&str, u64)]) -> Vec<TypeTotal> {
        parts
            .iter()
            .map(|(kind, bytes)| TypeTotal {
                kind: (*kind).to_owned(),
                count: 1,
                bytes: *bytes,
            })
            .collect()
    }

    fn browser() -> Browser {
        Browser {
            product: "Chromium 131".into(),
            profile: "mobile, throttled".into(),
            url: "https://www.example.com/".into(),
            metrics: vec![
                metric("lcp", 1900.0, "good"),
                metric("cls", 0.02, "good"),
                metric("tbt", 410.0, "needs_improvement"),
                metric("fcp", 800.0, "good"),
            ],
            requests: 87,
            transferred_bytes: 2_100_000,
            by_type: totals(&[
                ("Script", 1_000_000),
                ("Image", 570_000),
                ("Stylesheet", 230_000),
                ("Font", 190_000),
                ("Document", 110_000),
            ]),
            heaviest: Vec::new(),
            third_party_bytes: 714_000,
            third_party_share: 0.34,
            third_party_domains: 15,
            failed: Vec::new(),
            console_errors: Vec::new(),
            load_ms: Some(2100.0),
        }
    }

    fn with_browser(module: Module<Browser>) -> Report {
        let mut report = full_report();
        report.modules.browser = module;
        report
    }

    fn ok(data: Browser) -> Module<Browser> {
        Module {
            status: Status::Ok,
            reason: None,
            data: Some(data),
            findings: Vec::new(),
        }
    }

    pub(in crate::live) fn browser_report() -> Report {
        with_browser(ok(browser()))
    }

    fn row_of(lines: &[String], label: &str) -> String {
        plain(lines)
            .into_iter()
            .find(|l| l.trim_start().starts_with(label))
            .unwrap_or_else(|| panic!("no {label} row in {lines:#?}"))
    }

    #[test]
    fn stages_change_the_activity_text() {
        let mut view = BrowserView::new();
        let text = |view: &BrowserView| plain(&view.frame(0, 100, TALL, &ascii())).join("\n");
        assert!(text(&view).contains("browser") && text(&view).contains("launching"));
        view.launched();
        assert!(text(&view).contains("launching"));
        view.on_stage(BrowserStage::Navigating);
        assert!(text(&view).contains("loading the page"));
        view.on_stage(BrowserStage::Loaded);
        assert!(text(&view).contains("waiting for the page to settle"));
        view.on_stage(BrowserStage::Quiet);
        assert!(text(&view).contains("measuring"));
        // A load timeout goes straight to Quiet; a navigation error never gets past Navigating.
        let mut view = BrowserView::new();
        view.on_stage(BrowserStage::Navigating);
        view.on_stage(BrowserStage::Quiet);
        assert!(text(&view).contains("measuring"));
    }

    #[test]
    fn the_row_spins() {
        let view = BrowserView::new();
        let a = view.frame(0, 100, TALL, &ascii());
        let b = view.frame(1, 100, TALL, &ascii());
        assert_eq!(a.len(), 1);
        assert_ne!(a, b);
    }

    #[test]
    fn meters_take_the_rating_color() {
        let theme = Theme {
            truecolor: true,
            unicode: true,
        };
        let mut data = browser();
        data.metrics = vec![
            metric("lcp", 5000.0, "poor"),
            metric("cls", 0.02, "good"),
            metric("tbt", 410.0, "needs_improvement"),
        ];
        let lines = final_lines(&with_browser(ok(data)), 100, &theme, false);
        let w = meter_width(100);
        let line = |label: &str| {
            lines
                .iter()
                .find(|l| strip(l).trim_start().starts_with(label))
                .unwrap()
                .clone()
        };
        // LCP is past the poor threshold: a full meter, in the poor color.
        assert!(line("LCP").contains(&theme.meter(1.0, w, MeterColor::Poor)));
        assert!(line("CLS").contains(&theme.meter(0.02 / 0.25, w, MeterColor::Good)));
        // 410 ms of a 600 ms threshold.
        assert!(line("TBT").contains(&theme.meter(410.0 / 600.0, w, MeterColor::Warn)));
        assert!(strip(&line("TBT")).contains("needs work"));
        assert!(strip(&line("LCP")).contains("poor") && strip(&line("LCP")).contains("5.0 s"));
    }

    #[test]
    fn stacked_bar_has_the_requested_width() {
        let kinds = totals(&[
            ("Script", 1_000_000),
            ("Image", 570_000),
            ("Stylesheet", 230_000),
            ("Font", 190_000),
            ("Document", 110_000),
        ]);
        for cells in [10, 11, 24, 33, 40] {
            let bar = strip(&stacked_bar(&kinds, cells, &ascii()));
            assert_eq!(bar.chars().count(), cells, "{bar}");
        }
        // Unicode cells count the same.
        let unicode = Theme {
            truecolor: false,
            unicode: true,
        };
        assert_eq!(display_width(&stacked_bar(&kinds, 24, &unicode)), 24);
        // A kind with a few bytes still gets a cell, and one without none.
        let tiny = totals(&[("Script", 1_000_000), ("Font", 3), ("Image", 0)]);
        let bar = stacked_bar(&tiny, 10, &Theme::plain_ascii());
        assert_eq!(strip(&bar).chars().count(), 10);
        assert_eq!(bar.matches("\x1b[").count() / 2, 2, "{bar:?}");
        // Nothing to show, nothing drawn.
        assert_eq!(stacked_bar(&totals(&[("Script", 0)]), 10, &ascii()), "");
    }

    #[test]
    fn the_bar_row_uses_the_room_the_width_gives() {
        for width in [40, 50, 60, 80, 100, 140] {
            let lines = final_lines(&browser_report(), width, &ascii(), false);
            let text = plain(&lines);
            let bar = text
                .iter()
                .find(|l| l.trim_start().starts_with('#'))
                .unwrap_or_else(|| panic!("{width}: {text:#?}"));
            let cells = bar.trim_start().chars().take_while(|c| *c == '#').count();
            assert!(cells >= 10, "{width}: {bar}");
            assert!(display_width(bar) < width.max(20), "{width}: {bar}");
            // Same bar at the same width: the legend names every kind.
            let all = text.join("\n");
            for kind in ["js", "images", "css", "fonts", "other"] {
                assert!(all.contains(kind), "{width}: {all}");
            }
        }
    }

    #[test]
    fn kinds_map_onto_the_five_groups() {
        let kinds = totals(&[("Script", 100), ("XHR", 50), ("Fetch", 50), ("Media", 10), ("Ping", 10)]);
        let bar = stacked_bar(&kinds, 20, &ascii());
        // js, then everything unknown in one other segment.
        assert_eq!(bar.matches("\x1b[").count() / 2, 2, "{bar:?}");
    }

    #[test]
    fn browser_error_shows_a_cross() {
        let report = with_browser(Module {
            status: Status::Failed,
            reason: Some("chromium did not start".into()),
            data: None,
            findings: Vec::new(),
        });
        let lines = plain(&final_lines(&report, 100, &ascii(), false));
        assert_eq!(lines.len(), 1, "{lines:#?}");
        assert!(lines[0].starts_with("x browser") && lines[0].ends_with("chromium did not start"));
        let unicode = Theme {
            truecolor: false,
            unicode: true,
        };
        assert!(plain(&final_lines(&report, 100, &unicode, false))[0].starts_with("✗ browser"));
    }

    #[test]
    fn a_skipped_browser_has_nothing_to_show_unless_it_says_why() {
        let none = with_browser(Module::skipped("not selected"));
        assert!(final_lines(&none, 100, &ascii(), false).is_empty());
        let why = with_browser(Module::skipped("run with --browser to load the page in a browser"));
        let lines = plain(&final_lines(&why, 100, &ascii(), false));
        assert!(
            lines[0].starts_with("- browser") && lines[0].contains("--browser"),
            "{lines:#?}"
        );
    }

    #[test]
    fn the_header_names_the_product_the_profile_and_the_load() {
        let lines = final_lines(&browser_report(), 100, &ascii(), false);
        let head = row_of(&lines, "+ browser");
        assert!(
            head.contains("Chromium 131") && head.contains("mobile, throttled"),
            "{head}"
        );
        assert!(head.contains("quiet after 2.1 s"), "{head}");
    }

    #[test]
    fn the_totals_row_keeps_requests_bytes_and_third_parties() {
        let lines = final_lines(&browser_report(), 100, &ascii(), false);
        let row = row_of(&lines, "requests");
        assert!(row.contains("requests 87"), "{row}");
        assert!(row.contains("bytes 2.1 MB"), "{row}");
        assert!(row.contains("third parties 15 (34% of bytes)"), "{row}");
        // A page with no third-party bytes does not claim a share.
        let mut data = browser();
        data.third_party_bytes = 0;
        data.third_party_share = 0.0;
        data.third_party_domains = 0;
        let row = row_of(&final_lines(&with_browser(ok(data)), 100, &ascii(), false), "requests");
        assert!(row.contains("third parties 0") && !row.contains('%'), "{row}");
    }

    #[test]
    fn the_plain_facts_survive() {
        // Everything `render::browser_update` prints without -v is still on screen.
        let mut report = browser_report();
        report.modules.browser.status = Status::Partial;
        report.modules.browser.reason = Some("the page never went quiet".into());
        report.modules.browser.findings = vec![
            finding("perf.tbt.poor", Severity::Medium, "Main thread blocked"),
            finding("browser.note", Severity::Info, "Only for -v"),
        ];
        let text = plain(&final_lines(&report, 100, &ascii(), false)).join("\n");
        for fact in [
            "LCP",
            "CLS",
            "TBT",
            "FCP",
            "1.9 s",
            "0.02",
            "410 ms",
            "0.8 s",
            "87",
            "2.1 MB",
            "34%",
            "mobile, throttled",
            "stack",
            "Astro",
            "Main thread blocked",
            "perf.tbt.poor",
            "browser: the page never went quiet",
        ] {
            assert!(text.contains(fact), "{fact}: {text}");
        }
        assert!(!text.contains("Only for -v"), "{text}");
        let verbose = plain(&final_lines(&report, 100, &ascii(), true)).join("\n");
        assert!(verbose.contains("Only for -v"), "{verbose}");
    }

    /// A complete report whose stack has a finding the fast one could not have had.
    fn found_by_the_browser() -> (Report, Report) {
        let mut full = browser_report();
        full.modules.browser.findings = vec![finding("perf.tbt.poor", Severity::Medium, "Main thread blocked")];
        full.modules.stack.findings = vec![
            finding("stack.library.vulnerable", Severity::High, "Vulnerable library"),
            finding("stack.library.old", Severity::Low, "Old library"),
        ];
        let mut fast = full.clone();
        fast.modules.browser = Module::skipped("the browser is still loading the page");
        fast.modules.stack.findings.clear();
        (fast, full)
    }

    #[test]
    fn after_a_frozen_fast_report_the_act_lists_what_the_browser_made_possible() {
        let (fast, full) = found_by_the_browser();
        let theme = ascii();
        let text = plain(&super::final_lines(&full, 100, &theme, false, Above::Fast(&fast)));
        let at = |id: &str| text.iter().position(|l| l.contains(id));
        // Its own findings first, then the stack's Medium and above; a low one stays out.
        assert!(at("perf.tbt.poor") < at("stack.library.vulnerable"), "{text:#?}");
        assert!(
            at("stack.library.vulnerable").is_some() && at("stack.library.old").is_none(),
            "{text:#?}"
        );
        // The stack row, with its cross, is in the act.
        assert!(text.iter().any(|l| l.starts_with("x stack")), "{text:#?}");
        // Verbose shows every one of them.
        let text = plain(&super::final_lines(&full, 100, &theme, true, Above::Fast(&fast)));
        assert!(text.iter().any(|l| l.contains("stack.library.old")), "{text:#?}");
        // A finding the fast report already had is not said again.
        let text = plain(&super::final_lines(&full, 100, &theme, false, Above::Fast(&full)));
        assert!(
            !text.iter().any(|l| l.contains("stack.library.vulnerable")),
            "{text:#?}"
        );
    }

    #[test]
    fn above_the_same_report_the_act_repeats_nothing() {
        let (_, full) = found_by_the_browser();
        let text = plain(&super::final_lines(&full, 100, &ascii(), false, Above::Same));
        assert!(!text.iter().any(|l| l.contains("stack")), "{text:#?}");
        // Only the browser's own findings are the act's.
        assert!(text.iter().any(|l| l.contains("perf.tbt.poor")));
        assert!(!text.iter().any(|l| l.contains("stack.library")), "{text:#?}");
    }

    #[test]
    fn verbose_appends_todays_browser_details() {
        let mut data = browser();
        data.failed = vec!["https://cdn.example.net/a.js (404)".into()];
        data.console_errors = vec!["Uncaught TypeError".into()];
        let report = with_browser(ok(data));
        let short = plain(&final_lines(&report, 100, &ascii(), false));
        let long = plain(&final_lines(&report, 100, &ascii(), true));
        assert_eq!(long[..short.len()], short[..]);
        let text = long.join("\n");
        assert!(text.contains("load event") && text.contains("2100 ms"), "{text}");
        assert!(text.contains("failed") && text.contains("Uncaught TypeError"), "{text}");
        assert!(!short.join("\n").contains("Uncaught TypeError"));
    }

    #[test]
    fn hostile_text_cannot_escape() {
        let theme = Theme {
            truecolor: true,
            unicode: true,
        };
        let mut data = browser();
        data.product = HOSTILE.into();
        data.url = format!("https://{HOSTILE}/");
        data.failed = vec![HOSTILE.into()];
        data.console_errors = vec![HOSTILE.into()];
        let mut module = ok(data);
        module.status = Status::Partial;
        module.reason = Some(HOSTILE.into());
        module.findings = vec![Finding {
            title: HOSTILE.into(),
            evidence: HOSTILE.into(),
            ..finding("browser.console_errors", Severity::Medium, "x")
        }];
        let report = with_browser(module);
        for verbose in [false, true] {
            let joined = final_lines(&report, 80, &theme, verbose).join("\n");
            assert!(!joined.contains("\x1b[2J") && !joined.contains("\x1b]"), "{joined:?}");
            every_escape_is_sgr(&joined);
        }
        let failed = with_browser(Module {
            status: Status::Failed,
            reason: Some(HOSTILE.into()),
            data: None,
            findings: Vec::new(),
        });
        let joined = final_lines(&failed, 80, &theme, true).join("\n");
        assert!(!joined.contains("\x1b[2J") && !joined.contains("\x1b]"), "{joined:?}");
        every_escape_is_sgr(&joined);
    }

    #[test]
    fn no_line_holds_a_newline_and_the_layout_fits() {
        let mut data = browser();
        data.product = "Chromium\n131".into();
        let mut report = with_browser(ok(data));
        report.modules.browser.status = Status::Partial;
        report.modules.browser.reason = Some("one\ntwo".into());
        for width in [40, 50, 60, 80, 100, 140] {
            for verbose in [false, true] {
                for line in final_lines(&report, width, &ascii(), verbose) {
                    assert!(!line.contains('\n'), "{line:?}");
                }
            }
            for line in final_lines(&report, width, &ascii(), false) {
                let text = strip(&line);
                if text.trim_start().starts_with(['+', 'L', 'C', 'T', 'F', '#', 'r']) {
                    assert!(display_width(&line) < width, "{width}: {text:?}");
                }
            }
        }
    }

    #[test]
    fn narrow_rows_wrap_instead_of_cutting_facts() {
        let text = plain(&final_lines(&browser_report(), 40, &ascii(), false)).join("\n");
        assert!(
            text.contains("mobile, throttled") && text.contains("quiet after 2.1 s"),
            "{text}"
        );
        let reason = "chromium exited before the page finished loading, twice";
        let failed = with_browser(Module {
            status: Status::Failed,
            reason: Some(reason.into()),
            data: None,
            findings: Vec::new(),
        });
        let text = plain(&final_lines(&failed, 40, &ascii(), false));
        assert!(text.len() > 1);
        let joined = text.join(" ").replace("x browser", "");
        assert_eq!(joined.split_whitespace().collect::<Vec<_>>().join(" "), reason);
    }
}
