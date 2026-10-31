//! The live terminal output. One thread owns the terminal and redraws it; the rest of the
//! program only sends it events, through an unbounded channel that never blocks collection.

pub(crate) mod batch;
pub(crate) mod browser;
pub(crate) mod site;
pub(crate) mod term;
pub(crate) mod theme;

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use insite_core::collect::progress::{Progress, ProgressSender};
use insite_core::report::{Report, Selection};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender, WeakUnboundedSender};
use tokio::sync::oneshot;

use batch::BatchView;
use browser::BrowserView;
use site::SiteView;
use term::Region;
use theme::Theme;

/// How often the spinners move.
const TICK: Duration = Duration::from_millis(80);
/// The height assumed when the terminal cannot tell.
const DEFAULT_HEIGHT: usize = 24;

/// What the collection tells the UI. `site` is the position among the valid targets.
pub(crate) enum UiEvent {
    /// Something the collector or the browser did.
    Progress { site: usize, event: Progress },
    /// The site's browser process is about to start.
    Launching { site: usize },
    /// The report without the browser's part; only sent with `--browser`.
    Fast { site: usize, report: Box<Report> },
    /// The complete report.
    Full { site: usize, report: Box<Report> },
    /// The analysis died, so no report will come for the site.
    Gone { site: usize },
    /// Text for the person, printed above the live area.
    Message(String),
}

/// A sender that does not keep the channel open: the UI ends when the main sender is
/// dropped, whatever tasks are still around. Sending after that is ignored.
#[derive(Clone)]
pub(crate) struct UiLink(WeakUnboundedSender<UiEvent>);

impl UiLink {
    pub(crate) fn to(tx: &UnboundedSender<UiEvent>) -> Self {
        UiLink(tx.downgrade())
    }

    pub(crate) fn send(&self, event: UiEvent) {
        if let Some(tx) = self.0.upgrade() {
            let _ = tx.send(event);
        }
    }
}

/// Carries one site's progress events to the UI.
pub(crate) struct Forwarder {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Forwarder {
    /// The sender goes into the collection options and the browser visit.
    pub(crate) fn spawn(ui: UiLink, site: usize) -> (ProgressSender, Forwarder) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (stop, mut stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = rx.recv() => match event {
                        Some(event) => ui.send(UiEvent::Progress { site, event }),
                        None => return,
                    },
                    _ = &mut stopped => break,
                }
            }
            while let Ok(event) = rx.try_recv() {
                ui.send(UiEvent::Progress { site, event });
            }
        });
        (tx, Forwarder { stop, task })
    }

    /// Delivers what is queued and stops. Auxiliary tasks may hold senders long after the
    /// collection ended, so the channel closing is never waited for.
    pub(crate) async fn finish(self) {
        let _ = self.stop.send(());
        let _ = self.task.await;
    }
}

/// Starts the UI on its own thread, writing to stdout. Dropping the sender ends it: it
/// commits everything still pending and gives the terminal back.
pub(crate) fn spawn_ui(
    inputs: Vec<String>,
    selection: Selection,
    verbose: bool,
    browser: bool,
) -> (UnboundedSender<UiEvent>, JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let theme = Theme::detect();
    let thread = thread::spawn(move || {
        let _ = drive(Locked, real_size, theme, rx, &inputs, selection, verbose, browser);
    });
    (tx, thread)
}

/// `spawn_ui` for tests: any writer, a fixed size and the plain theme. The thread
/// returns the writer.
#[cfg(test)]
pub(crate) fn spawn_ui_with<W: Write + Send + 'static>(
    out: W,
    width: usize,
    height: usize,
    inputs: Vec<String>,
    selection: Selection,
    verbose: bool,
    browser: bool,
) -> (UnboundedSender<UiEvent>, JoinHandle<W>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let thread = thread::spawn(move || {
        let size = move || (width, height);
        drive(
            out,
            size,
            Theme::plain_ascii(),
            rx,
            &inputs,
            selection,
            verbose,
            browser,
        )
        .expect("the writer works")
    });
    (tx, thread)
}

/// The terminal's width and height, as the region should use them this tick.
fn real_size() -> (usize, usize) {
    match crossterm::terminal::size() {
        Ok((columns, rows)) if columns > 0 && rows > 0 => (usize::from(columns), usize::from(rows)),
        _ => (crate::style::terminal_width(), DEFAULT_HEIGHT),
    }
}

/// The UI thread's loop. It sleeps until an event arrives, the channel closes or the next
/// tick is due, so a result is drawn, and the terminal given back, at once; the tick
/// only paces the spinners. Returns the writer when the channel closes and the terminal
/// has been given back.
#[allow(clippy::too_many_arguments)]
fn drive<W: Write>(
    out: W,
    mut size: impl FnMut() -> (usize, usize),
    theme: Theme,
    mut rx: UnboundedReceiver<UiEvent>,
    inputs: &[String],
    selection: Selection,
    verbose: bool,
    browser: bool,
) -> io::Result<W> {
    // Only to wait on the channel with a timeout.
    let waiter = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio runtime");
    let mut ui = Ui::new(out, theme, inputs, selection, verbose, browser);
    let mut next_tick = Instant::now() + TICK;
    loop {
        let wait = next_tick.saturating_duration_since(Instant::now());
        let first = waiter.block_on(async { tokio::time::timeout(wait, rx.recv()).await });
        // Read after waking: the terminal may have been resized meanwhile.
        let (width, height) = size();
        // Whether something a person waits for arrived: it is drawn without waiting for a tick.
        let mut urgent = false;
        match first {
            Err(_) => {}
            Ok(None) => return ui.close(width),
            Ok(Some(event)) => {
                urgent |= is_result(&event);
                // A failed write (the terminal went away) must not stop the draining.
                let _ = ui.handle(event, width);
                loop {
                    match rx.try_recv() {
                        Ok(event) => {
                            urgent |= is_result(&event);
                            let _ = ui.handle(event, width);
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => return ui.close(width),
                    }
                }
            }
        }
        let advance = Instant::now() >= next_tick;
        if advance {
            next_tick = Instant::now() + TICK;
        }
        if advance || urgent {
            let _ = ui.render(width, height, advance);
        }
    }
}

/// Events that change what is on screen beyond a progress step.
fn is_result(event: &UiEvent) -> bool {
    !matches!(event, UiEvent::Progress { .. } | UiEvent::Launching { .. })
}

/// Which view the run needs.
enum View {
    One(One),
    Batch(Batch),
}

/// One site: its live frame, then, with `--browser`, the browser's.
struct One {
    site: SiteView,
    /// Present with `--browser`.
    browser: Option<BrowserView>,
    stage: Stage,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The site view spins.
    Collecting,
    /// The fast report is in the scrollback and the browser row spins.
    Browsing,
    /// Everything is committed.
    Done,
}

/// Several sites: the table, and what `-v` needs at the end.
struct Batch {
    table: BatchView,
    browser: bool,
    /// Filled only with `-v`.
    kept: Vec<Kept>,
}

#[derive(Default)]
struct Kept {
    fast: Option<Box<Report>>,
    full: Option<Box<Report>>,
}

struct Ui<W: Write> {
    region: Region<W>,
    theme: Theme,
    verbose: bool,
    started: Instant,
    /// Counts the ticks, for the spinners.
    frame: usize,
    view: View,
}

impl<W: Write> Ui<W> {
    fn new(out: W, theme: Theme, inputs: &[String], selection: Selection, verbose: bool, browser: bool) -> Self {
        let view = match inputs {
            [input] => View::One(One {
                site: SiteView::new(input, selection),
                browser: browser.then(BrowserView::new),
                stage: Stage::Collecting,
            }),
            _ => View::Batch(Batch {
                table: BatchView::new(inputs, browser),
                browser,
                kept: inputs.iter().map(|_| Kept::default()).collect(),
            }),
        };
        Ui {
            region: Region::new(out),
            theme,
            verbose,
            started: Instant::now(),
            frame: 0,
            view,
        }
    }

    fn handle(&mut self, event: UiEvent, width: usize) -> io::Result<()> {
        let (theme, verbose) = (&self.theme, self.verbose);
        match (&mut self.view, event) {
            (_, UiEvent::Message(text)) => {
                let lines: Vec<String> = text.lines().map(str::to_owned).collect();
                self.region.commit(&lines, width)
            }
            (View::One(one), event) => {
                let lines = match event {
                    UiEvent::Progress { event, .. } => {
                        if let (Progress::Browser(stage), Some(browser)) = (&event, one.browser.as_mut()) {
                            browser.on_stage(*stage);
                        }
                        one.site.on_progress(&event);
                        return Ok(());
                    }
                    UiEvent::Launching { .. } => {
                        if let Some(browser) = one.browser.as_mut() {
                            browser.launched();
                        }
                        return Ok(());
                    }
                    // The fast report freezes in the scrollback before the browser's act.
                    UiEvent::Fast { report, .. } if one.browser.is_some() && one.stage == Stage::Collecting => {
                        one.stage = Stage::Browsing;
                        // A blank line sets the browser's act apart.
                        let mut lines = site::final_lines(&report, width, theme, verbose);
                        lines.push(String::new());
                        lines
                    }
                    UiEvent::Fast { .. } => return Ok(()),
                    UiEvent::Full { report, .. } => {
                        let mut lines = Vec::new();
                        // No Fast came first (its analysis died, which should not happen), so
                        // nothing is in the scrollback yet: the site block goes out with the
                        // browser's, and the stack row may repeat.
                        if one.stage == Stage::Collecting {
                            lines = site::final_lines(&report, width, theme, verbose);
                            if one.browser.is_some() {
                                lines.push(String::new());
                            }
                        }
                        if one.browser.is_some() {
                            lines.extend(browser::final_lines(&report, width, theme, verbose));
                        }
                        one.stage = Stage::Done;
                        lines
                    }
                    UiEvent::Gone { .. } => {
                        one.stage = Stage::Done;
                        vec![format!("  {}", batch::analysis_failed(theme))]
                    }
                    UiEvent::Message(_) => unreachable!("handled above"),
                };
                self.region.commit(&lines, width)
            }
            (View::Batch(batch), event) => {
                match event {
                    UiEvent::Progress { site, .. } | UiEvent::Launching { site } => batch.table.on_started(site),
                    UiEvent::Fast { site, report } => {
                        batch.table.on_started(site);
                        batch.table.on_fast(site, &report);
                        if let (true, Some(kept)) = (verbose, batch.kept.get_mut(site)) {
                            kept.fast = Some(report);
                        }
                    }
                    UiEvent::Full { site, report } => {
                        batch.table.on_started(site);
                        // Without the browser the only report is the row's last word.
                        if batch.browser {
                            batch.table.on_full(site, &report);
                        } else {
                            batch.table.on_fast(site, &report);
                        }
                        if let (true, Some(kept)) = (verbose, batch.kept.get_mut(site)) {
                            kept.full = Some(report);
                        }
                    }
                    UiEvent::Gone { site } => batch.table.on_gone(site),
                    UiEvent::Message(_) => unreachable!("handled above"),
                }
                Ok(())
            }
        }
    }

    /// Commits what became final and redraws what is still live, one spinner frame further
    /// when `advance`. With
    /// nothing animating there is nothing to redraw.
    fn render(&mut self, width: usize, height: usize, advance: bool) -> io::Result<()> {
        if advance {
            self.frame = self.frame.wrapping_add(1);
        }
        let (theme, frame) = (&self.theme, self.frame);
        match &mut self.view {
            View::One(one) => {
                let lines = match one.stage {
                    Stage::Collecting => one.site.frame(frame, width, theme),
                    Stage::Browsing => one
                        .browser
                        .as_ref()
                        .map_or_else(Vec::new, |b| b.frame(frame, width, theme)),
                    Stage::Done => return Ok(()),
                };
                self.region.draw(&lines, width)
            }
            View::Batch(batch) => {
                let finished = batch.table.take_finished(width, theme);
                if !finished.is_empty() {
                    self.region.commit(&finished, width)?;
                }
                if !batch.table.pending() {
                    return Ok(());
                }
                self.region.draw(&batch.table.frame(frame, width, height, theme), width)
            }
        }
    }

    /// The channel closed: everything not yet in the scrollback goes there, then the
    /// terminal is given back.
    fn close(mut self, width: usize) -> io::Result<W> {
        let (theme, verbose) = (&self.theme, self.verbose);
        match &mut self.view {
            View::One(one) => {
                // Interrupted before the report: the frame as it stands.
                let lines = match one.stage {
                    Stage::Collecting => one.site.frame(self.frame, width, theme),
                    Stage::Browsing => one
                        .browser
                        .as_ref()
                        .map_or_else(Vec::new, |b| b.frame(self.frame, width, theme)),
                    Stage::Done => Vec::new(),
                };
                if !lines.is_empty() {
                    let _ = self.region.commit(&lines, width);
                }
            }
            View::Batch(batch) => {
                batch.table.end_unfinished();
                let mut lines = batch.table.take_finished(width, theme);
                lines.extend(batch.table.summary_lines(Some(self.started.elapsed()), width, theme));
                lines.extend(batch.table.findings_lines(width, theme));
                if verbose {
                    let sites: Vec<(Option<&Report>, Option<&Report>)> = batch
                        .kept
                        .iter()
                        .map(|k| {
                            let site = k.fast.as_deref().or(k.full.as_deref());
                            (site, k.full.as_deref().filter(|_| batch.browser))
                        })
                        .collect();
                    lines.extend(details(&sites, width, theme));
                }
                let _ = self.region.commit(&lines, width);
            }
        }
        // Whatever failed above, the terminal must get its cursor back. The last draw is at
        // today's width, which `finish` reuses to clear what is left.
        let _ = self.region.draw(&[], width);
        self.region.finish()
    }
}

/// What `-v` adds under a batch: each site's report in input order. The site part comes
/// from the fast report when there is one; the browser part from the complete one.
fn details(sites: &[(Option<&Report>, Option<&Report>)], width: usize, theme: &Theme) -> Vec<String> {
    let mut lines = Vec::new();
    for (site, browser) in sites {
        if let Some(report) = site {
            lines.push(String::new());
            lines.extend(site::final_lines(report, width, theme, true));
        }
        if let Some(report) = browser {
            let act = browser::final_lines(report, width, theme, true);
            if site.is_some() && !act.is_empty() {
                lines.push(String::new());
            }
            lines.extend(act);
        }
    }
    lines
}

/// A saved snapshot, for `--from`: its report, and, when the snapshot has browser data, the
/// report as it was before the browser.
pub(crate) struct Saved {
    pub(crate) full: Report,
    pub(crate) fast: Option<Report>,
}

/// `--from` on a terminal: the live view's final frames as plain text, with no animation:
/// the one-site view, or the batch table.
pub(crate) fn saved_lines(saved: &[Saved], verbose: bool, width: usize, theme: &Theme) -> Vec<String> {
    if let [one] = saved {
        let mut lines = site::final_lines(one.fast.as_ref().unwrap_or(&one.full), width, theme, verbose);
        if one.fast.is_some() {
            lines.push(String::new());
            lines.extend(browser::final_lines(&one.full, width, theme, verbose));
        }
        return lines;
    }
    let browser = saved.iter().any(|s| s.fast.is_some());
    let labels: Vec<String> = saved.iter().map(|s| s.full.target.display_host.clone()).collect();
    let mut table = BatchView::new(&labels, browser);
    for (i, s) in saved.iter().enumerate() {
        if browser {
            table.on_full(i, &s.full);
        } else {
            table.on_fast(i, &s.full);
        }
    }
    let mut lines = table.take_finished(width, theme);
    lines.extend(table.summary_lines(None, width, theme));
    lines.extend(table.findings_lines(width, theme));
    if verbose {
        let sites: Vec<(Option<&Report>, Option<&Report>)> = saved
            .iter()
            .map(|s| {
                (
                    Some(s.fast.as_ref().unwrap_or(&s.full)),
                    s.fast.as_ref().map(|_| &s.full),
                )
            })
            .collect();
        lines.extend(details(&sites, width, theme));
    }
    lines
}

/// Set by the second Ctrl-C: after it the UI writes nothing more.
static QUITTING: AtomicBool = AtomicBool::new(false);

/// Stdout for the UI thread. Each write holds the stdout lock while it checks `QUITTING`,
/// so a frame is either written whole before the restore bytes or not at all.
struct Locked;

impl Write for Locked {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut out = io::stdout().lock();
        if QUITTING.load(Ordering::SeqCst) {
            return Ok(());
        }
        out.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut out = io::stdout().lock();
        if QUITTING.load(Ordering::SeqCst) {
            return Ok(());
        }
        out.flush()
    }
}

/// The second Ctrl-C: gives the terminal back and keeps the UI thread from taking it again
/// in the moments before the process exits.
pub(crate) fn quit() {
    // The lock is reentrant: `restore_terminal` takes it again on this thread.
    let _held = io::stdout().lock();
    QUITTING.store(true, Ordering::SeqCst);
    term::restore_terminal();
}

/// A panic anywhere leaves the cursor hidden otherwise: restore first, then report.
pub(crate) fn restore_on_panic() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        term::restore_terminal();
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use insite_core::report::{Module, Outcome};

    use super::*;
    use crate::render::tests::{full_report, hostile_report};

    const SHOW: &str = "\x1b[?25h";
    const TAIL: &str = "\x1b[?25h\x1b[0m\x1b[?2026l";

    fn hosts(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn theme() -> Theme {
        Theme::plain_ascii()
    }

    /// Runs the UI over `events`, closes the channel and returns what was written.
    fn run_ui(inputs: &[&str], verbose: bool, browser: bool, events: Vec<UiEvent>) -> String {
        let (tx, thread) = spawn_ui_with(Vec::new(), 100, 24, hosts(inputs), Selection::all(), verbose, browser);
        for event in events {
            tx.send(event).unwrap();
        }
        drop(tx);
        String::from_utf8(join(thread, Duration::from_secs(5))).unwrap()
    }

    /// Joins the UI thread, failing instead of hanging when it does not end in time.
    fn join<T: Send + 'static>(thread: JoinHandle<T>, within: Duration) -> T {
        let (done, wait) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = done.send(thread.join());
        });
        wait.recv_timeout(within)
            .expect("the UI thread ends in time")
            .expect("the UI thread does not panic")
    }

    /// A writer the test can read while the thread still owns it.
    #[derive(Clone, Default)]
    struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[test]
    fn an_idle_ui_ends_promptly_when_the_sender_drops() {
        // Two ticks are 160 ms: ending in well under one means the thread did not sleep
        // through a tick before noticing.
        for browser in [false, true] {
            let (tx, thread) = spawn_ui_with(
                Vec::new(),
                100,
                24,
                hosts(&["a.example", "b.example"]),
                Selection::all(),
                false,
                browser,
            );
            thread::sleep(Duration::from_millis(30));
            let dropped = Instant::now();
            drop(tx);
            join(thread, Duration::from_secs(5));
            assert!(dropped.elapsed() < Duration::from_millis(40), "{:?}", dropped.elapsed());
        }
    }

    #[test]
    fn a_result_is_drawn_without_waiting_for_a_tick() {
        let out = Shared::default();
        let names = hosts(&["a.example", "b.example"]);
        let (tx, thread) = spawn_ui_with(out.clone(), 100, 24, names, Selection::all(), false, false);
        // The first tick is 80 ms after the start; the row must be out well before it.
        tx.send(full(0)).unwrap();
        let sent = Instant::now();
        while !visible(&out.text()).contains("a.example") {
            assert!(sent.elapsed() < Duration::from_millis(60), "not drawn in time");
            thread::sleep(Duration::from_millis(1));
        }
        drop(tx);
        join(thread, Duration::from_secs(5));
    }

    /// The text of the screen lines, without any escape sequence.
    fn visible(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '\x1b' {
                out.push(c);
                continue;
            }
            if chars.next_if_eq(&'[').is_some() {
                // A CSI sequence ends at a byte from `@` to `~`.
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
        }
        out.replace("\r\n", "\n")
    }

    fn full(site: usize) -> UiEvent {
        UiEvent::Full {
            site,
            report: Box::new(full_report()),
        }
    }

    #[test]
    fn ui_thread_ends_when_the_channel_closes() {
        let report = full_report();
        let events = vec![
            UiEvent::Fast {
                site: 0,
                report: Box::new(report.clone()),
            },
            full(0),
        ];
        let text = run_ui(&["example.com"], false, true, events);
        let screen = visible(&text);
        assert!(screen.contains("example.com"), "{screen}");
        // The findings block and the hint come from the final lines, once.
        assert!(screen.contains("-v for evidence"), "{screen}");
        assert_eq!(screen.matches("-v for evidence").count(), 1, "{screen}");
        for line in site::final_lines(&report, 100, &theme(), false) {
            assert!(text.contains(&line), "missing: {line}");
        }
        assert!(text.ends_with(TAIL), "{:?}", &text[text.len().saturating_sub(40)..]);
        // The cursor was hidden while the region lived and shown at the end.
        assert!(text.contains("\x1b[?25l") && text.rfind(SHOW) > text.rfind("\x1b[?25l"));
    }

    #[test]
    fn one_site_without_the_browser_commits_the_final_lines_once() {
        let report = full_report();
        let text = run_ui(&["example.com"], false, false, vec![full(0)]);
        let screen = visible(&text);
        assert_eq!(screen.matches("-v for evidence").count(), 1, "{screen}");
        for line in site::final_lines(&report, 100, &theme(), false) {
            assert!(text.contains(&line), "missing: {line}");
        }
    }

    #[test]
    fn the_browser_run_freezes_the_fast_report_before_its_own_act() {
        let mut fast = full_report();
        fast.modules.browser = Module::skipped("the browser is still loading the page");
        let out = Shared::default();
        let (tx, thread) = spawn_ui_with(
            out.clone(),
            100,
            24,
            hosts(&["example.com"]),
            Selection::all(),
            false,
            true,
        );
        tx.send(UiEvent::Launching { site: 0 }).unwrap();
        tx.send(UiEvent::Fast {
            site: 0,
            report: Box::new(fast.clone()),
        })
        .unwrap();
        // The browser row spins for a few frames before the complete report arrives.
        thread::sleep(Duration::from_millis(200));
        tx.send(full(0)).unwrap();
        drop(tx);
        join(thread, Duration::from_secs(5));
        let text = out.text();
        let frozen = site::final_lines(&fast, 100, &theme(), false);
        let hint = frozen.iter().find(|l| l.contains("-v for evidence")).unwrap();
        // The fast block is committed once, and before the first frame of the browser's act;
        // the collecting frames before it never mention the browser.
        assert_eq!(text.matches(hint.as_str()).count(), 1, "{}", visible(&text));
        let frozen_at = text.find(hint.as_str()).unwrap();
        let act_at = text.find("launching").expect("the browser row was drawn");
        assert!(frozen_at < act_at, "{}", visible(&text));
        assert!(!text[..frozen_at].contains("launching"));
    }

    #[test]
    fn a_message_is_committed_above_the_region() {
        let text = run_ui(
            &["example.com"],
            false,
            false,
            vec![UiEvent::Message("insite: interrupted".to_owned()), full(0)],
        );
        let screen = visible(&text);
        assert_eq!(screen.matches("insite: interrupted").count(), 1, "{screen}");
        assert!(
            screen.find("insite: interrupted") < screen.find("-v for evidence"),
            "{screen}"
        );
    }

    #[test]
    fn a_one_site_run_closed_before_any_report_commits_its_frame() {
        let text = run_ui(&["example.com"], false, false, Vec::new());
        let screen = visible(&text);
        assert!(screen.contains("example.com"), "{screen}");
        assert!(text.ends_with(TAIL));
    }

    #[test]
    fn a_site_whose_analysis_died_gets_a_red_line() {
        let text = run_ui(&["example.com"], false, false, vec![UiEvent::Gone { site: 0 }]);
        assert!(visible(&text).contains("x analysis failed"));
        // The plain-ascii theme paints red with the basic SGR, right before the text.
        let red = text.find("\x1b[31m").expect("a red sequence");
        assert!(red < text.find("x analysis failed").unwrap(), "{text:?}");
        assert!(text.ends_with(TAIL));
    }

    #[test]
    fn batch_ui_commits_every_row_and_the_summary() {
        let names = ["a.example", "b.example", "c.example"];
        let text = run_ui(&names, false, false, vec![full(2), full(0), full(1)]);
        let screen = visible(&text);
        let summary = screen.rfind("3 sites in").expect("the summary");
        assert!(screen[summary..].contains("grades"), "{screen}");
        // A row shows up in live frames too, but its last appearance before the summary is
        // the commit, and commits go in input order.
        let table = &screen[..summary];
        let last: Vec<usize> = names.iter().map(|n| table.rfind(n).expect(n)).collect();
        assert!(last[0] < last[1] && last[1] < last[2], "{last:?}\n{screen}");
        assert!(text.ends_with(TAIL), "{:?}", &text[text.len().saturating_sub(40)..]);
    }

    #[test]
    fn gone_and_interrupted_rows_still_finish() {
        let names = ["a.example", "b.example", "c.example", "d.example"];
        let events = vec![
            UiEvent::Gone { site: 0 },
            full(1),
            // Site 2 started but never reported; site 3 never started.
            UiEvent::Launching { site: 2 },
        ];
        let text = run_ui(&names, false, false, events);
        let screen = visible(&text);
        let summary = screen.rfind("4 sites in").expect("the summary");
        let table = &screen[..summary];
        let line_of = |name: &str| {
            table
                .lines()
                .rfind(|l| l.contains(name))
                .unwrap_or_else(|| panic!("{name}\n{screen}"))
        };
        assert!(line_of("a.example").contains("x analysis failed"), "{screen}");
        assert!(line_of("b.example").contains("s "), "{screen}");
        assert!(line_of("c.example").contains("interrupted"), "{screen}");
        assert!(line_of("d.example").contains("not started"), "{screen}");
        assert!(screen.contains("4 sites in"), "{screen}");
        assert!(text.ends_with(TAIL));
    }

    #[test]
    fn batch_with_a_browser_waits_for_the_full_report() {
        let names = ["a.example", "b.example"];
        let events = vec![
            UiEvent::Fast {
                site: 0,
                report: Box::new(full_report()),
            },
            full(0),
            UiEvent::Fast {
                site: 1,
                report: Box::new(hostile_report()),
            },
        ];
        // Site 1 never gets its full report: the close ends its row with the fast data.
        let screen = visible(&run_ui(&names, false, true, events));
        assert!(screen.contains("2 sites in"), "{screen}");
        assert!(screen.contains("LCP"), "{screen}");
    }

    #[test]
    fn verbose_batches_end_with_each_site_in_input_order() {
        let names = ["a.example", "b.example"];
        let mut one = full_report();
        one.target.display_host = "first.example".to_owned();
        let mut two = full_report();
        two.target.display_host = "second.example".to_owned();
        let events = vec![
            UiEvent::Full {
                site: 1,
                report: Box::new(two),
            },
            UiEvent::Full {
                site: 0,
                report: Box::new(one),
            },
        ];
        let screen = visible(&run_ui(&names, true, false, events));
        let summary = screen.rfind("2 sites in").unwrap();
        let first = screen.rfind("first.example").unwrap();
        let second = screen.rfind("second.example").unwrap();
        assert!(summary < first && first < second, "{screen}");
    }

    #[tokio::test]
    async fn the_forwarder_delivers_what_is_queued_and_stops_with_a_sender_alive() {
        use insite_core::collect::progress::Part;

        let (ui, mut rx) = mpsc::unbounded_channel();
        let (progress, forwarder) = Forwarder::spawn(UiLink::to(&ui), 3);
        // An auxiliary task would keep a clone like this one past the collection.
        let straggler = progress.clone();
        for part in [Part::Page, Part::Asn] {
            progress.send(Progress::Done(part)).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), forwarder.finish())
            .await
            .expect("finish does not wait for the senders to close");
        for part in [Part::Page, Part::Asn] {
            match rx.try_recv() {
                Ok(UiEvent::Progress { site: 3, event }) => assert_eq!(event, Progress::Done(part)),
                _ => panic!("the queued events arrive in order"),
            }
        }
        drop(straggler);
    }

    #[test]
    fn links_do_not_keep_the_channel_open() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let link = UiLink::to(&tx);
        link.send(UiEvent::Gone { site: 0 });
        drop(tx);
        assert!(matches!(rx.try_recv(), Ok(UiEvent::Gone { site: 0 })));
        // Every strong sender is gone, so the channel is closed although a link is left.
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
        link.send(UiEvent::Gone { site: 1 });
    }

    #[test]
    fn saved_snapshots_print_without_any_cursor_movement() {
        let mut unreachable = hostile_report();
        unreachable.outcome = Outcome::Unreachable {
            reason: "refused".to_owned(),
        };
        let saved = vec![
            Saved {
                full: full_report(),
                fast: None,
            },
            Saved {
                full: unreachable,
                fast: None,
            },
        ];
        let lines = saved_lines(&saved, false, 100, &theme());
        let text = lines.join("\n");
        assert!(visible(&text).contains("2 sites"), "{text}");
        assert!(!visible(&text).contains(" in "), "no wall time for --from: {text}");
        assert!(!text.contains("\x1b[A") && !text.contains("\x1b[?25"), "{text:?}");
        let one = saved_lines(&saved[..1], false, 100, &theme());
        assert_eq!(one, site::final_lines(&saved[0].full, 100, &theme(), false));
    }
}
