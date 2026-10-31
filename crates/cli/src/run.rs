//! Collection of one or many sites, and printing reports as they finish.

use std::borrow::Cow;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use insite_core::analyze::analyze_selected;
use insite_core::collect::browser::{Browser, Visit};
use insite_core::collect::deadline::Deadline;
use insite_core::collect::dns::Resolver;
use insite_core::collect::records::registrable;
use insite_core::collect::target::Target;
use insite_core::collect::tls::Tls;
use insite_core::collect::{Collector, Options};
use insite_core::report::{Module, ModuleName, Outcome, Report, Selection};
use insite_core::snapshot::{BrowserData, Snapshot};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::live::{self, Forwarder, UiEvent, UiLink};
use crate::snapshots::Writer;
use crate::{Format, markdown, render};

/// Analyses of the same registrable domain run one after the other, with this
/// pause between them, so a host never sees more than one analysis at a time.
const SAME_DOMAIN_PAUSE: Duration = Duration::from_secs(1);
/// Browsers running at once in batch mode.
const BROWSERS: usize = 2;

pub struct Plan {
    pub inputs: Vec<String>,
    pub opts: Options,
    pub selection: Selection,
    pub format: Format,
    pub save: Option<PathBuf>,
    pub native_roots: bool,
    pub concurrency: usize,
    pub browser: Option<BrowserPlan>,
}

pub struct BrowserPlan {
    pub visit: Visit,
    /// From the start of each site's analysis.
    pub timeout: Duration,
    pub proxy: Option<String>,
}

/// A report ready to print: the fast one while the browser still works, or
/// the complete one.
enum Ready {
    Fast(usize, Box<Report>),
    Full(usize, Box<Snapshot>, Box<Report>),
}

pub fn run(mut plan: Plan) -> ExitCode {
    if plan.selection.contains(ModuleName::Stack) {
        // Builds the signature engine while the network works.
        insite_core::detect::warm_up();
    }
    let mut printer = Printer::new(plan.format, plan.inputs.len());
    // One site on an interactive terminal: the fast report first, the browser
    // section when it is ready.
    printer.progressive = plan.browser.is_some()
        && plan.inputs.len() == 1
        && matches!(plan.format, Format::Terminal { .. })
        && std::io::stdout().is_terminal();
    let mut targets = Vec::new();
    let mut warned_credentials = false;
    // What the live view labels its rows with, one per valid target.
    let mut shown = Vec::new();
    for input in &plan.inputs {
        match Target::parse(input) {
            Ok(t) => {
                if t.credentials_ignored && !warned_credentials {
                    warned_credentials = true;
                    eprintln!("insite: credentials in the URL are ignored (they are not sent or saved)");
                }
                // A target's index is its position among the valid ones: it orders like the
                // input and is the row of the live view.
                targets.push((targets.len(), t));
                shown.push(input.clone());
            }
            Err(e) => {
                eprintln!("insite: {input}: {e}");
                printer.exit.usage = true;
            }
        }
    }
    if targets.is_empty() {
        return printer.finish();
    }
    let mut save = match plan.save.as_deref().map(Writer::create).transpose() {
        Ok(w) => w,
        Err(e) => return crate::usage_error(&e),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let started = Instant::now();
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    plan.opts.stop = Some(stop.clone());
    let live = matches!(plan.format, Format::Live { .. });
    let mut ui_thread = None;
    let result = runtime.block_on(async {
        let collector = Collector::with(Resolver::from_system()?, Tls::new(&[], plan.native_roots)?);
        // The live view starts with the collection, so the shell's prompt waits for it.
        let ui = match plan.format {
            Format::Live { verbose } => {
                live::restore_on_panic();
                let (ui, thread) = live::spawn_ui(shown, plan.selection, verbose, plan.browser.is_some());
                ui_thread = Some(thread);
                Some(ui)
            }
            _ => None,
        };
        let link = ui.as_ref().map(UiLink::to);
        // First Ctrl-C: close every snapshot with what has arrived and print the
        // reports. Second: quit at once.
        let notice = link.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let text = "insite: interrupted; printing what arrived (Ctrl-C again to quit)";
                match &notice {
                    Some(ui) => ui.send(UiEvent::Message(text.to_owned())),
                    None => eprintln!("\n{text}"),
                }
                let _ = stop_tx.send(true);
                if tokio::signal::ctrl_c().await.is_ok() {
                    if notice.is_some() {
                        live::quit();
                    }
                    // No destructors run on this exit: stop the browsers and delete
                    // their profiles first.
                    insite_core::collect::browser::cleanup_all();
                    std::process::exit(130);
                }
            }
        });
        let (tx, mut rx) = mpsc::channel::<Ready>(plan.concurrency.max(1));
        let permits = Arc::new(Semaphore::new(plan.concurrency));
        let browsers = Arc::new(Semaphore::new(BROWSERS));
        let opts = Arc::new(plan.opts);
        let browser = plan.browser.map(Arc::new);
        for group in by_domain(targets) {
            let (collector, opts, permits, tx) = (collector.clone(), opts.clone(), permits.clone(), tx.clone());
            let (browser, browsers) = (browser.clone(), browsers.clone());
            let selection = plan.selection;
            let stop = stop.clone();
            let link = link.clone();
            tokio::spawn(async move {
                for (n, (index, target)) in group.into_iter().enumerate() {
                    if n > 0 {
                        tokio::time::sleep(SAME_DOMAIN_PAUSE).await;
                    }
                    let permit = permits.acquire().await.expect("the semaphore is never closed");
                    // Sites not started before an interruption are not started at all.
                    if *stop.borrow() {
                        return;
                    }
                    // The browser process starts at t = 0, while the fast collection runs,
                    // when a browser slot is free. Its deadline counts from the slot, not
                    // from t = 0: a site queued behind other visits still gets its time.
                    let launch = browser.as_ref().map(|b| {
                        let (proxy, browsers, stop, timeout) =
                            (b.proxy.clone(), browsers.clone(), stop.clone(), b.timeout);
                        let link = link.clone();
                        tokio::spawn(async move {
                            let (slot, deadline) = acquire_browser_slot(browsers, timeout, stop).await;
                            if let Some(ui) = &link {
                                ui.send(UiEvent::Launching { site: index });
                            }
                            let launched = Browser::launch(proxy.as_deref(), &deadline).await;
                            (launched, slot, deadline)
                        })
                    });
                    // Each site reports its own progress, so a batch's stages do not interleave.
                    let (progress, forwarder) = match &link {
                        Some(ui) => {
                            let (progress, forwarder) = Forwarder::spawn(ui.clone(), index);
                            (Some(progress), Some(forwarder))
                        }
                        None => (None, None),
                    };
                    let site_opts = match &progress {
                        Some(progress) => {
                            let mut site_opts = (*opts).clone();
                            site_opts.progress = Some(progress.clone());
                            Cow::Owned(site_opts)
                        }
                        None => Cow::Borrowed(&*opts),
                    };
                    let mut snapshot = collector.collect(&target, &site_opts).await;
                    drop(permit);
                    if let (Some(launch), Some(plan)) = (launch, browser.as_ref()) {
                        if let Some((_, mut report)) = analyzed(snapshot.clone(), selection).await {
                            report.modules.browser = Module::skipped("the browser is still loading the page");
                            let _ = tx.send(Ready::Fast(index, Box::new(report))).await;
                        }
                        let visit = match &progress {
                            Some(progress) => Cow::Owned(Visit {
                                progress: Some(progress.clone()),
                                ..plan.visit.clone()
                            }),
                            None => Cow::Borrowed(&plan.visit),
                        };
                        // Where the fast collection ended, or the input when it did not.
                        let url = match (snapshot.chain.last(), &snapshot.page) {
                            (Some(hop), Some(_)) => hop.url.clone(),
                            _ => target.url.to_string(),
                        };
                        snapshot.browser = Some(match launch.await {
                            Ok((Ok(mut b), slot, deadline)) => {
                                let data = b.visit(&url, &visit, &deadline).await;
                                b.close().await;
                                drop(slot);
                                data
                            }
                            Ok((Err(e), _, _)) => BrowserData {
                                error: Some(e),
                                ..BrowserData::default()
                            },
                            Err(e) => BrowserData {
                                error: Some(e.to_string()),
                                ..BrowserData::default()
                            },
                        });
                    }
                    // What is still queued goes out before the report; the progress channel
                    // may stay open (auxiliary tasks hold senders), so it is not awaited.
                    if let Some(forwarder) = forwarder {
                        forwarder.finish().await;
                    }
                    let Some((snapshot, report)) = analyzed(snapshot, selection).await else {
                        if let Some(ui) = &link {
                            ui.send(UiEvent::Gone { site: index });
                        }
                        continue;
                    };
                    if tx
                        .send(Ready::Full(index, Box::new(snapshot), Box::new(report)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
        drop(tx);
        while let Some(ready) = rx.recv().await {
            match ready {
                Ready::Fast(site, report) => {
                    printer.print_fast(&report);
                    if let Some(ui) = &ui {
                        let _ = ui.send(UiEvent::Fast { site, report });
                    }
                }
                Ready::Full(index, snapshot, report) => {
                    if let Some(writer) = save.as_mut()
                        && let Err(e) = writer.write(&snapshot)
                    {
                        let text = format!("insite: could not save the snapshot: {e}");
                        match &ui {
                            Some(ui) => {
                                let _ = ui.send(UiEvent::Message(text));
                            }
                            None => eprintln!("{text}"),
                        }
                        save = None;
                    }
                    printer.print(index, &report);
                    if let Some(ui) = &ui {
                        let _ = ui.send(UiEvent::Full { site: index, report });
                    }
                }
            }
        }
        // `ui` is dropped here, the last sender that keeps the live view open.
        Ok::<_, String>(())
    });
    // The live view commits what is left and gives the terminal back before anything else
    // is printed.
    if let Some(thread) = ui_thread {
        let _ = thread.join();
    }
    shut_down(runtime);
    if let Some(writer) = save
        && let Err(e) = writer.finish()
    {
        eprintln!("insite: could not save the snapshots: {e}");
    }
    if let Err(e) = result {
        eprintln!("insite: {e}");
        return ExitCode::from(2);
    }
    // The live view has its own summary.
    if !live && plan.inputs.len() > 1 && std::io::stderr().is_terminal() {
        eprintln!("{}", printer.summary(started.elapsed()));
    }
    let code = printer.finish();
    if *stop.borrow() { ExitCode::from(130) } else { code }
}

/// Waits for one of the browser slots. The returned deadline, `timeout` long,
/// starts when the slot is held.
async fn acquire_browser_slot(
    slots: Arc<Semaphore>,
    timeout: Duration,
    stop: tokio::sync::watch::Receiver<bool>,
) -> (OwnedSemaphorePermit, Deadline) {
    let slot = slots.acquire_owned().await.expect("the semaphore is never closed");
    let deadline = Deadline::new(tokio::time::Instant::now() + timeout, Some(stop));
    (slot, deadline)
}

/// Ends the runtime without waiting for blocking threads. A name lookup the
/// system resolver has not answered (`getaddrinfo` runs on one) cannot be
/// cancelled, and waiting for it would leave the CLI hanging after its report.
/// Browsers still alive are stopped first.
fn shut_down(runtime: tokio::runtime::Runtime) {
    insite_core::collect::browser::cleanup_all();
    runtime.shutdown_background();
}

/// The analysis is CPU work: it runs off the IO threads.
async fn analyzed(snapshot: Snapshot, selection: Selection) -> Option<(Snapshot, Report)> {
    tokio::task::spawn_blocking(move || {
        let report = analyze_selected(&snapshot, selection);
        (snapshot, report)
    })
    .await
    .ok()
}

/// Targets grouped by registrable domain, groups in input order.
fn by_domain(targets: Vec<(usize, Target)>) -> Vec<Vec<(usize, Target)>> {
    let mut groups: Vec<(String, Vec<(usize, Target)>)> = Vec::new();
    for (index, target) in targets {
        let key = target.url.host_str().map(registrable).unwrap_or_default();
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, group)) => group.push((index, target)),
            None => groups.push((key, vec![(index, target)])),
        }
    }
    groups.into_iter().map(|(_, g)| g).collect()
}

/// The exit code: 2 for bad input, 1 when a site was unreachable, 3 when a
/// report was partial, 0 otherwise. In batch mode, the most serious wins.
#[derive(Default)]
pub struct Exit {
    pub usage: bool,
    complete: usize,
    partial: usize,
    unreachable: usize,
}

impl Exit {
    pub fn record(&mut self, outcome: &Outcome) {
        match outcome {
            Outcome::Complete => self.complete += 1,
            Outcome::Partial { .. } => self.partial += 1,
            Outcome::Unreachable { .. } => self.unreachable += 1,
        }
    }

    pub fn code(&self) -> ExitCode {
        ExitCode::from(if self.usage {
            2
        } else if self.unreachable > 0 {
            1
        } else if self.partial > 0 {
            3
        } else {
            0
        })
    }
}

/// Prints each report in the chosen format as it arrives. A JSON document is
/// printed whole at the end: an object for one site, an array for several.
pub struct Printer {
    format: Format,
    inputs: usize,
    printed: usize,
    json: Vec<(usize, Report)>,
    pub exit: Exit,
    /// Print the fast report, then only the browser's additions.
    pub progressive: bool,
    fast_printed: bool,
    /// NDJSON lines carry a phase once a fast line was printed.
    phased: bool,
}

impl Printer {
    pub fn new(format: Format, inputs: usize) -> Self {
        Printer {
            format,
            inputs,
            printed: 0,
            json: Vec::new(),
            exit: Exit::default(),
            progressive: false,
            fast_printed: false,
            phased: false,
        }
    }

    /// The report before the browser finished: shown on an interactive terminal
    /// with one site, and as a `phase: fast` line in NDJSON.
    pub fn print_fast(&mut self, report: &Report) {
        match self.format {
            Format::Terminal { color, verbose, width } if self.progressive => {
                write_out(&render::terminal(report, color, verbose, width));
                self.fast_printed = true;
            }
            Format::Ndjson => {
                let mut report = report.clone();
                report.phase = Some("fast");
                write_out(&(serde_json::to_string(&report).expect("reports serialize") + "\n"));
                self.phased = true;
            }
            _ => {}
        }
    }

    pub fn print(&mut self, index: usize, report: &Report) {
        self.exit.record(&report.outcome);
        // The live view prints on its own; the printer only keeps the outcomes.
        if matches!(self.format, Format::Live { .. }) {
            return;
        }
        let text = match self.format {
            Format::Terminal { color, verbose, width } if self.fast_printed => {
                render::browser_update(report, color, verbose, width)
            }
            Format::Ndjson if self.phased => {
                let mut report = report.clone();
                report.phase = Some("full");
                serde_json::to_string(&report).expect("reports serialize") + "\n"
            }
            Format::Terminal { color, verbose, width } => {
                let separator = if self.printed > 0 { "\n" } else { "" };
                format!("{separator}{}", render::terminal(report, color, verbose, width))
            }
            Format::Ndjson => serde_json::to_string(report).expect("reports serialize") + "\n",
            Format::Markdown => {
                let separator = if self.printed > 0 { "\n---\n\n" } else { "" };
                format!("{separator}{}", markdown::render(report))
            }
            Format::Json { .. } => {
                self.json.push((index, report.clone()));
                String::new()
            }
            Format::Live { .. } => unreachable!("returned above"),
        };
        self.printed += 1;
        write_out(&text);
    }

    pub fn summary(&self, elapsed: Duration) -> String {
        let e = &self.exit;
        let mut parts = vec![format!("{} complete", e.complete)];
        if e.partial > 0 {
            parts.push(format!("{} partial", e.partial));
        }
        if e.unreachable > 0 {
            parts.push(format!("{} unreachable", e.unreachable));
        }
        format!(
            "insite: {} sites in {:.1} s: {}",
            e.complete + e.partial + e.unreachable,
            elapsed.as_secs_f64(),
            parts.join(", ")
        )
    }

    pub fn finish(mut self) -> ExitCode {
        if let Format::Json { pretty } = self.format
            && !self.json.is_empty()
        {
            self.json.sort_by_key(|(i, _)| *i);
            let reports: Vec<&Report> = self.json.iter().map(|(_, r)| r).collect();
            let value = if self.inputs == 1 {
                serde_json::to_value(reports[0])
            } else {
                serde_json::to_value(&reports)
            }
            .expect("reports serialize");
            let text = if pretty {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            };
            write_out(&(text.expect("reports serialize") + "\n"));
        }
        self.exit.code()
    }
}

/// Writes to stdout, ignoring a closed pipe (`insite ... | head`).
pub(crate) fn write_out(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|_| out.flush());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_keep_input_order_and_share_domains() {
        let targets = ["a.com", "www.b.com", "c.org", "shop.a.com", "b.com"]
            .iter()
            .enumerate()
            .map(|(i, t)| (i, Target::parse(t).unwrap()))
            .collect();
        let groups: Vec<Vec<usize>> = by_domain(targets)
            .into_iter()
            .map(|g| g.into_iter().map(|(i, _)| i).collect())
            .collect();
        assert_eq!(groups, [vec![0, 3], vec![1, 4], vec![2]]);
    }

    #[test]
    fn shutting_down_does_not_wait_for_a_stuck_lookup() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        // What `lookup_host` does: a blocking call that outlives its future.
        runtime.block_on(async {
            let lookup = tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(5)));
            let _ = tokio::time::timeout(Duration::from_millis(50), lookup).await;
        });
        let started = Instant::now();
        shut_down(runtime);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn the_browser_deadline_starts_when_the_slot_is_held() {
        let slots = Arc::new(Semaphore::new(1));
        let (_, stop) = tokio::sync::watch::channel(false);
        let timeout = Duration::from_millis(400);
        let started = tokio::time::Instant::now();
        let (first, _) = acquire_browser_slot(slots.clone(), timeout, stop.clone()).await;
        let queued = tokio::spawn(acquire_browser_slot(slots, timeout, stop));
        // The first visit uses most of the time a site is allowed once it has a slot.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let freed = tokio::time::Instant::now();
        drop(first);
        let (_slot, deadline) = queued.await.unwrap();
        assert!(deadline.instant() >= freed + timeout, "counted from before the slot");
        assert!(deadline.instant() < freed + timeout + Duration::from_millis(200));
        assert!(deadline.instant() > started + timeout);
        assert!(!deadline.passed());
    }

    #[test]
    fn the_most_serious_exit_code_wins() {
        let mut exit = Exit::default();
        exit.record(&Outcome::Complete);
        assert_eq!(exit.code(), ExitCode::from(0));
        exit.record(&Outcome::Partial { reasons: Vec::new() });
        assert_eq!(exit.code(), ExitCode::from(3));
        exit.record(&Outcome::Unreachable { reason: String::new() });
        assert_eq!(exit.code(), ExitCode::from(1));
        exit.usage = true;
        assert_eq!(exit.code(), ExitCode::from(2));
    }
}
