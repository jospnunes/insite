//! `--browser`: a headless Chromium driven over the DevTools protocol, for what
//! only a browser sees: Core Web Vitals, every resource the page loads, console
//! errors, and the page as JavaScript builds it.
//!
//! The process starts at t = 0, in parallel with the fast collection; the
//! navigation starts once that collection is done, so the browser never
//! competes for bandwidth with the timings measured on our own connection.

pub mod cdp;

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;

use self::cdp::{Connection, Event};
use crate::collect::deadline::Deadline;
use crate::collect::progress::{BrowserStage, Progress, ProgressSender, emit};
use crate::snapshot::{BrowserData, BrowserMetrics, BrowserResource};

/// The rendered HTML kept in the snapshot, like the page body.
const HTML_LIMIT: usize = 5 << 20;
/// Lighthouse's defaults: the page must be quiet this long after `load`.
const QUIET: Duration = Duration::from_millis(1000);
/// Requests still in flight that count as quiet ("network-2-quiet").
const QUIET_INFLIGHT: usize = 2;
/// Pages that never go quiet are read this long after `load`, marked partial.
const QUIET_CAP: Duration = Duration::from_secs(15);
/// Kept for the final evaluation before the browser deadline.
const EVALUATE_RESERVE: Duration = Duration::from_millis(1500);
const CONSOLE_LIMIT: usize = 20;
/// Resources kept in the snapshot; the rest are counted out, with a warning.
const RESOURCE_LIMIT: usize = 2000;
/// Characters kept of each resource URL.
const URL_LIMIT: usize = 2048;
/// Requests tracked as in flight. Past it the page is far from quiet anyway.
const INFLIGHT_LIMIT: usize = 5000;
/// The browser's last stderr lines kept, to explain a failed start.
const STDERR_LINES: usize = 5;

/// How the page is emulated.
#[derive(Debug, Clone)]
pub struct Visit {
    pub mobile: bool,
    /// Lighthouse's mobile throttling, devtools method: Slow 4G and 4x CPU.
    pub throttle: bool,
    /// Appended to the browser's user agent (the hybrid profile's `insite/x`).
    pub user_agent_suffix: Option<String>,
    pub accept_language: String,
    /// Property paths the `js` signatures read, such as `React.version`.
    pub js_paths: Vec<String>,
    /// Selector and element property pairs the `dom` signatures read.
    pub dom_properties: Vec<(String, String)>,
    /// Receives the visit's stages (`Progress::Browser`); `None` sends nothing.
    pub progress: Option<ProgressSender>,
}

pub struct Browser {
    child: Child,
    conn: Connection,
    events: mpsc::UnboundedReceiver<Event>,
    profile: Profile,
    executable: PathBuf,
    product: String,
    warnings: Vec<String>,
    /// The last lines the browser printed to stderr, read until it closes.
    #[cfg_attr(not(unix), allow(dead_code))]
    stderr: Arc<Mutex<VecDeque<String>>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    stderr_reader: Option<std::thread::JoinHandle<()>>,
}

/// `CHROME_PATH`, then the usual places of Chrome, Chromium, Edge and Brave.
pub fn find_executable() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("CHROME_PATH").map(PathBuf::from) {
        return if path.is_file() {
            Ok(path)
        } else {
            Err(format!(
                "CHROME_PATH points to {}, which does not exist",
                path.display()
            ))
        };
    }
    let absolute: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ]
    } else {
        &["/opt/google/chrome/chrome", "/usr/bin/chromium", "/snap/bin/chromium"]
    };
    let names = [
        "google-chrome-stable",
        "google-chrome",
        "chromium",
        "chromium-browser",
        "microsoft-edge",
        "brave-browser",
    ];
    let in_path = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)));
    absolute
        .iter()
        .map(PathBuf::from)
        .chain(in_path)
        .find(|p| p.is_file())
        .ok_or_else(|| "no Chrome, Chromium, Edge or Brave found; set CHROME_PATH".to_owned())
}

impl Browser {
    /// Starts the browser with a new, temporary profile.
    #[cfg(unix)]
    pub async fn launch(proxy: Option<&str>, deadline: &Deadline) -> Result<Browser, String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let executable = find_executable()?;
        let mut warnings = Vec::new();
        let profile = temporary_profile(&executable);

        let mut command = Command::new(&executable);
        command
            .args([
                "--headless",
                "--remote-debugging-pipe",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-sync",
                "--metrics-recording-only",
                "--mute-audio",
                "--hide-scrollbars",
                "--password-store=basic",
                "--use-mock-keychain",
            ])
            .arg(format!("--user-data-dir={}", profile.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // Its own process group, with the browser as leader: its helpers
            // (zygote, renderers, GPU, network service, crashpad) join it, and
            // `kill_group` ends them all. A Ctrl-C at the terminal no longer
            // reaches the browser directly; we stop it ourselves.
            .process_group(0);
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            command.arg("--no-sandbox");
            warnings.push("running as root, so the browser runs without its sandbox".to_owned());
        }
        if let Some(proxy) = proxy {
            command.arg(format!("--proxy-server={proxy}"));
        }

        // Commands go to the child's fd 3; responses come from its fd 4.
        let (child_reads, we_write) = std::io::pipe().map_err(|e| e.to_string())?;
        let (we_read, child_writes) = std::io::pipe().map_err(|e| e.to_string())?;
        let (r, w) = (child_reads.as_raw_fd(), child_writes.as_raw_fd());
        // SAFETY: between fork and exec only async-signal-safe calls: fcntl and
        // dup2. Copying both ends above 10 first keeps a dup2 onto 3 or 4 from
        // closing the other end; dup2 clears close-on-exec on the targets.
        unsafe {
            command.pre_exec(move || {
                let (r, w) = (libc::fcntl(r, libc::F_DUPFD, 10), libc::fcntl(w, libc::F_DUPFD, 10));
                if r < 0 || w < 0 || libc::dup2(r, 3) < 0 || libc::dup2(w, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // The last step that can fail: the profile is created only now, and
        // removed again if the browser does not start.
        let profile = Profile::create(profile).map_err(|e| format!("could not create the profile: {e}"))?;
        let mut child = command
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", executable.display()))?;
        profile.attach(child.id());
        drop((child_reads, child_writes));
        // Drained to the end, or the browser blocks once the pipe is full.
        let stderr = Arc::new(Mutex::new(VecDeque::new()));
        let stderr_reader = child.stderr.take().map(|pipe| {
            let lines = Arc::clone(&stderr);
            std::thread::spawn(move || keep_last_lines(pipe, &lines))
        });
        let (conn, events) = Connection::new(we_read, we_write);
        let mut browser = Browser {
            child,
            conn,
            events,
            profile,
            executable,
            product: String::new(),
            warnings,
            stderr,
            stderr_reader,
        };
        match browser.conn.call("Browser.getVersion", json!({}), None, deadline).await {
            Ok(v) => {
                browser.product = v["product"].as_str().unwrap_or_default().to_owned();
                // A page cannot drop files into the user's Downloads.
                let denied = json!({ "behavior": "deny" });
                if let Err(e) = browser
                    .conn
                    .call("Browser.setDownloadBehavior", denied, None, deadline)
                    .await
                {
                    browser.warnings.push(format!("could not block downloads: {e}"));
                }
                Ok(browser)
            }
            Err(e) => {
                let reader = browser.stderr_reader.take();
                let printed = Arc::clone(&browser.stderr);
                browser.close().await;
                // The reader ends when stderr closes, just after the browser exits.
                if let Some(reader) = reader {
                    let until = Instant::now() + Duration::from_millis(500);
                    while !reader.is_finished() && Instant::now() < until {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                let printed: Vec<String> = printed.lock().map(|l| l.iter().cloned().collect()).unwrap_or_default();
                Err(if printed.is_empty() {
                    format!("the browser did not start: {e}")
                } else {
                    format!("the browser did not start: {e}; it printed: {}", printed.join(" | "))
                })
            }
        }
    }

    #[cfg(not(unix))]
    pub async fn launch(_proxy: Option<&str>, _deadline: &Deadline) -> Result<Browser, String> {
        Err("--browser is not available on this platform yet".into())
    }

    /// Loads `url` and gathers everything the browser saw. Never fails: what
    /// went wrong is in `error`, with whatever was measured before it.
    pub async fn visit(&mut self, url: &str, visit: &Visit, deadline: &Deadline) -> BrowserData {
        let mut data = BrowserData {
            product: self.product.clone(),
            executable: self.executable.display().to_string(),
            mobile: visit.mobile,
            throttled: visit.throttle,
            warnings: self.warnings.clone(),
            ..BrowserData::default()
        };
        if let Err(e) = self.run(url, visit, deadline, &mut data).await {
            data.error = Some(e);
        }
        data
    }

    async fn run(
        &mut self,
        url: &str,
        visit: &Visit,
        deadline: &Deadline,
        data: &mut BrowserData,
    ) -> Result<(), String> {
        let target = self
            .conn
            .call("Target.createTarget", json!({ "url": "about:blank" }), None, deadline)
            .await?;
        let target_id = target["targetId"].as_str().ok_or("no target id")?.to_owned();
        let attached = self
            .conn
            .call(
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }),
                None,
                deadline,
            )
            .await?;
        let session = attached["sessionId"].as_str().ok_or("no session id")?.to_owned();
        let s = Some(session.as_str());
        let call = |method: &'static str, params: Value| self.conn.call(method, params, s, deadline);

        for method in ["Page.enable", "Network.enable", "Runtime.enable", "Log.enable"] {
            call(method, json!({})).await?;
        }
        call("Page.setLifecycleEventsEnabled", json!({ "enabled": true })).await?;
        let major = self
            .product
            .split('/')
            .nth(1)
            .and_then(|v| v.split('.').next())
            .unwrap_or("150");
        let (width, height, scale) = if visit.mobile {
            (412, 823, 1.75)
        } else {
            (1350, 940, 1.0)
        };
        let mut user_agent = if visit.mobile {
            format!(
                "Mozilla/5.0 (Linux; Android 11; moto g power (2022)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Mobile Safari/537.36"
            )
        } else {
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
            )
        };
        if let Some(suffix) = &visit.user_agent_suffix {
            user_agent = format!("{user_agent} {suffix}");
        }
        data.user_agent = user_agent.clone();
        call(
            "Emulation.setDeviceMetricsOverride",
            json!({ "width": width, "height": height, "deviceScaleFactor": scale, "mobile": visit.mobile }),
        )
        .await?;
        call(
            "Emulation.setUserAgentOverride",
            json!({ "userAgent": user_agent, "acceptLanguage": visit.accept_language }),
        )
        .await?;
        call("Emulation.setTouchEmulationEnabled", json!({ "enabled": visit.mobile })).await?;
        if visit.throttle {
            // Lighthouse's mobileSlow4G with the devtools method: 150 ms RTT x 3.75,
            // 1.6 Mbps x 0.9 down, 750 kbps x 0.9 up, and a 4x slower CPU.
            call(
                "Network.emulateNetworkConditions",
                json!({
                    "offline": false,
                    "latency": 562.5,
                    "downloadThroughput": 1474.56 * 1024.0 / 8.0,
                    "uploadThroughput": 607.5 * 1024.0 / 8.0,
                }),
            )
            .await?;
            call("Emulation.setCPUThrottlingRate", json!({ "rate": 4 })).await?;
        }
        call("Page.addScriptToEvaluateOnNewDocument", json!({ "source": OBSERVER })).await?;

        // Drop events from before the navigation.
        while self.events.try_recv().is_ok() {}
        // Before the call: it answers only once the navigation commits, which a slow server delays.
        emit(&visit.progress, Progress::Browser(BrowserStage::Navigating));
        let navigated = self
            .conn
            .call("Page.navigate", json!({ "url": url }), s, deadline)
            .await?;
        if let Some(e) = navigated["errorText"].as_str().filter(|e| !e.is_empty()) {
            return Err(format!("navigation failed: {e}"));
        }

        let stop_waiting = deadline
            .instant()
            .checked_sub(EVALUATE_RESERVE)
            .unwrap_or(deadline.instant());
        let frame = navigated["frameId"].as_str().unwrap_or_default().to_owned();
        let quiet = self
            .wait_until_quiet(&session, &frame, stop_waiting, deadline, &visit.progress, data)
            .await;
        data.quiet = quiet;
        emit(&visit.progress, Progress::Browser(BrowserStage::Quiet));

        let expression = collector_expression(&visit.js_paths, &visit.dom_properties);
        let evaluate = self.conn.call(
            "Runtime.evaluate",
            json!({ "expression": expression, "returnByValue": true, "awaitPromise": true }),
            s,
            deadline,
        );
        tokio::pin!(evaluate);
        // A dialog that opens now would block the page, and the evaluation with it.
        let evaluated = loop {
            tokio::select! {
                result = &mut evaluate => break result?,
                Some(event) = self.events.recv() => {
                    if event.method == "Page.javascriptDialogOpening" && event.session.as_deref() == s {
                        dismiss_dialog(&self.conn, &session, deadline).await;
                    }
                }
            }
        };
        if let Some(e) = evaluated.get("exceptionDetails") {
            return Err(format!(
                "the page script failed: {}",
                e["text"].as_str().unwrap_or("exception")
            ));
        }
        read_evaluation(&evaluated["result"]["value"], data);
        let _ = self
            .conn
            .call("Target.closeTarget", json!({ "targetId": target_id }), None, deadline)
            .await;
        Ok(())
    }

    /// Records resources and console errors until the page is quiet after
    /// `load` and its first contentful paint, the quiet cap passes (false) or
    /// `until` comes. Waiting for the paint, as Lighthouse does, matters when
    /// the browser paints late (a cold start on a slow machine): read before
    /// it, the page has no FCP or LCP.
    async fn wait_until_quiet(
        &mut self,
        session: &str,
        frame: &str,
        until: Instant,
        deadline: &Deadline,
        progress: &Option<ProgressSender>,
        data: &mut BrowserData,
    ) -> bool {
        let started = Instant::now();
        let mut loaded_at: Option<Instant> = None;
        let mut painted = false;
        let mut quiet_since: Option<Instant> = None;
        let mut inflight: Inflight = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                event = self.events.recv() => {
                    let Some(event) = event else { return false };
                    if event.session.as_deref() != Some(session) {
                        continue;
                    }
                    if event.method == "Page.javascriptDialogOpening" {
                        dismiss_dialog(&self.conn, session, deadline).await;
                        continue;
                    }
                    record(&event, &mut inflight, data);
                    if event.method == "Page.loadEventFired" && loaded_at.is_none() {
                        loaded_at = Some(Instant::now());
                        data.load_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                        emit(progress, Progress::Browser(BrowserStage::Loaded));
                    }
                    if event.method == "Page.lifecycleEvent"
                        && event.params["name"] == "firstContentfulPaint"
                        && event.params["frameId"] == frame
                    {
                        painted = true;
                    }
                }
                _ = tick.tick() => {}
                _ = deadline.reached() => return false,
            }
            let now = Instant::now();
            if now >= until {
                return false;
            }
            let Some(loaded) = loaded_at else { continue };
            if painted && inflight.len() <= QUIET_INFLIGHT {
                let since = *quiet_since.get_or_insert(now);
                if now - since >= QUIET && now - loaded >= QUIET {
                    return true;
                }
            } else {
                quiet_since = None;
            }
            if now - loaded >= QUIET_CAP {
                return false;
            }
        }
    }

    /// Closes the browser and deletes its profile.
    pub async fn close(mut self) {
        let deadline = Deadline::new(Instant::now() + Duration::from_secs(2), None);
        let _ = self.conn.call("Browser.close", json!({}), None, &deadline).await;
        for _ in 0..20 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Dropping kills a browser that is still running and deletes the profile.
    }

    /// The browser's temporary profile directory.
    pub fn profile(&self) -> &Path {
        &self.profile.path
    }

    /// The browser's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

/// A browser dropped without `close` (an error path, a panic, an abandoned
/// future) must not outlive us or leave its profile behind.
impl Drop for Browser {
    fn drop(&mut self) {
        // The whole group, not only the leader: the helpers would outlive it
        // for a moment and keep writing into the profile. The leader is not
        // reaped yet, so its id is still the group's.
        #[cfg(unix)]
        kill_group(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The process is gone: its id may be reused, so it leaves the registry.
        self.profile.detach();
    }
}

/// Profiles of the live browsers, with their process ids, so that a quit that
/// runs no destructors (a second Ctrl-C) can still clean up.
static LIVE: Mutex<Vec<(PathBuf, Option<u32>)>> = Mutex::new(Vec::new());

/// A browser's temporary directory, deleted when it is dropped.
struct Profile {
    path: PathBuf,
}

impl Profile {
    fn create(path: PathBuf) -> std::io::Result<Profile> {
        std::fs::create_dir_all(&path)?;
        if let Ok(mut live) = LIVE.lock() {
            live.push((path.clone(), None));
        }
        Ok(Profile { path })
    }

    fn attach(&self, pid: u32) {
        if let Ok(mut live) = LIVE.lock()
            && let Some(entry) = live.iter_mut().find(|(p, _)| *p == self.path)
        {
            entry.1 = Some(pid);
        }
    }

    fn detach(&self) {
        if let Ok(mut live) = LIVE.lock()
            && let Some(entry) = live.iter_mut().find(|(p, _)| *p == self.path)
        {
            entry.1 = None;
        }
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        if let Ok(mut live) = LIVE.lock() {
            live.retain(|(p, _)| *p != self.path);
        }
        remove_dir_with_retry(&self.path);
    }
}

/// How long a profile removal keeps trying.
const REMOVE_BUDGET: Duration = Duration::from_millis(500);

/// Deletes `path`, trying again for a short while when the browser's last
/// writes race with the removal (the directory is not empty by the time it is
/// removed, or a file vanishes under the walk). Best effort: other errors, and
/// running out of time, are ignored.
fn remove_dir_with_retry(path: &Path) {
    let until = std::time::Instant::now() + REMOVE_BUDGET;
    let mut pause = Duration::from_millis(2);
    loop {
        let racing = match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    if !path.exists() {
                        return;
                    }
                    true
                }
                std::io::ErrorKind::DirectoryNotEmpty => true,
                _ => false,
            },
        };
        if !racing || std::time::Instant::now() >= until {
            return;
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(50));
    }
}

/// Ends the process group `leader` heads, with every helper in it.
#[cfg(unix)]
fn kill_group(leader: u32) {
    // Ids 0 and 1 would mean our own group and init's: never a browser's.
    if let Ok(pgid) = i32::try_from(leader)
        && pgid > 1
    {
        // SAFETY: kill has no memory preconditions; the group is one we created
        // with `process_group(0)` and its leader has not been waited for.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
}

/// Kills every live browser and deletes its profile, for a process that is
/// about to exit without running destructors. Best effort.
pub fn cleanup_all() {
    let live = match LIVE.try_lock() {
        Ok(mut live) => std::mem::take(&mut *live),
        Err(_) => return,
    };
    for (path, pid) in live {
        #[cfg(unix)]
        if let Some(pid) = pid {
            // The leader of a group of ours, not yet waited for.
            kill_group(pid);
        }
        #[cfg(not(unix))]
        let _ = pid;
        remove_dir_with_retry(&path);
    }
}

/// Reads `pipe` to the end, keeping its last non-empty lines.
#[cfg(unix)]
fn keep_last_lines(pipe: impl std::io::Read, lines: &Mutex<VecDeque<String>>) {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(pipe);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let text: String = String::from_utf8_lossy(&line).trim().chars().take(200).collect();
        if text.is_empty() {
            continue;
        }
        if let Ok(mut lines) = lines.lock() {
            if lines.len() == STDERR_LINES {
                lines.pop_front();
            }
            lines.push_back(text);
        }
    }
}

/// A fresh directory per run. Chromium from snap cannot read /tmp, so its
/// profile goes under ~/snap/chromium/common.
fn temporary_profile(executable: &Path) -> PathBuf {
    // The count keeps apart browsers this process starts at once: the clock
    // on macOS has only microseconds, and two browsers sharing a profile both
    // fail on its lock.
    static STARTED: AtomicU32 = AtomicU32::new(0);
    let unique = format!(
        "insite-{}-{}-{}",
        std::process::id(),
        STARTED.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
    );
    let snap_home = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("snap/chromium/common"));
    match snap_home {
        Some(dir) if executable.starts_with("/snap/") => dir.join(unique),
        _ => std::env::temp_dir().join(unique),
    }
}

/// Requests in flight: the index of their entry in `resources`, or `None` for
/// a request past the cap, which is only counted.
type Inflight = HashMap<String, Option<usize>>;

const RESOURCES_CUT: &str = "the page made more requests than are listed; the resource list was cut";

/// Network and console events into the snapshot's lists.
fn record(event: &Event, inflight: &mut Inflight, data: &mut BrowserData) {
    let p = &event.params;
    let id = p["requestId"].as_str().unwrap_or_default().to_owned();
    match event.method.as_str() {
        "Network.requestWillBeSent" => {
            let url = p["request"]["url"].as_str().unwrap_or_default();
            if url.starts_with("data:") {
                return;
            }
            let url: String = url.chars().take(URL_LIMIT).collect();
            let kind = p["type"].as_str().unwrap_or("Other").to_owned();
            match inflight.get(&id) {
                // A redirect: the same request continues at a new URL.
                Some(Some(i)) => data.resources[*i].url = url,
                Some(None) => {}
                None => {
                    let slot = if data.resources.len() < RESOURCE_LIMIT {
                        data.resources.push(BrowserResource {
                            url,
                            kind,
                            ..BrowserResource::default()
                        });
                        Some(data.resources.len() - 1)
                    } else {
                        if !data.warnings.iter().any(|w| w == RESOURCES_CUT) {
                            data.warnings.push(RESOURCES_CUT.to_owned());
                        }
                        None
                    };
                    if inflight.len() < INFLIGHT_LIMIT {
                        inflight.insert(id, slot);
                    }
                }
            }
        }
        "Network.responseReceived" => {
            if let Some(&Some(i)) = inflight.get(&id) {
                let r = &mut data.resources[i];
                r.status = p["response"]["status"].as_u64().map(|s| s as u16);
                r.mime = p["response"]["mimeType"].as_str().map(str::to_owned);
                r.from_cache = p["response"]["fromDiskCache"].as_bool().unwrap_or(false);
            }
        }
        "Network.loadingFinished" => {
            if let Some(Some(i)) = inflight.remove(&id) {
                data.resources[i].transferred = p["encodedDataLength"].as_f64().unwrap_or(0.0) as u64;
            }
        }
        "Network.loadingFailed" => {
            if let Some(Some(i)) = inflight.remove(&id) {
                data.resources[i].failed = p["errorText"].as_str().map(str::to_owned);
            }
        }
        "Runtime.exceptionThrown" => {
            let d = &p["exceptionDetails"];
            let text = d["exception"]["description"]
                .as_str()
                .or(d["text"].as_str())
                .unwrap_or("exception");
            push_console(data, text.lines().next().unwrap_or(text));
        }
        "Runtime.consoleAPICalled" if p["type"] == "error" => {
            let text: Vec<String> = p["args"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|a| {
                    a["value"]
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| a["description"].as_str().map(str::to_owned))
                })
                .collect();
            push_console(data, &text.join(" "));
        }
        "Log.entryAdded" if p["entry"]["level"] == "error" => {
            let entry = &p["entry"];
            let text = entry["text"].as_str().unwrap_or_default();
            match entry["url"].as_str() {
                Some(url) if !url.is_empty() => push_console(data, &format!("{text} ({url})")),
                _ => push_console(data, text),
            }
        }
        _ => {}
    }
}

/// Closes a JavaScript dialog (`alert`, `confirm`, `prompt`, `beforeunload`)
/// without accepting it: left open, it blocks the page's renderer.
async fn dismiss_dialog(conn: &Connection, session: &str, deadline: &Deadline) {
    let _ = conn
        .call(
            "Page.handleJavaScriptDialog",
            json!({ "accept": false }),
            Some(session),
            deadline,
        )
        .await;
}

fn push_console(data: &mut BrowserData, text: &str) {
    let text: String = text.chars().take(300).collect();
    if data.console.len() < CONSOLE_LIMIT && !text.is_empty() && !data.console.contains(&text) {
        data.console.push(text);
    }
}

fn read_evaluation(v: &Value, data: &mut BrowserData) {
    let ms = |key: &str| v[key].as_f64().filter(|x| *x > 0.0);
    data.url = v["url"].as_str().unwrap_or_default().to_owned();
    data.metrics = Some(BrowserMetrics {
        fcp_ms: ms("fcp"),
        lcp_ms: ms("lcp"),
        cls: v["cls"].as_f64().unwrap_or(0.0),
        tbt_ms: v["tbt"].as_f64().unwrap_or(0.0),
        long_tasks: v["longTasks"].as_u64().unwrap_or(0) as usize,
        dom_content_loaded_ms: ms("dcl"),
        load_ms: ms("load"),
    });
    if let Some(js) = v["js"].as_object() {
        data.js = js
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
            .collect();
        data.js.sort();
    }
    if let Some(props) = v["props"].as_array() {
        data.dom_properties = props
            .iter()
            .filter_map(|p| {
                let values = p[2]
                    .as_array()?
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect();
                Some((p[0].as_str()?.to_owned(), p[1].as_str()?.to_owned(), values))
            })
            .collect();
    }
    data.html = v["html"].as_str().map(str::to_owned);
    data.html_truncated = v["htmlTruncated"].as_bool().unwrap_or(false);
}

/// Runs before any page script: records paint, LCP, layout shifts (in session
/// windows, as Core Web Vitals defines CLS) and long tasks.
const OBSERVER: &str = r#"(() => {
  if (window !== window.top || window.__insite) return;
  const m = window.__insite = { cls: 0, longTasks: [], pending: [] };
  const observe = (type, each) => {
    try {
      const o = new PerformanceObserver(list => list.getEntries().forEach(each));
      o.observe({ type, buffered: true });
      m.pending.push(() => o.takeRecords().forEach(each));
    } catch (e) {}
  };
  observe('paint', e => { if (e.name === 'first-contentful-paint') m.fcp = e.startTime; });
  observe('largest-contentful-paint', e => { m.lcp = e.startTime; });
  let session = 0, first = 0, last = 0;
  observe('layout-shift', e => {
    if (e.hadRecentInput) return;
    if (session && e.startTime - last < 1000 && e.startTime - first < 5000) { session += e.value; }
    else { session = e.value; first = e.startTime; }
    last = e.startTime;
    if (session > m.cls) m.cls = session;
  });
  observe('longtask', e => m.longTasks.push([e.startTime, e.duration]));
})();"#;

/// One expression for everything read at the end: metrics, the `js` and `dom`
/// properties the signatures need, and the rendered HTML.
fn collector_expression(js_paths: &[String], dom_properties: &[(String, String)]) -> String {
    let paths = serde_json::to_string(js_paths).expect("strings serialize");
    let props = serde_json::to_string(dom_properties).expect("strings serialize");
    format!(
        r#"(async () => {{
  const m = window.__insite || {{ cls: 0, longTasks: [], pending: [] }};
  // Entries already recorded whose observer callback has not run yet.
  for (const take of m.pending) take();
  const text = v => ['string', 'number', 'boolean'].includes(typeof v) ? String(v) : '';
  const nav = performance.getEntriesByType('navigation')[0];
  const fcp = m.fcp ?? null;
  let tbt = 0;
  for (const [start, duration] of m.longTasks) if (fcp !== null && start >= fcp && duration > 50) tbt += duration - 50;
  const js = {{}};
  for (const path of {paths}) {{
    try {{
      let v = window, found = true;
      for (const key of path.split('.')) {{
        if (v === null || v === undefined || !(key in Object(v))) {{ found = false; break; }}
        v = v[key];
      }}
      if (found && v !== undefined && v !== null) js[path] = text(v);
    }} catch (e) {{}}
  }}
  const props = [];
  for (const [selector, property] of {props}) {{
    try {{
      const values = [];
      for (const el of document.querySelectorAll(selector)) {{
        const v = el[property];
        if (v !== undefined && v !== null) values.push(text(v));
        if (values.length >= 5) break;
      }}
      if (values.length) props.push([selector, property, values]);
    }} catch (e) {{}}
  }}
  const html = document.documentElement ? document.documentElement.outerHTML : '';
  return {{
    url: location.href, fcp, lcp: m.lcp ?? null, cls: m.cls, tbt, longTasks: m.longTasks.length,
    dcl: nav ? nav.domContentLoadedEventEnd : null, load: nav ? nav.loadEventEnd : null,
    js, props, html: html.slice(0, {HTML_LIMIT}), htmlTruncated: html.length > {HTML_LIMIT},
  }};
}})()"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_started_at_once_get_their_own_profiles() {
        let names: std::collections::HashSet<_> = (0..1000)
            .map(|_| temporary_profile(Path::new("/usr/bin/chromium")))
            .collect();
        assert_eq!(names.len(), 1000);
    }

    fn request(id: &str, url: &str) -> Event {
        Event {
            method: "Network.requestWillBeSent".into(),
            params: json!({ "requestId": id, "type": "Script", "request": { "url": url } }),
            session: None,
        }
    }

    #[test]
    fn a_page_cannot_grow_the_resource_list_without_limit() {
        let mut data = BrowserData::default();
        let mut inflight = Inflight::new();
        for i in 0..RESOURCE_LIMIT * 3 {
            record(
                &request(&format!("r{i}"), &format!("https://x.test/{i}.js")),
                &mut inflight,
                &mut data,
            );
        }
        assert_eq!(data.resources.len(), RESOURCE_LIMIT);
        assert_eq!(data.warnings, [RESOURCES_CUT]);
        // Requests past the cap still count as in flight, and finishing them frees the map.
        assert_eq!(inflight.len(), (RESOURCE_LIMIT * 3).min(INFLIGHT_LIMIT));
        let finished = |id: &str| Event {
            method: "Network.loadingFinished".into(),
            params: json!({ "requestId": id, "encodedDataLength": 10.0 }),
            session: None,
        };
        record(&finished("r0"), &mut inflight, &mut data);
        record(&finished(&format!("r{}", RESOURCE_LIMIT + 1)), &mut inflight, &mut data);
        assert_eq!(data.resources[0].transferred, 10);
        assert_eq!(inflight.len(), (RESOURCE_LIMIT * 3).min(INFLIGHT_LIMIT) - 2);
    }

    #[test]
    fn resource_urls_are_cut() {
        let mut data = BrowserData::default();
        let mut inflight = Inflight::new();
        let long = format!("https://x.test/?q={}", "a".repeat(URL_LIMIT * 4));
        record(&request("a", &long), &mut inflight, &mut data);
        // A redirect to a long URL is cut too.
        record(
            &request("a", &long.replace("x.test", "y.test")),
            &mut inflight,
            &mut data,
        );
        assert_eq!(data.resources.len(), 1);
        assert_eq!(data.resources[0].url.chars().count(), URL_LIMIT);
        assert!(data.resources[0].url.starts_with("https://y.test/"));
    }
}
