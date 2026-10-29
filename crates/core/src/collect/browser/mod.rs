//! `--browser`: a headless Chromium driven over the DevTools protocol, for what
//! only a browser sees: Core Web Vitals, every resource the page loads, console
//! errors, and the page as JavaScript builds it.
//!
//! The process starts at t = 0, in parallel with the fast collection; the
//! navigation starts once that collection is done, so the browser never
//! competes for bandwidth with the timings measured on our own connection.

pub mod cdp;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;

use self::cdp::{Connection, Event};
use crate::collect::deadline::Deadline;
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
}

pub struct Browser {
    child: Child,
    conn: Connection,
    events: mpsc::UnboundedReceiver<Event>,
    profile: PathBuf,
    executable: PathBuf,
    product: String,
    warnings: Vec<String>,
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
        std::fs::create_dir_all(&profile).map_err(|e| format!("{}: {e}", profile.display()))?;

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
            .stderr(Stdio::null());
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
        let child = command
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", executable.display()))?;
        drop((child_reads, child_writes));
        let (conn, events) = Connection::new(we_read, we_write);
        let mut browser = Browser {
            child,
            conn,
            events,
            profile,
            executable,
            product: String::new(),
            warnings,
        };
        match browser.conn.call("Browser.getVersion", json!({}), None, deadline).await {
            Ok(v) => {
                browser.product = v["product"].as_str().unwrap_or_default().to_owned();
                Ok(browser)
            }
            Err(e) => {
                browser.close().await;
                Err(format!("the browser did not start: {e}"))
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
            .wait_until_quiet(&session, &frame, stop_waiting, deadline, data)
            .await;
        data.quiet = quiet;

        let expression = collector_expression(&visit.js_paths, &visit.dom_properties);
        let evaluated = self
            .conn
            .call(
                "Runtime.evaluate",
                json!({ "expression": expression, "returnByValue": true, "awaitPromise": true }),
                s,
                deadline,
            )
            .await?;
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
        data: &mut BrowserData,
    ) -> bool {
        let started = Instant::now();
        let mut loaded_at: Option<Instant> = None;
        let mut painted = false;
        let mut quiet_since: Option<Instant> = None;
        let mut inflight: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                event = self.events.recv() => {
                    let Some(event) = event else { return false };
                    if event.session.as_deref() != Some(session) {
                        continue;
                    }
                    record(&event, &mut inflight, data);
                    if event.method == "Page.loadEventFired" && loaded_at.is_none() {
                        loaded_at = Some(Instant::now());
                        data.load_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
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
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// A fresh directory per run. Chromium from snap cannot read /tmp, so its
/// profile goes under ~/snap/chromium/common.
fn temporary_profile(executable: &Path) -> PathBuf {
    let unique = format!(
        "insite-{}-{}",
        std::process::id(),
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

/// Network and console events into the snapshot's lists.
fn record(event: &Event, inflight: &mut std::collections::HashMap<String, usize>, data: &mut BrowserData) {
    let p = &event.params;
    let id = p["requestId"].as_str().unwrap_or_default().to_owned();
    match event.method.as_str() {
        "Network.requestWillBeSent" => {
            let url = p["request"]["url"].as_str().unwrap_or_default();
            if url.starts_with("data:") {
                return;
            }
            let kind = p["type"].as_str().unwrap_or("Other").to_owned();
            match inflight.get(&id) {
                // A redirect: the same request continues at a new URL.
                Some(&i) => data.resources[i].url = url.to_owned(),
                None => {
                    inflight.insert(id, data.resources.len());
                    data.resources.push(BrowserResource {
                        url: url.to_owned(),
                        kind,
                        ..BrowserResource::default()
                    });
                }
            }
        }
        "Network.responseReceived" => {
            if let Some(&i) = inflight.get(&id) {
                let r = &mut data.resources[i];
                r.status = p["response"]["status"].as_u64().map(|s| s as u16);
                r.mime = p["response"]["mimeType"].as_str().map(str::to_owned);
                r.from_cache = p["response"]["fromDiskCache"].as_bool().unwrap_or(false);
            }
        }
        "Network.loadingFinished" => {
            if let Some(i) = inflight.remove(&id) {
                data.resources[i].transferred = p["encodedDataLength"].as_f64().unwrap_or(0.0) as u64;
            }
        }
        "Network.loadingFailed" => {
            if let Some(i) = inflight.remove(&id) {
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
