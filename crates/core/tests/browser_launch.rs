//! A browser that fails to start, or a fake one that answers the first
//! commands. In its own test binary because it sets `CHROME_PATH`, which is
//! global to the process; the tests take turns.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use insite_core::collect::browser::{Browser, cleanup_all};
use insite_core::collect::deadline::Deadline;
use tokio::sync::Mutex;

static TURN: Mutex<()> = Mutex::const_new(());

fn deadline(secs: u64) -> Deadline {
    Deadline::new(tokio::time::Instant::now() + Duration::from_secs(secs), None)
}

/// A scratch directory with a `chrome` of the given mode in it.
fn fake_browser(name: &str, script: &str, mode: u32) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("insite-fake-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fake = dir.join("chrome");
    std::fs::write(&fake, script).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(mode)).unwrap();
    // SAFETY: the tests of this binary take turns, so no other thread reads the
    // environment meanwhile.
    unsafe { std::env::set_var("CHROME_PATH", &fake) };
    dir
}

/// Profiles this process left in the temp dir.
fn leftovers() -> Vec<PathBuf> {
    let prefix = format!("insite-{}-", std::process::id());
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect()
}

/// Answers `Browser.getVersion` and every other command with an empty result,
/// logging each message it reads.
fn answering_script(log: &Path) -> String {
    format!(
        r#"#!/bin/bash
n=0
while IFS= read -r -d '' msg <&3; do
  n=$((n+1))
  echo "$msg" >> '{}'
  if [ $n = 1 ]; then printf '{{"id":%d,"result":{{"product":"Fake/1.0"}}}}\0' $n >&4
  else printf '{{"id":%d,"result":{{}}}}\0' $n >&4; fi
done
"#,
        log.display()
    )
}

fn log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("insite-fake-log-{name}-{}", std::process::id()))
}

fn exists(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Gone, or a zombie that only waits to be reaped.
fn is_dead(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rsplit(')')
            .next()
            .is_some_and(|rest| rest.trim_start().starts_with('Z')),
        Err(_) => !exists(pid) || !cfg!(target_os = "linux"),
    }
}

#[tokio::test]
async fn what_the_browser_printed_explains_why_it_did_not_start() {
    let _turn = TURN.lock().await;
    let dir = fake_browser(
        "exits",
        "#!/bin/sh\necho 'starting' >&2\necho 'Missing X server or $DISPLAY' >&2\nexit 1\n",
        0o755,
    );
    let error = Browser::launch(None, &deadline(10))
        .await
        .err()
        .expect("a browser that exits does not start");
    std::fs::remove_dir_all(&dir).unwrap();

    assert!(error.starts_with("the browser did not start"), "{error}");
    assert!(error.contains("starting | Missing X server or $DISPLAY"), "{error}");
    assert_eq!(leftovers(), Vec::<PathBuf>::new());
}

#[tokio::test]
async fn a_browser_that_cannot_be_spawned_leaves_no_profile() {
    let _turn = TURN.lock().await;
    let dir = fake_browser("noexec", "#!/bin/sh\n", 0o644);
    let error = Browser::launch(None, &deadline(10))
        .await
        .err()
        .expect("a file that is not executable does not start");
    std::fs::remove_dir_all(&dir).unwrap();

    assert!(error.starts_with("could not start"), "{error}");
    assert_eq!(leftovers(), Vec::<PathBuf>::new());
}

#[tokio::test]
async fn downloads_are_denied_at_startup() {
    let _turn = TURN.lock().await;
    let log = log_path("downloads");
    let dir = fake_browser("downloads", &answering_script(&log), 0o755);
    let browser = Browser::launch(None, &deadline(10)).await.expect("the fake starts");
    let received = std::fs::read_to_string(&log).unwrap();
    drop(browser);
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&log).unwrap();

    let line = received
        .lines()
        .find(|l| l.contains("Browser.setDownloadBehavior"))
        .unwrap_or_else(|| panic!("no setDownloadBehavior in {received}"));
    assert!(line.contains(r#""behavior":"deny""#), "{line}");
}

#[tokio::test]
async fn dropping_a_browser_kills_it_and_removes_its_profile() {
    let _turn = TURN.lock().await;
    let log = log_path("dropped");
    let dir = fake_browser("dropped", &answering_script(&log), 0o755);
    let browser = Browser::launch(None, &deadline(10)).await.expect("the fake starts");
    let (pid, profile) = (browser.pid(), browser.profile().to_path_buf());
    assert!(profile.exists() && exists(pid));

    // No `close()`: an error path, a panic or an abandoned future.
    drop(browser);
    std::fs::remove_dir_all(&dir).unwrap();
    let _ = std::fs::remove_file(&log);

    assert!(!profile.exists(), "the profile stays: {}", profile.display());
    assert!(!exists(pid), "the browser process lives on");
    assert_eq!(leftovers(), Vec::<PathBuf>::new());
}

#[tokio::test]
async fn cleanup_all_serves_a_quit_that_runs_no_destructors() {
    let _turn = TURN.lock().await;
    let log = log_path("quit");
    let dir = fake_browser("quit", &answering_script(&log), 0o755);
    let browser = Browser::launch(None, &deadline(10)).await.expect("the fake starts");
    let (pid, profile) = (browser.pid(), browser.profile().to_path_buf());

    cleanup_all();

    assert!(!profile.exists(), "the profile stays: {}", profile.display());
    // Killed, waiting for its parent to reap it.
    let until = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < until && !is_dead(pid) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(is_dead(pid), "the browser process lives on");
    drop(browser);
    std::fs::remove_dir_all(&dir).unwrap();
    let _ = std::fs::remove_file(&log);
}
