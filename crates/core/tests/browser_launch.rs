//! A browser that fails to start. In its own test binary because it sets
//! `CHROME_PATH`, which is global to the process.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use insite_core::collect::browser::Browser;
use insite_core::collect::deadline::Deadline;

#[tokio::test]
async fn what_the_browser_printed_explains_why_it_did_not_start() {
    let dir = std::env::temp_dir().join(format!("insite-fake-browser-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fake = dir.join("chrome");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho 'starting' >&2\necho 'Missing X server or $DISPLAY' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the
    // environment meanwhile.
    unsafe { std::env::set_var("CHROME_PATH", &fake) };

    let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(10), None);
    let error = Browser::launch(None, &deadline)
        .await
        .err()
        .expect("a browser that exits does not start");
    std::fs::remove_dir_all(&dir).unwrap();

    assert!(error.starts_with("the browser did not start"), "{error}");
    assert!(error.contains("starting | Missing X server or $DISPLAY"), "{error}");
}
