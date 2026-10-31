//! `--browser` against a local page. Needs a Chrome or Chromium: the tests run
//! when `CHROME_PATH` is set and pass trivially otherwise, so the suite stays
//! green on machines without a browser.

mod server;

use std::time::Duration;

use hyper::Response;
use insite_core::collect::browser::{Browser, Visit};
use insite_core::collect::deadline::Deadline;
use insite_core::collect::progress::{BrowserStage, Progress};
use server::{Server, TlsMode, ok};

const PAGE: &str = r#"<!doctype html><html lang="en"><head><title>t</title>
<script src="/app.js"></script></head>
<body><h1 id="main">Hello</h1><img src="/missing.png" alt="x"></body></html>"#;

const APP: &str = "window.React = { version: '18.2.0' }; console.error('boom from app');";

fn chrome() -> bool {
    std::env::var_os("CHROME_PATH").is_some()
}

#[tokio::test]
async fn loads_the_page_and_reads_what_signatures_need() {
    if !chrome() {
        eprintln!("skipped: set CHROME_PATH to run the browser tests");
        return;
    }
    let server = Server::start(TlsMode::Plain, 0, |req| async move {
        match req.uri().path() {
            "/app.js" => Response::builder()
                .header("content-type", "application/javascript")
                .body(http_body_util::Full::new(hyper::body::Bytes::from(APP)))
                .unwrap(),
            "/missing.png" => Response::builder()
                .status(404)
                .body(http_body_util::Full::new(hyper::body::Bytes::new()))
                .unwrap(),
            _ => ok(PAGE),
        }
    })
    .await;
    let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(30), None);
    let mut browser = Browser::launch(None, &deadline).await.expect("the browser starts");
    let visit = Visit {
        mobile: true,
        throttle: false,
        user_agent_suffix: Some("insite/test".into()),
        accept_language: "en".into(),
        js_paths: vec!["React.version".into(), "Vue.version".into()],
        dom_properties: vec![("h1#main".into(), "textContent".into())],
        progress: None,
    };
    let url = format!("http://{}/", server.addr);
    let data = browser.visit(&url, &visit, &deadline).await;
    browser.close().await;

    assert_eq!(data.error, None);
    assert!(data.quiet, "a static page goes quiet");
    assert_eq!(data.url, url);
    assert!(data.user_agent.contains("Mobile") && data.user_agent.ends_with("insite/test"));
    // Only paths that exist come back.
    assert_eq!(data.js, [("React.version".to_owned(), "18.2.0".to_owned())]);
    assert_eq!(
        data.dom_properties,
        [("h1#main".to_owned(), "textContent".to_owned(), vec!["Hello".to_owned()])]
    );
    let metrics = data.metrics.expect("metrics");
    assert!(metrics.fcp_ms.is_some() && metrics.lcp_ms.is_some(), "{metrics:?}");
    let kinds: Vec<(&str, Option<u16>)> = data.resources.iter().map(|r| (r.kind.as_str(), r.status)).collect();
    assert!(
        kinds.contains(&("Document", Some(200))) && kinds.contains(&("Script", Some(200))),
        "{kinds:?}"
    );
    assert!(kinds.contains(&("Image", Some(404))), "{kinds:?}");
    assert!(
        data.console.iter().any(|c| c.contains("boom from app")),
        "{:?}",
        data.console
    );
    assert!(data.html.unwrap().contains("<h1 id=\"main\">Hello</h1>"));
}

/// A page that paints only after the quiet window following `load`, as a cold
/// browser on a slow machine does.
#[tokio::test]
async fn waits_for_the_first_paint() {
    if !chrome() {
        return;
    }
    const LATE: &str = r#"<!doctype html><html><head><title>t</title></head><body><script>
addEventListener('load', () => setTimeout(() => document.body.append('late'), 1500));
</script></body></html>"#;
    let server = Server::start(TlsMode::Plain, 0, |_| async move { ok(LATE) }).await;
    let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(30), None);
    let mut browser = Browser::launch(None, &deadline).await.expect("the browser starts");
    let visit = Visit {
        mobile: false,
        throttle: false,
        user_agent_suffix: None,
        accept_language: "en".into(),
        js_paths: Vec::new(),
        dom_properties: Vec::new(),
        progress: None,
    };
    let data = browser
        .visit(&format!("http://{}/", server.addr), &visit, &deadline)
        .await;
    browser.close().await;
    assert_eq!(data.error, None);
    assert!(data.quiet);
    let metrics = data.metrics.expect("metrics");
    assert!(metrics.fcp_ms.is_some_and(|f| f >= 1500.0), "{metrics:?}");
    assert!(metrics.lcp_ms.is_some(), "{metrics:?}");
}

#[tokio::test]
async fn a_navigation_error_is_reported_not_raised() {
    if !chrome() {
        return;
    }
    let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(30), None);
    let mut browser = Browser::launch(None, &deadline).await.expect("the browser starts");
    let visit = Visit {
        mobile: false,
        throttle: false,
        user_agent_suffix: None,
        accept_language: "en".into(),
        js_paths: Vec::new(),
        dom_properties: Vec::new(),
        progress: None,
    };
    // A port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let data = browser
        .visit(&format!("http://127.0.0.1:{port}/"), &visit, &deadline)
        .await;
    browser.close().await;
    assert!(
        data.error
            .as_deref()
            .is_some_and(|e| e.contains("ERR_CONNECTION_REFUSED")),
        "{:?}",
        data.error
    );
}

fn plain_visit() -> Visit {
    Visit {
        mobile: false,
        throttle: false,
        user_agent_suffix: None,
        accept_language: "en".into(),
        js_paths: Vec::new(),
        dom_properties: Vec::new(),
        progress: None,
    }
}

/// A live view says what the browser is doing: navigating, loaded, quiet, once each and in order.
#[tokio::test]
async fn visit_reports_its_stages() {
    if !chrome() {
        eprintln!("skipped: set CHROME_PATH to run the browser tests");
        return;
    }
    let server = Server::start(TlsMode::Plain, 0, |_| async move { ok(PAGE) }).await;
    let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(30), None);
    let mut browser = Browser::launch(None, &deadline).await.expect("the browser starts");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let visit = Visit {
        progress: Some(tx),
        ..plain_visit()
    };
    let data = browser
        .visit(&format!("http://{}/", server.addr), &visit, &deadline)
        .await;
    browser.close().await;
    assert_eq!(data.error, None);
    drop(visit);
    let mut stages = Vec::new();
    while let Some(event) = rx.recv().await {
        match event {
            Progress::Browser(stage) => stages.push(stage),
            other => panic!("only browser stages expected, got {other:?}"),
        }
    }
    assert_eq!(
        stages,
        [BrowserStage::Navigating, BrowserStage::Loaded, BrowserStage::Quiet]
    );
}

/// `alert()` and `confirm()` block the renderer until someone answers them.
#[tokio::test]
async fn javascript_dialogs_do_not_block_the_visit() {
    if !chrome() {
        return;
    }
    const DIALOGS: &str = r#"<!doctype html><html><head><title>t</title></head><body><h1>oi</h1><script>
alert('hello');
confirm('sure?');
addEventListener('load', () => setTimeout(() => alert('late'), 300));
</script></body></html>"#;
    let server = Server::start(TlsMode::Plain, 0, |_| async move { ok(DIALOGS) }).await;
    let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(30), None);
    let mut browser = Browser::launch(None, &deadline).await.expect("the browser starts");
    let started = std::time::Instant::now();
    let data = browser
        .visit(&format!("http://{}/", server.addr), &plain_visit(), &deadline)
        .await;
    browser.close().await;
    assert_eq!(data.error, None);
    assert!(data.metrics.is_some(), "no metrics after a dialog");
    assert!(data.html.is_some_and(|h| h.contains("<h1>oi</h1>")));
    assert!(started.elapsed() < Duration::from_secs(25), "ran to the deadline");
}

/// A browser dropped without `close` takes its profile with it.
#[tokio::test]
async fn a_dropped_browser_removes_its_profile() {
    if !chrome() {
        return;
    }
    let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(30), None);
    let browser = Browser::launch(None, &deadline).await.expect("the browser starts");
    let profile = browser.profile().to_path_buf();
    assert!(profile.exists());
    drop(browser);
    assert!(!profile.exists());
}
