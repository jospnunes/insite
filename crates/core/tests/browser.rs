//! `--browser` against a local page. Needs a Chrome or Chromium: the tests run
//! when `CHROME_PATH` is set and pass trivially otherwise, so the suite stays
//! green on machines without a browser.

mod server;

use std::time::Duration;

use hyper::Response;
use insite_core::collect::browser::{Browser, Visit};
use insite_core::collect::deadline::Deadline;
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
