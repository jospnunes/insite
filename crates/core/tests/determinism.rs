//! The analysis is a pure function of the snapshot: the same snapshot gives the
//! same report, byte for byte, also after a trip through `--save` and `--from`.

mod server;

use std::time::Duration;

use hyper::Response;
use insite_core::analyze::analyze;
use insite_core::collect::http::ACCEPT_ENCODING_VALUE;
use insite_core::collect::target::Target;
use insite_core::collect::{Collector, Options};
use insite_core::snapshot::{RequestProfile, Snapshot};
use server::{Server, TlsMode};

const PAGE: &str = r#"<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8"><title>Loja de exemplo</title>
<meta name="description" content="Uma página de teste com conteúdo suficiente.">
<meta name="generator" content="WordPress 6.6">
<link rel="stylesheet" href="/wp-content/themes/x/style.css">
<script src="https://cdn.other.net/lib.js"></script>
</head><body><h1>Ofertas</h1><img src="/a.png"><form action="/buscar"></form></body></html>"#;

#[tokio::test(flavor = "multi_thread")]
async fn the_same_snapshot_gives_the_same_report() {
    let server = Server::start(TlsMode::Tls(&[b"h2", b"http/1.1"]), 0, |_| async {
        Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .header("server", "nginx/1.25.3")
            .header("set-cookie", "PHPSESSID=abc; path=/")
            .header("strict-transport-security", "max-age=300")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(PAGE)))
            .unwrap()
    })
    .await;
    let mut opts = Options::new(RequestProfile {
        user_agent: "insite-test/1".into(),
        accept_language: "pt-BR".into(),
        accept_encoding: ACCEPT_ENCODING_VALUE.into(),
    });
    opts.timeout = Duration::from_secs(5);
    let collector = Collector::new(&[server.ca_der.clone().unwrap()]).unwrap();
    let target = Target::parse(&format!("https://localhost:{}/", server.addr.port())).unwrap();
    let snapshot = collector.collect(&target, &opts).await;

    let first = serde_json::to_string(&analyze(&snapshot)).unwrap();
    let second = serde_json::to_string(&analyze(&snapshot)).unwrap();
    assert_eq!(first, second);

    let reloaded = Snapshot::from_json(&snapshot.to_json()).unwrap();
    let third = serde_json::to_string(&analyze(&reloaded)).unwrap();
    assert_eq!(first, third);

    // And the report says something: the page was read and graded.
    let report: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(report["modules"]["seo"]["data"]["title"], "Loja de exemplo");
    let ids: Vec<&str> = report["modules"]["security"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"sec.cookies.session_insecure") && ids.contains(&"sec.hsts.short"),
        "{ids:?}"
    );
    assert!(
        report["modules"]["stack"]["data"]["technologies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "WordPress")
    );
}
