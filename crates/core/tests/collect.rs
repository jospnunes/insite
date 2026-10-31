//! Connection engine against local servers: protocols, redirects, encodings,
//! limits, deadlines, retries and the port 80 fallback.

mod server;

use std::time::Duration;

use http::Response;
use http_body_util::Full;
use hyper::body::Bytes;
use insite_core::analyze::analyze;
use insite_core::analyze::network::HttpsEnforcement;
use insite_core::collect::http::ACCEPT_ENCODING_VALUE;
use insite_core::collect::progress::{Part, Phase, Progress};
use insite_core::collect::proxy::ProxyConfig;
use insite_core::collect::target::Target;
use insite_core::collect::{Collector, Options, Ports};
use insite_core::report::{Outcome, Status};
use insite_core::snapshot::{
    CertProblem, ConnectionUse, DomainRole, FailureKind, HttpCheck, HttpVersion, RequestProfile, Snapshot, Verification,
};
use server::{Server, TlsMode, ok, redirect};

const H2_AND_H1: &[&[u8]] = &[b"h2", b"http/1.1"];
const H1_ONLY: &[&[u8]] = &[b"http/1.1"];

fn options() -> Options {
    let mut opts = Options::new(RequestProfile {
        user_agent: "insite-test/1".into(),
        accept_language: "pt-BR,pt;q=0.9,en;q=0.8".into(),
        accept_encoding: ACCEPT_ENCODING_VALUE.into(),
    });
    opts.timeout = Duration::from_secs(5);
    opts
}

async fn collect(server: &Server, path: &str, trust: bool, opts: &Options) -> Snapshot {
    let roots = if trust {
        vec![server.ca_der.clone().expect("TLS server")]
    } else {
        vec![]
    };
    let collector = Collector::new(&roots).unwrap();
    let scheme = if server.ca_der.is_some() { "https" } else { "http" };
    let target = Target::parse(&format!("{scheme}://localhost:{}{path}", server.addr.port())).unwrap();
    collector.collect(&target, opts).await
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_with_trusted_chain() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |req| async move {
        let ua = req.headers()["user-agent"].to_str().unwrap().to_owned();
        let lang = req.headers()["accept-language"].to_str().unwrap().to_owned();
        ok(format!("{ua}|{lang}"))
    })
    .await;
    let snap = collect(&server, "/", true, &options()).await;

    assert!(snap.failure.is_none(), "{:?}", snap.failure);
    assert_eq!(snap.chain.len(), 1);
    let hop = &snap.chain[0];
    assert_eq!((hop.status, hop.version, hop.attempts), (200, HttpVersion::Http2, 1));
    let ConnectionUse::New(conn) = &hop.connection else {
        panic!("first hop opens a connection")
    };
    let tls = conn.tls.as_ref().unwrap();
    assert_eq!(tls.verification, Verification::Valid);
    assert_eq!(tls.version, "TLS 1.3");
    assert_eq!(tls.alpn.as_deref(), Some("h2"));
    assert_eq!(tls.sni.as_deref(), Some("localhost"));
    assert!(conn.resolution.as_ref().unwrap().duration.is_some());
    assert_eq!(snap.page.unwrap().body, b"insite-test/1|pt-BR,pt;q=0.9,en;q=0.8");
    // An explicit port disables the port 80 check: one connection, carrying the
    // page plus robots.txt, security.txt and the sitemap.
    assert!(snap.http_check.is_none());
    assert_eq!((server.connections(), server.requests()), (1, 4));
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_certificate_is_recorded_not_fatal() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { ok("page") }).await;
    let snap = collect(&server, "/", false, &options()).await;

    let ConnectionUse::New(conn) = &snap.chain[0].connection else {
        panic!()
    };
    assert!(matches!(
        &conn.tls.as_ref().unwrap().verification,
        Verification::Invalid {
            problem: CertProblem::UnknownIssuer,
            ..
        }
    ));
    let tls = analyze(&snap).modules.tls;
    assert_eq!(tls.findings.len(), 1);
    assert_eq!(tls.findings[0].id, "tls.cert.untrusted");
    assert_eq!(snap.page.unwrap().body, b"page");
}

#[tokio::test(flavor = "multi_thread")]
async fn http1_when_the_server_only_offers_it() {
    let server = Server::start(TlsMode::Tls(H1_ONLY), 0, |_| async { ok("page") }).await;
    let snap = collect(&server, "/", true, &options()).await;
    assert_eq!(snap.chain[0].version, HttpVersion::Http1);
}

#[tokio::test(flavor = "multi_thread")]
async fn same_origin_redirect_reuses_the_connection() {
    let server = Server::start(TlsMode::Tls(H1_ONLY), 0, |req| async move {
        match req.uri().path() {
            "/old" => redirect(301, "/new"),
            _ => ok("new page"),
        }
    })
    .await;
    let snap = collect(&server, "/old", true, &options()).await;

    assert_eq!(snap.chain.len(), 2);
    assert!(matches!(snap.chain[1].connection, ConnectionUse::Reused));
    // The page's connection served both hops; the second one is the auxiliary
    // files' connection, which HTTP/1.1 cannot multiplex.
    assert_eq!(server.connections(), 2);
    let report = analyze(&snap);
    let net = report.modules.network.data.unwrap();
    assert_eq!(net.redirects.len(), 1);
    assert!(net.phases.unwrap().connection_reused);
    assert!(net.final_url.unwrap().ends_with("/new"));
    assert_eq!(report.outcome, Outcome::Complete);
}

/// The events follow the chain: phases of the first connection, the redirect, the
/// second hop without connection phases (reused), then the page is done.
#[tokio::test(flavor = "multi_thread")]
async fn progress_follows_the_chain() {
    let server = Server::start(TlsMode::Tls(H1_ONLY), 0, |req| async move {
        match req.uri().path() {
            "/a" => redirect(301, "/b"),
            _ => ok("page b"),
        }
    })
    .await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut opts = options();
    opts.progress = Some(tx);
    let snap = collect(&server, "/a", true, &opts).await;
    assert_eq!(snap.chain.len(), 2, "{:?}", snap.failure);
    assert!(matches!(snap.chain[1].connection, ConnectionUse::Reused));

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    let position = |wanted: &dyn Fn(&Progress) -> bool, from: usize| {
        events[from..]
            .iter()
            .position(wanted)
            .map(|i| i + from)
            .unwrap_or_else(|| panic!("event missing after {from}: {events:?}"))
    };
    let phase = |hop, phase| move |e: &Progress| matches!(e, Progress::Phase { hop: h, phase: p, .. } if *h == hop && *p == phase);
    let mut at = position(&phase(0, Phase::Dns), 0);
    at = position(&phase(0, Phase::Tcp), at);
    at = position(&phase(0, Phase::Tls), at);
    at = position(&phase(0, Phase::Ttfb), at);
    at = position(
        &|e| matches!(e, Progress::Redirect { hop: 0, status: 301, to, .. } if to.ends_with("/b")),
        at,
    );
    at = position(&phase(1, Phase::Ttfb), at);
    at = position(&phase(1, Phase::Download), at);
    position(&|e| *e == Progress::Done(Part::Page), at);

    for connection_phase in [Phase::Dns, Phase::Tcp, Phase::Tls] {
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Progress::Phase { hop: 1, phase, .. } if *phase == connection_phase)),
            "{events:?}"
        );
    }
    // Every part is reported exactly once, also those that did not run.
    for part in [Part::Page, Part::HttpCheck, Part::Auxiliary, Part::Asn] {
        let n = events.iter().filter(|e| **e == Progress::Done(part)).count();
        assert_eq!(n, 1, "{part:?} in {events:?}");
    }
    for role in [DomainRole::Input, DomainRole::Final] {
        let n = events
            .iter()
            .filter(|e| **e == Progress::Done(Part::Records(role)))
            .count();
        assert_eq!(n, 1, "{role:?} in {events:?}");
    }
}

/// A refused connection takes the error arm, yet every part is still reported once.
#[tokio::test(flavor = "multi_thread")]
async fn progress_reports_every_part_once_when_the_connection_fails() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut opts = options();
    opts.progress = Some(tx);
    let target = Target::parse(&format!("https://localhost:{port}/")).unwrap();
    let snap = Collector::new(&[]).unwrap().collect(&target, &opts).await;
    assert_eq!(
        snap.failure.as_ref().map(|f| f.kind),
        Some(FailureKind::Connect),
        "{:?}",
        snap.failure
    );

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    let parts = [
        Part::Page,
        Part::HttpCheck,
        Part::Records(DomainRole::Input),
        Part::Records(DomainRole::Final),
        Part::Auxiliary,
        Part::Asn,
    ];
    for part in parts {
        let n = events.iter().filter(|e| **e == Progress::Done(part)).count();
        assert_eq!(n, 1, "{part:?} in {events:?}");
    }
}

/// `user:pass@` in the input or in a redirect never reaches the snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn credentials_in_urls_are_not_stored() {
    let server = Server::start(TlsMode::Plain, 0, |req| async move {
        match req.uri().path() {
            "/old" => {
                let host = req.headers().get("host").unwrap().to_str().unwrap().to_owned();
                redirect(301, &format!("http://outro:senha2@{host}/new"))
            }
            _ => ok("new page"),
        }
    })
    .await;
    let target = Target::parse(&format!("http://ana:segredo@localhost:{}/old", server.addr.port())).unwrap();
    assert!(target.credentials_ignored);
    let snap = Collector::new(&[]).unwrap().collect(&target, &options()).await;

    assert_eq!(snap.chain.len(), 2, "{:?}", snap.failure);
    let mut stored = vec![snap.input.clone()];
    stored.extend(snap.chain.iter().map(|hop| hop.url.clone()));
    for text in &stored {
        assert!(!text.contains("segredo") && !text.contains("senha2"), "{text}");
    }
    // The server's own Location header is its data; the user's password is not in it.
    assert!(!serde_json::to_string(&snap).unwrap().contains("segredo"));
    assert!(snap.chain[1].url.ends_with("/new"), "{}", snap.chain[1].url);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_loop_becomes_a_finding() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { redirect(302, "/loop") }).await;
    let snap = collect(&server, "/loop", true, &options()).await;

    assert_eq!(snap.failure.as_ref().unwrap().kind, FailureKind::RedirectLoop);
    assert_eq!(snap.chain.len(), 1);
    let report = analyze(&snap);
    assert_eq!(report.modules.network.findings[0].id, "net.redirect.loop");
    assert_eq!(report.outcome.exit_code(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_redirects_stop_at_the_limit() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |req| async move {
        let n: u32 = req.uri().path().trim_start_matches("/r/").parse().unwrap_or(0);
        redirect(302, &format!("/r/{}", n + 1))
    })
    .await;
    let mut opts = options();
    opts.max_redirects = 3;
    let snap = collect(&server, "/r/0", true, &opts).await;

    assert_eq!(snap.failure.as_ref().unwrap().kind, FailureKind::TooManyRedirects);
    assert_eq!(snap.chain.len(), 4);
    assert_eq!(analyze(&snap).modules.network.findings[0].id, "net.redirect.too_many");
}

#[tokio::test(flavor = "multi_thread")]
async fn gzip_and_brotli_are_decoded() {
    let html = "<html><body>".to_owned() + &"olá mundo ".repeat(2000) + "</body></html>";
    let expected = html.clone();
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, move |req| {
        let html = html.clone();
        async move {
            let (encoding, body) = match req.uri().path() {
                "/gz" => ("gzip", server::gzip(html.as_bytes())),
                _ => ("br", server::brotli(html.as_bytes())),
            };
            Response::builder()
                .header("content-encoding", encoding)
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }
    })
    .await;
    for path in ["/gz", "/br"] {
        let page = collect(&server, path, true, &options()).await.page.unwrap();
        assert_eq!(page.body, expected.as_bytes(), "{path}");
        assert!(page.transferred < page.body.len() as u64 / 10, "{path}");
        assert!(!page.truncated && page.decode_error.is_none(), "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn body_limit_cuts_the_page_and_marks_the_report_partial() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { ok(vec![b'a'; 6 << 20]) }).await;
    let snap = collect(&server, "/", true, &options()).await;

    let page = snap.page.as_ref().unwrap();
    assert_eq!(page.body.len(), 5 << 20);
    assert!(page.truncated);
    assert_eq!(analyze(&snap).outcome.exit_code(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_before_headers_means_unreachable() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        ok("late")
    })
    .await;
    let mut opts = options();
    opts.timeout = Duration::from_millis(800);
    let snap = collect(&server, "/", true, &opts).await;

    assert!(snap.deadline_hit);
    assert_eq!(snap.failure.as_ref().unwrap().kind, FailureKind::Timeout);
    assert!(snap.duration < Duration::from_millis(1500));
    assert_eq!(analyze(&snap).outcome.exit_code(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_during_the_body_keeps_what_arrived() {
    let server = Server::start(TlsMode::Tls(H1_ONLY), 0, |_| async {
        server::dripping(b"chunk ", 50, Duration::from_millis(50))
    })
    .await;
    let mut opts = options();
    opts.timeout = Duration::from_millis(700);
    let snap = collect(&server, "/", true, &opts).await;

    let page = snap.page.as_ref().unwrap();
    assert!(snap.deadline_hit && page.truncated && page.deadline_hit);
    assert!(!page.body.is_empty() && page.body.len() < 300);
    let report = analyze(&snap);
    assert!(matches!(report.outcome, Outcome::Partial { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn one_retry_after_a_dropped_connection() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 1, |_| async { ok("second time") }).await;
    let snap = collect(&server, "/", true, &options()).await;

    assert!(snap.failure.is_none(), "{:?}", snap.failure);
    assert_eq!(snap.chain[0].attempts, 2);
    assert_eq!(snap.page.unwrap().body, b"second time");
    assert_eq!(server.connections(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn port_80_check_sees_the_https_redirect() {
    let https = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { ok("secure") }).await;
    let https_port = https.addr.port();
    let http = Server::start(TlsMode::Plain, 0, move |_| async move {
        redirect(301, &format!("https://localhost:{https_port}/"))
    })
    .await;

    let mut opts = options();
    opts.default_ports = Ports {
        http: http.addr.port(),
        https: https_port,
    };
    let collector = Collector::new(&[https.ca_der.clone().unwrap()]).unwrap();
    let snap = collector.collect(&Target::parse("localhost").unwrap(), &opts).await;

    assert!(matches!(snap.http_check, Some(HttpCheck::Response { status: 301, .. })));
    assert_eq!(snap.page.as_ref().unwrap().body, b"secure");
    assert_eq!(
        analyze(&snap).modules.network.data.unwrap().https,
        HttpsEnforcement::Redirects
    );
}

/// A port 80 that never answers holds the collection until the deadline, but the
/// page arrived whole: only the check is missing, not the download.
#[tokio::test(flavor = "multi_thread")]
async fn silent_port_80_does_not_blame_the_page() {
    let https = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { ok("secure") }).await;
    let http = Server::start(TlsMode::Plain, 0, |_| async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        ok("late")
    })
    .await;

    let mut opts = options();
    opts.timeout = Duration::from_millis(800);
    opts.default_ports = Ports {
        http: http.addr.port(),
        https: https.addr.port(),
    };
    let collector = Collector::new(&[https.ca_der.clone().unwrap()]).unwrap();
    let snap = collector.collect(&Target::parse("localhost").unwrap(), &opts).await;

    assert!(snap.deadline_hit);
    let page = snap.page.as_ref().unwrap();
    assert!(!page.truncated && !page.deadline_hit);
    let report = analyze(&snap);
    assert_eq!(
        report.modules.network.status,
        Status::Ok,
        "{:?}",
        report.modules.network.reason
    );
    assert_eq!(report.modules.security.status, Status::Partial);
}

#[tokio::test(flavor = "multi_thread")]
async fn site_without_https_falls_back_to_port_80() {
    let http = Server::start(TlsMode::Plain, 0, |_| async { ok("plain page") }).await;
    let closed = server::closed_port().await;

    let mut opts = options();
    opts.default_ports = Ports {
        http: http.addr.port(),
        https: closed,
    };
    let collector = Collector::new(&[]).unwrap();
    let snap = collector.collect(&Target::parse("localhost").unwrap(), &opts).await;

    assert!(snap.failure.is_none(), "{:?}", snap.failure);
    assert_eq!(snap.https_fallback.as_ref().unwrap().kind, FailureKind::Connect);
    assert!(snap.chain[0].url.starts_with("http://"));
    assert_eq!(snap.page.as_ref().unwrap().body, b"plain page");
    // The check's response was reused as the page: one request for it, plus
    // robots.txt, security.txt and the sitemap.
    assert_eq!(http.requests(), 4);
    let report = analyze(&snap);
    assert_eq!(
        report.modules.network.data.unwrap().https,
        HttpsEnforcement::HttpsUnavailable
    );
    assert_eq!(report.outcome, Outcome::Complete);
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_listening_is_unreachable() {
    let closed = server::closed_port().await;
    let collector = Collector::new(&[]).unwrap();
    let snap = collector
        .collect(
            &Target::parse(&format!("https://localhost:{closed}/")).unwrap(),
            &options(),
        )
        .await;

    assert!(snap.chain.is_empty());
    assert_eq!(snap.failure.as_ref().unwrap().kind, FailureKind::Connect);
    assert_eq!(analyze(&snap).outcome.exit_code(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn analysis_is_deterministic() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |req| async move {
        match req.uri().path() {
            "/" => redirect(302, "/home"),
            _ => ok("home"),
        }
    })
    .await;
    let snap = collect(&server, "/", true, &options()).await;
    let a = serde_json::to_string(&analyze(&snap)).unwrap();
    let b = serde_json::to_string(&analyze(&snap)).unwrap();
    assert_eq!(a, b);
}

fn site(req: http::Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    match req.uri().path() {
        "/robots.txt" => ok("User-agent: *\nDisallow: /admin\nSitemap: /sm.xml\n"),
        "/sm.xml" => ok("<?xml version=\"1.0\"?><urlset><url><loc>https://x/</loc></url></urlset>"),
        "/.well-known/security.txt" => ok("Contact: mailto:security@example.com\n"),
        "/" => ok("<html>home</html>"),
        _ => Response::builder()
            .status(404)
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn auxiliary_files_ride_the_http2_connection() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |req| async move { site(req) }).await;
    let snap = collect(&server, "/", true, &options()).await;
    let aux = &snap.auxiliary;

    let robots = aux.robots.as_ref().unwrap();
    assert_eq!(robots.status, Some(200));
    assert!(String::from_utf8_lossy(&robots.body).contains("Sitemap: /sm.xml"));
    assert_eq!(aux.security_txt.as_ref().unwrap().status, Some(200));
    let sitemap = aux.sitemap.as_ref().unwrap();
    assert!(sitemap.url.ends_with("/sm.xml"), "{}", sitemap.url);
    assert_eq!(sitemap.status, Some(200));
    // Page, robots.txt, security.txt and sitemap over a single connection.
    assert_eq!((server.connections(), server.requests()), (1, 4));
}

#[tokio::test(flavor = "multi_thread")]
async fn auxiliary_files_use_one_extra_http1_connection() {
    let server = Server::start(TlsMode::Tls(H1_ONLY), 0, |req| async move { site(req) }).await;
    let snap = collect(&server, "/", true, &options()).await;

    assert_eq!(snap.auxiliary.sitemap.as_ref().unwrap().status, Some(200));
    assert_eq!((server.connections(), server.requests()), (2, 4));
}

#[tokio::test(flavor = "multi_thread")]
async fn sitemap_defaults_to_sitemap_xml() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |req| async move {
        match req.uri().path() {
            "/" => ok("home"),
            _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
        }
    })
    .await;
    let snap = collect(&server, "/", true, &options()).await;
    let sitemap = snap.auxiliary.sitemap.unwrap();
    assert!(sitemap.requested.ends_with("/sitemap.xml"));
    assert_eq!(sitemap.status, Some(404));
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_go_through_an_https_proxy() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { ok("via proxy") }).await;
    let proxy = server::proxy::Proxy::start(false).await;
    let mut opts = options();
    opts.proxy = ProxyConfig::from_values(Some(&proxy.url()), None, None).unwrap();
    let snap = collect(&server, "/", true, &opts).await;

    assert!(snap.failure.is_none(), "{:?}", snap.failure);
    assert_eq!(snap.page.as_ref().unwrap().body, b"via proxy");
    let ConnectionUse::New(conn) = &snap.chain[0].connection else {
        panic!()
    };
    assert_eq!(conn.proxy.as_deref(), Some(proxy.addr.to_string().as_str()));
    assert!(conn.resolution.is_none(), "the proxy resolves the name, not us");
    assert_eq!(conn.tls.as_ref().unwrap().verification, Verification::Valid);
    assert!(proxy.tunnels() >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusing_proxy_is_not_blamed_on_the_site() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { ok("page") }).await;
    let proxy = server::proxy::Proxy::start(true).await;
    let mut opts = options();
    opts.proxy = ProxyConfig::from_values(Some(&proxy.url()), None, None).unwrap();
    let snap = collect(&server, "/", true, &opts).await;

    let failure = snap.failure.unwrap();
    assert_eq!(failure.kind, FailureKind::Proxy);
    assert!(failure.message.contains("403"), "{}", failure.message);
    assert_eq!(server.connections(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_proxy_hosts_go_direct() {
    let server = Server::start(TlsMode::Tls(H2_AND_H1), 0, |_| async { ok("direct") }).await;
    let proxy = server::proxy::Proxy::start(false).await;
    let mut opts = options();
    opts.proxy = ProxyConfig::from_values(Some(&proxy.url()), None, Some("localhost")).unwrap();
    let snap = collect(&server, "/", true, &opts).await;

    assert_eq!(snap.page.unwrap().body, b"direct");
    assert_eq!(proxy.tunnels(), 0);
}
