//! Collection: everything that touches the network. Produces a `Snapshot`.

pub mod asn;
pub mod browser;
pub mod connect;
pub mod deadline;
pub mod dns;
pub mod http;
pub mod proxy;
pub mod records;
pub mod target;
pub mod tls;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use url::{Host, Url};

use crate::report::{ModuleName, Selection};
use crate::snapshot::{
    AuxFile, Auxiliary, ConnectionInfo, ConnectionUse, DomainRecords, DomainRole, FailureKind, FetchFailure, Hop,
    HttpCheck, HttpVersion, Page, RequestProfile, SNAPSHOT_VERSION, Snapshot,
};
use deadline::Deadline;
use dns::{Resolved, Resolver};
use http::Sender;
use proxy::ProxyConfig;
use target::Target;
use tls::Tls;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub const DNS_TIMEOUT: Duration = Duration::from_secs(2);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const TLS_TIMEOUT: Duration = Duration::from_secs(3);
/// Redirect bodies are read only so the connection can be reused.
const REDIRECT_BODY_LIMIT: usize = 64 << 10;
const ROBOTS_LIMIT: usize = 512 << 10;
const SECURITY_TXT_LIMIT: usize = 64 << 10;
const SITEMAP_LIMIT: usize = 1 << 20;
const AUX_MAX_REDIRECTS: usize = 3;

#[derive(Debug, Clone)]
pub struct Options {
    pub request: RequestProfile,
    /// Deadline for the whole collection, from t = 0.
    pub timeout: Duration,
    /// Limit on the page body, both on the wire and after decompression.
    pub body_limit: usize,
    pub max_redirects: usize,
    /// Ports used when the URL does not name one. Only tests change them.
    pub default_ports: Ports,
    pub proxy: ProxyConfig,
    pub fetch: Fetch,
    /// Turns true to stop collecting (Ctrl-C): the snapshot then closes with
    /// what has arrived, as when the deadline passes.
    pub stop: Option<tokio::sync::watch::Receiver<bool>>,
}

/// Which optional pieces to collect; `-m` turns off what its modules do not need.
#[derive(Debug, Clone, Copy)]
pub struct Fetch {
    pub http_check: bool,
    pub dns_records: bool,
    pub asn: bool,
    pub robots_and_sitemap: bool,
    pub security_txt: bool,
}

impl Fetch {
    /// Only what the chosen modules read; the page itself is always fetched.
    pub fn for_modules(selection: Selection) -> Self {
        let has = |m| selection.contains(m);
        Fetch {
            http_check: has(ModuleName::Security) || has(ModuleName::Network),
            dns_records: has(ModuleName::Dns) || has(ModuleName::Infra) || has(ModuleName::Stack),
            asn: has(ModuleName::Infra),
            robots_and_sitemap: has(ModuleName::Seo),
            security_txt: has(ModuleName::Security),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ports {
    pub http: u16,
    pub https: u16,
}

impl Options {
    pub fn new(request: RequestProfile) -> Self {
        Options {
            request,
            timeout: Duration::from_secs(5),
            body_limit: 5 << 20,
            max_redirects: 10,
            default_ports: Ports { http: 80, https: 443 },
            proxy: ProxyConfig::default(),
            fetch: Fetch::for_modules(Selection::all()),
            stop: None,
        }
    }
}

/// Long-lived pieces shared by every collection: the resolver (and its cache) and
/// the trust roots. In batch mode, one `Collector` serves all sites.
#[derive(Clone)]
pub struct Collector {
    resolver: Resolver,
    tls: Tls,
}

impl Collector {
    /// The system resolver and the embedded roots plus `extra_roots` (DER).
    pub fn new(extra_roots: &[Vec<u8>]) -> Result<Self, String> {
        Ok(Self::with(Resolver::from_system()?, Tls::new(extra_roots, false)?))
    }

    pub fn with(resolver: Resolver, tls: Tls) -> Self {
        Collector { resolver, tls }
    }

    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    pub async fn collect(&self, target: &Target, opts: &Options) -> Snapshot {
        let t0 = Instant::now();
        let collected_at = SystemTime::now();
        let deadline = Deadline::new(tokio::time::Instant::from_std(t0 + opts.timeout), opts.stop.clone());

        let mut main = Session::new(self, opts, t0, deadline.clone());
        main.spawn_aux = opts.fetch.robots_and_sitemap || opts.fetch.security_txt;
        let mut side = Session::new(self, opts, t0, deadline.clone());
        let check_url = (opts.fetch.http_check && target.url.scheme() == "https" && !target.explicit_port).then(|| {
            let mut url = target.url.clone();
            url.set_scheme("http").expect("https URLs can become http");
            url
        });
        let input_host = match target.url.host() {
            Some(Host::Domain(domain)) if opts.fetch.dns_records => Some(domain.to_owned()),
            _ => None,
        };

        // The page, the port 80 check and the input domain's records all start at t = 0.
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let (main_result, check_step, input_records) = tokio::join!(
            main.follow(target.url.clone(), &mut chain, &mut visited),
            async {
                match &check_url {
                    Some(url) => Some(side.step(url, opts.body_limit).await),
                    None => None,
                }
            },
            async {
                match &input_host {
                    Some(host) => Some(records::collect(&self.resolver, host, DomainRole::Input, &deadline).await),
                    None => None,
                }
            }
        );

        // A first redirect to another plain HTTP address says nothing about where
        // the visitor ends up; follow it, so the redirection grade is exact.
        let mut route = Vec::new();
        if let Some(Ok(step)) = &check_step
            && let Some(first) = step.next.as_ref().filter(|n| n.scheme() == "http")
        {
            let mut next = Some(first.clone());
            while let Some(url) = next.take().filter(|_| route.len() < 5) {
                route.push(url.to_string());
                match side.step(&url, REDIRECT_BODY_LIMIT).await {
                    Ok(s) => match s.next {
                        Some(n) if n.scheme() == "http" => next = Some(n),
                        Some(n) => route.push(n.to_string()),
                        None => {}
                    },
                    Err(_) => break,
                }
            }
        }
        let http_check = check_step.as_ref().map(|step| match step {
            Ok(step) => HttpCheck::Response {
                status: step.hop.status,
                location: step.hop.header("location").map(str::to_owned),
                route,
            },
            Err(failure) => HttpCheck::Failed(failure.clone()),
        });

        let (mut page, mut failure, mut https_fallback) = (None, None, None);
        match main_result {
            Ok(p) => page = p,
            Err(main_failure) => {
                // HTTPS is unavailable: the port 80 response, already in hand, becomes
                // the start of the chain, unless it just redirects back to HTTPS.
                let fallback = match check_step {
                    Some(Ok(step))
                        if chain.is_empty()
                            && matches!(main_failure.kind, FailureKind::Connect | FailureKind::TlsIncompatible)
                            && step.next.as_ref().is_none_or(|next| next.scheme() != "https") =>
                    {
                        Some(step)
                    }
                    _ => None,
                };
                match fallback {
                    Some(step) => {
                        https_fallback = Some(main_failure);
                        visited.insert(step.hop.url.clone());
                        chain.push(step.hop);
                        match (step.page, step.next) {
                            (Some(p), _) => page = Some(p),
                            (None, Some(next)) => match side.follow(next, &mut chain, &mut visited).await {
                                Ok(p) => page = p,
                                Err(f) => failure = Some(f),
                            },
                            (None, None) => {}
                        }
                    }
                    None => failure = Some(main_failure),
                }
            }
        }

        main.settle_into(&mut chain).await;
        side.settle_into(&mut chain).await;

        // Once the chain is known: auxiliary files (already running when the main
        // session saw the final headers), the final domain's records when it is
        // another registrable domain, and the owner of the final address.
        let final_url = chain
            .last()
            .filter(|hop| !hop.is_redirect() && page.is_some())
            .and_then(|hop| Url::parse(&hop.url).ok());
        let aux_task = main.aux.take().map(|aux| aux.task);
        let wants_aux = opts.fetch.robots_and_sitemap || opts.fetch.security_txt;
        let final_host = final_url.as_ref().and_then(|u| match u.host() {
            Some(Host::Domain(d)) if opts.fetch.dns_records => Some(d.to_owned()),
            _ => None,
        });
        let other_domain = final_host.filter(|f| {
            input_host
                .as_deref()
                .is_none_or(|i| records::registrable(i) != records::registrable(f))
        });
        let (auxiliary, final_records) = tokio::join!(
            async {
                match (aux_task, &final_url) {
                    (Some(task), _) => deadline.run(task).await.and_then(Result::ok),
                    // The page came another way (fallback to port 80): fetch now.
                    (None, Some(url)) if wants_aux => Some(
                        fetch_auxiliary(
                            self.clone(),
                            opts.clone(),
                            t0,
                            deadline.clone(),
                            url.clone(),
                            None,
                            HashMap::new(),
                            None,
                        )
                        .await,
                    ),
                    _ => None,
                }
            },
            async {
                match &other_domain {
                    Some(host) => Some(records::collect(&self.resolver, host, DomainRole::Final, &deadline).await),
                    None => None,
                }
            }
        );
        let dns: Vec<DomainRecords> = input_records.into_iter().chain(final_records).collect();

        let asn_ip = if opts.fetch.asn {
            final_address(&chain, &dns)
        } else {
            None
        };
        let asn = match asn_ip {
            Some(ip) if !ip.is_loopback() => deadline.run(asn::lookup(&self.resolver, ip)).await,
            _ => None,
        };
        let deadline_hit = main.deadline_hit || side.deadline_hit || deadline.passed();

        Snapshot {
            snapshot_version: SNAPSHOT_VERSION,
            collector_version: env!("CARGO_PKG_VERSION").to_owned(),
            collected_at,
            duration: t0.elapsed(),
            input: target.url.to_string(),
            request: opts.request.clone(),
            chain,
            page,
            http_check,
            https_fallback,
            failure,
            deadline_hit,
            interrupted: deadline.interrupted(),
            browser: None,
            dns,
            asn,
            auxiliary: auxiliary.unwrap_or_default(),
        }
    }
}

/// The address of the final origin: the connected peer, or, behind a proxy, the
/// first address our DNS records hold for the final host.
fn final_address(chain: &[Hop], dns: &[DomainRecords]) -> Option<IpAddr> {
    let last = chain.last()?;
    let info = crate::analyze::network::opener(chain, last)?;
    if info.proxy.is_none() {
        return Some(info.peer.ip());
    }
    let host = Url::parse(&last.url).ok()?.host_str()?.to_owned();
    dns.iter()
        .flat_map(|d| d.records(&host, "A").iter().chain(d.records(&host, "AAAA")))
        .find_map(|a| a.parse().ok())
}

/// Fetches robots.txt and security.txt from the final origin, in parallel with the
/// page body, then the sitemap once the body has arrived so it does not compete
/// with the download we time. Over HTTP/2 the requests share the page's connection
/// as extra streams; over HTTP/1.1 they use one second connection.
#[allow(clippy::too_many_arguments)]
async fn fetch_auxiliary(
    collector: Collector,
    opts: Options,
    t0: Instant,
    deadline: Deadline,
    page_url: Url,
    h2: Option<Sender>,
    addresses: HashMap<String, Vec<IpAddr>>,
    body_done: Option<oneshot::Receiver<()>>,
) -> Auxiliary {
    let mut origin = page_url.clone();
    origin.set_path("/");
    origin.set_query(None);
    let robots_url = origin.join("/robots.txt").expect("static path");
    let security_url = origin.join("/.well-known/security.txt").expect("static path");

    let seeded = |sender: Option<Sender>| {
        let mut session = Session::new(&collector, &opts, t0, deadline.clone());
        session.addresses = addresses.clone();
        if let Some(sender) = sender {
            let key = session.origin(&page_url);
            session.pool.insert(key, sender);
        }
        session
    };
    let multiplexed = h2.is_some();
    let mut first = seeded(h2.as_ref().and_then(Sender::try_clone));
    let mut second = seeded(h2);

    let fetch = opts.fetch;
    let (robots, security_txt) = if multiplexed {
        tokio::join!(
            async {
                match fetch.robots_and_sitemap {
                    true => Some(first.aux_file(&robots_url, ROBOTS_LIMIT).await),
                    false => None,
                }
            },
            async {
                match fetch.security_txt {
                    true => Some(second.aux_file(&security_url, SECURITY_TXT_LIMIT).await),
                    false => None,
                }
            }
        )
    } else {
        let robots = match fetch.robots_and_sitemap {
            true => Some(first.aux_file(&robots_url, ROBOTS_LIMIT).await),
            false => None,
        };
        let security = match fetch.security_txt {
            true => Some(first.aux_file(&security_url, SECURITY_TXT_LIMIT).await),
            false => None,
        };
        (robots, security)
    };

    let sitemap = if fetch.robots_and_sitemap {
        if let Some(done) = body_done {
            let _ = deadline.run(done).await;
        }
        let declared = robots
            .as_ref()
            .filter(|r| r.status == Some(200))
            .and_then(|r| sitemap_from_robots(&String::from_utf8_lossy(&r.body), &origin));
        let url = declared.unwrap_or_else(|| origin.join("/sitemap.xml").expect("static path"));
        Some(first.aux_file(&url, SITEMAP_LIMIT).await)
    } else {
        None
    };
    Auxiliary {
        robots,
        security_txt,
        sitemap,
    }
}

/// The first `Sitemap:` line of a robots.txt, resolved against the origin.
pub fn sitemap_from_robots(robots: &str, origin: &Url) -> Option<Url> {
    robots.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if !key.trim().eq_ignore_ascii_case("sitemap") {
            return None;
        }
        origin
            .join(value.trim())
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"))
            .map(|mut u| {
                self::target::strip_userinfo(&mut u);
                u
            })
    })
}

/// One hop's worth of work: the hop, plus either the page or the next URL.
struct Step {
    hop: Hop,
    page: Option<Page>,
    next: Option<Url>,
}

struct AttemptError {
    failure: FetchFailure,
    retryable: bool,
}

#[derive(PartialEq, Eq, Hash, Clone)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

struct AuxRun {
    task: JoinHandle<Auxiliary>,
    body_done: Option<oneshot::Sender<()>>,
}

/// State for one chain of requests: open connections by origin and resolved hosts.
struct Session<'a> {
    collector: &'a Collector,
    opts: &'a Options,
    t0: Instant,
    deadline: Deadline,
    pool: HashMap<Origin, Sender>,
    addresses: HashMap<String, Vec<IpAddr>>,
    resolutions: Vec<Resolved>,
    deadline_hit: bool,
    /// Start the auxiliary requests when the final response's headers arrive.
    spawn_aux: bool,
    aux: Option<AuxRun>,
}

enum Expired {
    Phase,
    Global,
}

impl<'a> Session<'a> {
    fn new(collector: &'a Collector, opts: &'a Options, t0: Instant, deadline: Deadline) -> Self {
        Session {
            collector,
            opts,
            t0,
            deadline,
            pool: HashMap::new(),
            addresses: HashMap::new(),
            resolutions: Vec::new(),
            deadline_hit: false,
            spawn_aux: false,
            aux: None,
        }
    }

    /// Follows redirects from `url` until a final response, appending each hop.
    async fn follow(
        &mut self,
        mut url: Url,
        chain: &mut Vec<Hop>,
        visited: &mut HashSet<String>,
    ) -> Result<Option<Page>, FetchFailure> {
        loop {
            if !visited.insert(url.to_string()) {
                let message = format!("redirect loop: {url} was already visited");
                return Err(failure(FailureKind::RedirectLoop, &url, message));
            }
            if chain.len() > self.opts.max_redirects {
                let message = format!("more than {} redirects", self.opts.max_redirects);
                return Err(failure(FailureKind::TooManyRedirects, &url, message));
            }
            let step = self.step(&url, self.opts.body_limit).await?;
            chain.push(step.hop);
            match step.next {
                Some(next) => url = next,
                None => return Ok(step.page),
            }
        }
    }

    /// An auxiliary file: up to three redirects, never an error, only a record.
    async fn aux_file(&mut self, url: &Url, limit: usize) -> AuxFile {
        let mut file = AuxFile {
            requested: url.to_string(),
            url: url.to_string(),
            status: None,
            content_type: None,
            body: Vec::new(),
            truncated: false,
            redirects: 0,
            error: None,
        };
        let mut current = url.clone();
        loop {
            match self.step(&current, limit).await {
                Err(f) => {
                    file.error = Some(f.message);
                    return file;
                }
                Ok(step) => {
                    file.url = current.to_string();
                    file.status = Some(step.hop.status);
                    file.content_type = step.hop.header("content-type").map(str::to_owned);
                    match (step.next, step.page) {
                        (Some(next), _) if usize::from(file.redirects) < AUX_MAX_REDIRECTS => {
                            file.redirects += 1;
                            current = next;
                        }
                        (Some(_), _) => {
                            file.error = Some(format!("more than {AUX_MAX_REDIRECTS} redirects"));
                            return file;
                        }
                        (None, Some(page)) => {
                            file.truncated = page.truncated;
                            file.error = page.decode_error;
                            file.body = page.body;
                            return file;
                        }
                        (None, None) => return file,
                    }
                }
            }
        }
    }

    /// Fetches one URL with at most one retry after a network failure. HTTP
    /// statuses are never retried: a 503 is reported as it came.
    ///
    /// Boxed with an explicit `Send` because the auxiliary task spawned from
    /// `attempt` calls back into `step`, a cycle the compiler cannot see through.
    fn step<'s>(&'s mut self, url: &'s Url, body_limit: usize) -> BoxFuture<'s, Result<Step, FetchFailure>> {
        Box::pin(self.step_inner(url, body_limit))
    }

    async fn step_inner(&mut self, url: &Url, body_limit: usize) -> Result<Step, FetchFailure> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.attempt(url, body_limit).await {
                Ok(mut step) => {
                    step.hop.attempts = attempts;
                    return Ok(step);
                }
                Err(e) if e.retryable && attempts == 1 && !self.deadline.passed() => {
                    self.pool.remove(&self.origin(url));
                }
                Err(e) => return Err(e.failure),
            }
        }
    }

    async fn attempt(&mut self, url: &Url, body_limit: usize) -> Result<Step, AttemptError> {
        let origin = self.origin(url);
        let (mut sender, connection) = match self.pool.remove(&origin) {
            Some(sender) if !sender.is_closed() => (sender, ConnectionUse::Reused),
            _ => {
                let (sender, info) = self.open(url, origin.port).await?;
                (sender, ConnectionUse::New(Box::new(info)))
            }
        };
        let reused = matches!(connection, ConnectionUse::Reused);

        let (sent, response) = match self.within(None, sender.get(url, &self.opts.request)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                // A kept-alive connection the server already closed is worth a retry.
                let retryable = reused || e.is_closed() || e.is_incomplete_message() || e.is_canceled();
                let message = format!("HTTP request failed: {e}");
                return Err(AttemptError {
                    failure: failure(FailureKind::Http, url, message),
                    retryable,
                });
            }
            Err(_) => return Err(self.timed_out(url, "response headers")),
        };
        let headers_at = Instant::now();
        let version = sender.version();

        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let mut hop = Hop {
            url: url.to_string(),
            connection,
            request_at: sent - self.t0,
            ttfb: headers_at - sent,
            download: Duration::ZERO,
            status,
            version,
            headers,
            attempts: 1,
        };

        let next = if hop.is_redirect() {
            hop.header("location")
                .and_then(|location| url.join(location).ok())
                .filter(|next| matches!(next.scheme(), "http" | "https"))
                .map(|mut next| {
                    // A redirect to `https://user:pass@host/` is followed without them.
                    self::target::strip_userinfo(&mut next);
                    next
                })
        } else {
            None
        };

        // The final response's headers fix the final origin: the auxiliary
        // requests start now, in parallel with the body.
        if self.spawn_aux && next.is_none() && self.aux.is_none() {
            self.spawn_aux = false;
            let (done_tx, done_rx) = oneshot::channel();
            let task = tokio::spawn(fetch_auxiliary(
                self.collector.clone(),
                self.opts.clone(),
                self.t0,
                self.deadline.clone(),
                url.clone(),
                sender.try_clone(),
                self.addresses.clone(),
                Some(done_rx),
            ));
            self.aux = Some(AuxRun {
                task,
                body_done: Some(done_tx),
            });
        }
        self.pool.insert(origin, sender);

        let limit = if next.is_some() {
            REDIRECT_BODY_LIMIT
        } else {
            body_limit
        };
        let raw = http::read_body(response.into_body(), limit, &self.deadline).await;
        hop.download = headers_at.elapsed();
        self.deadline_hit |= raw.deadline_hit;
        if next.is_none()
            && let Some(done) = self.aux.as_mut().and_then(|a| a.body_done.take())
        {
            let _ = done.send(());
        }

        let page = next.is_none().then(|| {
            let encoding = hop.header("content-encoding");
            let decoded = http::decode(&raw.bytes, encoding, body_limit);
            Page {
                transferred: raw.bytes.len() as u64,
                content_encoding: encoding.map(str::to_owned),
                truncated: raw.truncated || decoded.truncated,
                deadline_hit: raw.deadline_hit,
                decode_error: raw.error.or(decoded.error),
                body: decoded.body,
            }
        });
        Ok(Step { hop, page, next })
    }

    /// DNS, TCP (or a proxy tunnel), TLS and the HTTP handshake for a new connection.
    async fn open(&mut self, url: &Url, port: u16) -> Result<(Sender, ConnectionInfo), AttemptError> {
        let host = url.host().expect("targets always have a host").to_owned();
        let via = self.opts.proxy.for_url(url).cloned();
        let mut resolution = None;

        // Behind a proxy we connect to the proxy, and the proxy resolves the name.
        let (connect_host, connect_port) = match &via {
            Some(proxy) => (proxy.host.clone(), proxy.port),
            None => (host.clone(), port),
        };
        let addresses = match &connect_host {
            Host::Ipv4(ip) => vec![IpAddr::V4(*ip)],
            Host::Ipv6(ip) => vec![IpAddr::V6(*ip)],
            Host::Domain(name) => match self.addresses.get(name) {
                Some(cached) => cached.clone(),
                None => {
                    let resolved = match self
                        .within(Some(DNS_TIMEOUT), self.collector.resolver.resolve(name))
                        .await
                    {
                        Ok(Ok(resolved)) => resolved,
                        Ok(Err(e)) => {
                            let kind = if via.is_some() { FailureKind::Proxy } else { e.kind };
                            return Err(AttemptError {
                                failure: failure(kind, url, e.message),
                                retryable: e.retryable,
                            });
                        }
                        Err(Expired::Phase) => {
                            return Err(self.phase_timeout(FailureKind::Dns, url, "DNS", DNS_TIMEOUT));
                        }
                        Err(Expired::Global) => return Err(self.timed_out(url, "DNS")),
                    };
                    let addresses = resolved.resolution.addresses.clone();
                    self.addresses.insert(name.clone(), addresses.clone());
                    if via.is_none() {
                        resolution = Some(resolved.resolution.clone());
                        self.resolutions.push(resolved);
                    }
                    addresses
                }
            },
        };

        let connected = match self
            .within(
                Some(CONNECT_TIMEOUT),
                connect::happy_eyeballs(&addresses, connect_port, self.t0),
            )
            .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                let (kind, message) = match &via {
                    Some(proxy) => (
                        FailureKind::Proxy,
                        format!("could not connect to proxy {}: {e}", proxy.display()),
                    ),
                    None => (
                        FailureKind::Connect,
                        format!("could not connect to {host} port {port}: {e}"),
                    ),
                };
                return Err(AttemptError {
                    failure: failure(kind, url, message),
                    retryable: true,
                });
            }
            Err(Expired::Phase) => {
                return Err(self.phase_timeout(FailureKind::Connect, url, "TCP connection", CONNECT_TIMEOUT));
            }
            Err(Expired::Global) => return Err(self.timed_out(url, "TCP connection")),
        };
        let mut stream = connected.stream;
        if let Some(proxy) = &via {
            match self
                .within(Some(CONNECT_TIMEOUT), proxy::tunnel(&mut stream, proxy, &host, port))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(message)) => {
                    return Err(AttemptError {
                        failure: failure(FailureKind::Proxy, url, message),
                        retryable: false,
                    });
                }
                Err(Expired::Phase) => {
                    return Err(self.phase_timeout(FailureKind::Proxy, url, "proxy tunnel", CONNECT_TIMEOUT));
                }
                Err(Expired::Global) => return Err(self.timed_out(url, "proxy tunnel")),
            }
        }
        let mut info = ConnectionInfo {
            resolution,
            peer: connected.peer,
            connect_at: connected.connect_at,
            tcp: connected.tcp,
            tls: None,
            proxy: via.as_ref().map(proxy::Proxy::display),
        };

        let handshake = if url.scheme() == "https" {
            let (stream, tls) = match self
                .within(Some(TLS_TIMEOUT), self.collector.tls.handshake(stream, &host))
                .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    return Err(AttemptError {
                        failure: failure(e.kind, url, e.message),
                        retryable: e.retryable,
                    });
                }
                Err(Expired::Phase) => {
                    return Err(self.phase_timeout(FailureKind::Tls, url, "TLS handshake", TLS_TIMEOUT));
                }
                Err(Expired::Global) => return Err(self.timed_out(url, "TLS handshake")),
            };
            let version = if tls.alpn.as_deref() == Some("h2") {
                HttpVersion::Http2
            } else {
                HttpVersion::Http1
            };
            info.tls = Some(tls);
            Sender::handshake(stream, version).await
        } else {
            Sender::handshake(stream, HttpVersion::Http1).await
        };
        match handshake {
            Ok(sender) => Ok((sender, info)),
            Err(e) => Err(AttemptError {
                failure: failure(FailureKind::Http, url, format!("HTTP handshake failed: {e}")),
                retryable: true,
            }),
        }
    }

    fn origin(&self, url: &Url) -> Origin {
        let default = if url.scheme() == "https" {
            self.opts.default_ports.https
        } else {
            self.opts.default_ports.http
        };
        Origin {
            scheme: url.scheme().to_owned(),
            host: url.host_str().unwrap_or_default().to_owned(),
            port: url.port().unwrap_or(default),
        }
    }

    /// Runs `fut` until the phase limit or the global deadline, whichever is first.
    async fn within<T>(&self, phase: Option<Duration>, fut: impl Future<Output = T>) -> Result<T, Expired> {
        let Some(limit) = phase else {
            return self.deadline.run(fut).await.ok_or(Expired::Global);
        };
        self.deadline
            .run_until(tokio::time::Instant::now() + limit, fut)
            .await
            .map_err(|e| match e {
                deadline::Expired::Global => Expired::Global,
                deadline::Expired::Limit => Expired::Phase,
            })
    }

    fn phase_timeout(&self, kind: FailureKind, url: &Url, phase: &str, limit: Duration) -> AttemptError {
        let message = format!("{phase} did not finish within {} s", limit.as_secs());
        AttemptError {
            failure: failure(kind, url, message),
            retryable: true,
        }
    }

    fn timed_out(&mut self, url: &Url, phase: &str) -> AttemptError {
        self.deadline_hit = true;
        let message = if self.deadline.interrupted() {
            format!("interrupted during {phase}")
        } else {
            format!(
                "global deadline of {} s reached during {phase}",
                self.opts.timeout.as_secs_f32()
            )
        };
        AttemptError {
            failure: failure(FailureKind::Timeout, url, message),
            retryable: false,
        }
    }

    /// Waits (until the deadline) for AAAA answers that missed the resolution delay
    /// and records whether each host has IPv6.
    async fn settle_into(&mut self, chain: &mut [Hop]) {
        for resolved in &mut self.resolutions {
            let _ = self.deadline.run(resolved.settle()).await;
            for hop in chain.iter_mut() {
                if let ConnectionUse::New(info) = &mut hop.connection
                    && let Some(resolution) = &mut info.resolution
                    && resolution.host == resolved.resolution.host
                {
                    resolution.has_ipv6 = resolved.resolution.has_ipv6;
                }
            }
        }
    }
}

fn failure(kind: FailureKind, url: &Url, message: String) -> FetchFailure {
    FetchFailure {
        kind,
        url: url.to_string(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sitemap_line_is_found_and_resolved() {
        let origin = Url::parse("https://exemplo.com.br/").unwrap();
        let robots =
            "User-agent: *\nDisallow: /admin\n\nSITEMAP: /sitemap_index.xml\nSitemap: https://cdn.example/x.xml\n";
        assert_eq!(
            sitemap_from_robots(robots, &origin).unwrap().as_str(),
            "https://exemplo.com.br/sitemap_index.xml"
        );
        assert!(sitemap_from_robots("User-agent: *", &origin).is_none());
    }
}
