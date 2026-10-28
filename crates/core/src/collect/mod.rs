//! Collection: everything that touches the network. Produces a `Snapshot`.

pub mod asn;
pub mod connect;
pub mod dns;
pub mod http;
pub mod records;
pub mod target;
pub mod tls;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use url::{Host, Url};

use crate::snapshot::{
    ConnectionInfo, ConnectionUse, DomainRole, FailureKind, FetchFailure, Hop, HttpCheck, HttpVersion, Page,
    RequestProfile, SNAPSHOT_VERSION, Snapshot,
};
use dns::{Resolved, Resolver};
use http::Sender;
use target::Target;
use tls::Tls;

pub const DNS_TIMEOUT: Duration = Duration::from_secs(2);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const TLS_TIMEOUT: Duration = Duration::from_secs(3);
/// Redirect bodies are read only so the connection can be reused.
const REDIRECT_BODY_LIMIT: usize = 64 << 10;

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
    /// `extra_roots` are DER certificates trusted on top of the embedded roots.
    pub fn new(extra_roots: &[Vec<u8>]) -> Result<Self, String> {
        Self::with_resolver(Resolver::from_system()?, extra_roots)
    }

    pub fn with_resolver(resolver: Resolver, extra_roots: &[Vec<u8>]) -> Result<Self, String> {
        Ok(Collector {
            resolver,
            tls: Tls::new(extra_roots)?,
        })
    }

    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    pub async fn collect(&self, target: &Target, opts: &Options) -> Snapshot {
        let t0 = Instant::now();
        let collected_at = SystemTime::now();
        let deadline = tokio::time::Instant::from_std(t0 + opts.timeout);

        let mut main = Session::new(self, opts, t0, deadline);
        let mut side = Session::new(self, opts, t0, deadline);
        let check_url = (target.url.scheme() == "https" && !target.explicit_port).then(|| {
            let mut url = target.url.clone();
            url.set_scheme("http").expect("https URLs can become http");
            url
        });

        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        // DNS records of the input domain start at t = 0, alongside the page.
        let input_host = match target.url.host() {
            Some(Host::Domain(domain)) => Some(domain.to_owned()),
            _ => None,
        };
        let (main_result, check_step, input_records) = tokio::join!(
            main.follow(target.url.clone(), &mut chain, &mut visited),
            async {
                match &check_url {
                    Some(url) => Some(side.step(url).await),
                    None => None,
                }
            },
            async {
                match &input_host {
                    Some(host) => Some(records::collect(&self.resolver, host, DomainRole::Input, deadline).await),
                    None => None,
                }
            }
        );

        let http_check = check_step.as_ref().map(|step| match step {
            Ok(step) => HttpCheck::Response {
                status: step.hop.status,
                location: step.hop.header("location").map(str::to_owned),
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

        // Once the chain is known: the final domain's records, when it is another
        // registrable domain, and the owner of the final peer address.
        let final_url = chain.last().and_then(|hop| Url::parse(&hop.url).ok());
        let final_host = final_url.as_ref().and_then(|u| match u.host() {
            Some(Host::Domain(d)) => Some(d.to_owned()),
            _ => None,
        });
        let other_domain = final_host.filter(|f| {
            input_host
                .as_deref()
                .is_none_or(|i| records::registrable(i) != records::registrable(f))
        });
        let peer = chain
            .last()
            .and_then(|hop| crate::analyze::network::opener(&chain, hop))
            .map(|c| c.peer.ip());
        let (final_records, asn) = tokio::join!(
            async {
                match &other_domain {
                    Some(host) => Some(records::collect(&self.resolver, host, DomainRole::Final, deadline).await),
                    None => None,
                }
            },
            async {
                match peer {
                    Some(ip) if !ip.is_loopback() => tokio::time::timeout_at(deadline, asn::lookup(&self.resolver, ip))
                        .await
                        .ok(),
                    _ => None,
                }
            }
        );
        let deadline_hit = main.deadline_hit || side.deadline_hit || tokio::time::Instant::now() >= deadline;

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
            dns: input_records.into_iter().chain(final_records).collect(),
            asn,
        }
    }
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

/// State for one chain of requests: open connections by origin and resolved hosts.
struct Session<'a> {
    collector: &'a Collector,
    opts: &'a Options,
    t0: Instant,
    deadline: tokio::time::Instant,
    pool: HashMap<Origin, Sender>,
    addresses: HashMap<String, Vec<IpAddr>>,
    resolutions: Vec<Resolved>,
    deadline_hit: bool,
}

enum Expired {
    Phase,
    Global,
}

impl<'a> Session<'a> {
    fn new(collector: &'a Collector, opts: &'a Options, t0: Instant, deadline: tokio::time::Instant) -> Self {
        Session {
            collector,
            opts,
            t0,
            deadline,
            pool: HashMap::new(),
            addresses: HashMap::new(),
            resolutions: Vec::new(),
            deadline_hit: false,
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
                return Err(failure(
                    FailureKind::RedirectLoop,
                    &url,
                    format!("redirect loop: {url} was already visited"),
                ));
            }
            if chain.len() > self.opts.max_redirects {
                let message = format!("more than {} redirects", self.opts.max_redirects);
                return Err(failure(FailureKind::TooManyRedirects, &url, message));
            }
            let step = self.step(&url).await?;
            chain.push(step.hop);
            match step.next {
                Some(next) => url = next,
                None => return Ok(step.page),
            }
        }
    }

    /// Fetches one URL with at most one retry after a network failure. HTTP
    /// statuses are never retried: a 503 is reported as it came.
    async fn step(&mut self, url: &Url) -> Result<Step, FetchFailure> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.attempt(url).await {
                Ok(mut step) => {
                    step.hop.attempts = attempts;
                    return Ok(step);
                }
                Err(e) if e.retryable && attempts == 1 && tokio::time::Instant::now() < self.deadline => {
                    self.pool.remove(&self.origin(url));
                }
                Err(e) => return Err(e.failure),
            }
        }
    }

    async fn attempt(&mut self, url: &Url) -> Result<Step, AttemptError> {
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
                return Err(AttemptError {
                    failure: failure(FailureKind::Http, url, format!("HTTP request failed: {e}")),
                    retryable,
                });
            }
            Err(_) => return Err(self.timed_out(url, "response headers")),
        };
        let headers_at = Instant::now();
        let version = sender.version();
        self.pool.insert(origin, sender);

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
        } else {
            None
        };
        let limit = if next.is_some() {
            REDIRECT_BODY_LIMIT
        } else {
            self.opts.body_limit
        };
        let raw = http::read_body(response.into_body(), limit, self.deadline).await;
        hop.download = headers_at.elapsed();
        self.deadline_hit |= raw.deadline_hit;

        let page = next.is_none().then(|| {
            let encoding = hop.header("content-encoding");
            let decoded = http::decode(&raw.bytes, encoding, self.opts.body_limit);
            Page {
                transferred: raw.bytes.len() as u64,
                content_encoding: encoding.map(str::to_owned),
                truncated: raw.truncated || decoded.truncated,
                decode_error: raw.error.or(decoded.error),
                body: decoded.body,
            }
        });
        Ok(Step { hop, page, next })
    }

    /// DNS, TCP, TLS and the HTTP handshake for a new connection.
    async fn open(&mut self, url: &Url, port: u16) -> Result<(Sender, ConnectionInfo), AttemptError> {
        let host = url.host().expect("targets always have a host").to_owned();
        let mut resolution = None;
        let addresses = match &host {
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
                            return Err(AttemptError {
                                failure: failure(e.kind, url, e.message),
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
                    resolution = Some(resolved.resolution.clone());
                    self.resolutions.push(resolved);
                    addresses
                }
            },
        };

        let connected = match self
            .within(
                Some(CONNECT_TIMEOUT),
                connect::happy_eyeballs(&addresses, port, self.t0),
            )
            .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                let message = format!("could not connect to {host} port {port}: {e}");
                return Err(AttemptError {
                    failure: failure(FailureKind::Connect, url, message),
                    retryable: true,
                });
            }
            Err(Expired::Phase) => {
                return Err(self.phase_timeout(FailureKind::Connect, url, "TCP connection", CONNECT_TIMEOUT));
            }
            Err(Expired::Global) => return Err(self.timed_out(url, "TCP connection")),
        };
        let mut info = ConnectionInfo {
            resolution,
            peer: connected.peer,
            connect_at: connected.connect_at,
            tcp: connected.tcp,
            tls: None,
        };

        let handshake = if url.scheme() == "https" {
            let (stream, tls) = match self
                .within(Some(TLS_TIMEOUT), self.collector.tls.handshake(connected.stream, &host))
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
            Sender::handshake(connected.stream, HttpVersion::Http1).await
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
        let phase_deadline = phase.map(|limit| tokio::time::Instant::now() + limit);
        let until = phase_deadline.map_or(self.deadline, |p| p.min(self.deadline));
        tokio::time::timeout_at(until, fut).await.map_err(|_| {
            if until == self.deadline {
                Expired::Global
            } else {
                Expired::Phase
            }
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
        let message = format!(
            "global deadline of {} s reached during {phase}",
            self.opts.timeout.as_secs_f32()
        );
        AttemptError {
            failure: failure(FailureKind::Timeout, url, message),
            retryable: false,
        }
    }

    /// Waits (until the deadline) for AAAA answers that missed the resolution delay
    /// and records whether each host has IPv6.
    async fn settle_into(&mut self, chain: &mut [Hop]) {
        for resolved in &mut self.resolutions {
            let _ = tokio::time::timeout_at(self.deadline, resolved.settle()).await;
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
