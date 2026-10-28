//! Raw data produced by the collection phase.
//!
//! A `Snapshot` holds only what was observed on the network, never conclusions.
//! The analysis phase turns it into a `Report` without touching the network or
//! the clock: every "now" the analyzers need comes from `collected_at`.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

/// Bumped on every change to these types. Each bump ships a conversion from
/// the previous version, so recorded fixtures never need to be re-recorded.
pub const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub snapshot_version: u32,
    pub collector_version: String,
    /// Wall clock at t = 0. The only clock reading the analysis ever sees.
    pub collected_at: SystemTime,
    /// From t = 0 until the snapshot closed.
    pub duration: Duration,
    pub input: String,
    pub request: RequestProfile,
    /// Every hop of the main chain, in order. The last one is the final response
    /// unless `failure` is set.
    pub chain: Vec<Hop>,
    /// Body of the final response.
    pub page: Option<Page>,
    /// Plain HTTP request to port 80, run in parallel when the input is HTTPS.
    pub http_check: Option<HttpCheck>,
    /// The chain started from the port 80 response because HTTPS was unavailable.
    pub https_fallback: Option<FetchFailure>,
    /// Why the chain stopped before a final response, if it did.
    pub failure: Option<FetchFailure>,
    /// The global deadline expired before collection finished.
    pub deadline_hit: bool,
}

/// What we sent, recorded because it changes what servers answer.
#[derive(Debug, Clone)]
pub struct RequestProfile {
    pub user_agent: String,
    pub accept_language: String,
    pub accept_encoding: String,
}

#[derive(Debug, Clone)]
pub struct Hop {
    pub url: String,
    pub connection: ConnectionUse,
    /// Offset from t = 0 at which the request was handed to hyper.
    pub request_at: Duration,
    /// Request handed to hyper until response headers were received. Ending at the
    /// headers, not at the first byte read, keeps the meaning identical in HTTP/2,
    /// where the first bytes can be control frames.
    pub ttfb: Duration,
    /// Response headers until the last byte of the body.
    pub download: Duration,
    pub status: u16,
    pub version: HttpVersion,
    /// In received order, duplicates kept (several `set-cookie`, for example).
    pub headers: Vec<(String, String)>,
    /// Network attempts used for this hop; 2 means one retry after a network failure.
    pub attempts: u8,
}

impl Hop {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308) && self.header("location").is_some()
    }

    /// Offset from t = 0 at which the last byte of this hop arrived.
    pub fn finished_at(&self) -> Duration {
        self.request_at + self.ttfb + self.download
    }
}

#[derive(Debug, Clone)]
pub enum ConnectionUse {
    New(Box<ConnectionInfo>),
    /// An earlier connection to the same origin carried this request.
    Reused,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Present when the host was resolved for this connection; absent for IP
    /// literals and for hosts already resolved earlier in the chain.
    pub resolution: Option<HostResolution>,
    pub peer: SocketAddr,
    /// Offset from t = 0 at which `connect()` was called on the winning attempt.
    pub connect_at: Duration,
    pub tcp: Duration,
    pub tls: Option<TlsInfo>,
}

#[derive(Debug, Clone)]
pub struct HostResolution {
    pub host: String,
    /// Query sent until the first address was resolved. Absent when the system
    /// resolver answered instead of ours, because then we cannot time it.
    pub duration: Option<Duration>,
    pub addresses: Vec<IpAddr>,
    /// Whether the host has AAAA records, independent of which family won the race.
    pub has_ipv6: bool,
    pub source: ResolutionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionSource {
    Resolver,
    /// Our resolver failed and the operating system resolved the name (VPN with
    /// split DNS, internal names, mDNS).
    System,
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    /// ClientHello until the handshake completed.
    pub handshake: Duration,
    pub sni: Option<String>,
    pub version: String,
    pub cipher_suite: String,
    pub key_exchange: Option<String>,
    pub alpn: Option<String>,
    pub verification: Verification,
    /// DER, leaf first, as sent by the server.
    pub certificates: Vec<Vec<u8>>,
    pub ocsp_stapled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    Valid,
    /// webpki stops at the first problem; the TLS analyzer checks dates and names
    /// on its own, so it can report every problem, not just this one.
    Invalid {
        problem: CertProblem,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertProblem {
    Expired,
    NotYetValid,
    UnknownIssuer,
    NameMismatch,
    Revoked,
    BadSignature,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1,
    Http2,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Http1 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Page {
    /// Decoded body, at most `Options::body_limit` bytes.
    pub body: Vec<u8>,
    /// Bytes on the wire, before decompression.
    pub transferred: u64,
    pub content_encoding: Option<String>,
    /// The body hit the limit, before or after decompression, and was cut.
    pub truncated: bool,
    pub decode_error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HttpCheck {
    Response { status: u16, location: Option<String> },
    Failed(FetchFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchFailure {
    pub kind: FailureKind,
    pub url: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    InvalidInput,
    Dns,
    Connect,
    /// The server answered the handshake with an alert we cannot get past: it only
    /// speaks protocol versions or cipher suites outside what rustls supports.
    TlsIncompatible,
    Tls,
    Http,
    RedirectLoop,
    TooManyRedirects,
    Timeout,
}
