//! HTTP proxies through a CONNECT tunnel, configured like curl: `HTTPS_PROXY`,
//! `HTTP_PROXY` and `NO_PROXY`.
//!
//! Behind a proxy the proxy resolves the name, so our DNS phase is skipped and
//! TCP timing measures the path to the proxy; the report says so.

use std::net::IpAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::{Host, Url};

/// Responses to CONNECT larger than this are not a proxy talking.
const MAX_RESPONSE_HEAD: usize = 16 << 10;

#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    pub https: Option<Proxy>,
    pub http: Option<Proxy>,
    /// Hosts and domain suffixes reached directly; `*` disables the proxy.
    pub no_proxy: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: Host<String>,
    pub port: u16,
    /// Value of `Proxy-Authorization`, from credentials in the proxy URL.
    pub authorization: Option<String>,
}

impl Proxy {
    pub fn parse(value: &str) -> Result<Self, String> {
        let with_scheme = if value.contains("://") {
            value.to_owned()
        } else {
            format!("http://{value}")
        };
        let url = Url::parse(&with_scheme).map_err(|e| format!("invalid proxy URL `{value}`: {e}"))?;
        if url.scheme() != "http" {
            return Err(format!(
                "unsupported proxy scheme `{}`: only http:// proxies are supported",
                url.scheme()
            ));
        }
        let host = url
            .host()
            .ok_or_else(|| format!("proxy URL `{value}` has no host"))?
            .to_owned();
        let authorization = (!url.username().is_empty()).then(|| {
            let user = percent_decode(url.username());
            let pass = percent_decode(url.password().unwrap_or_default());
            format!("Basic {}", base64(format!("{user}:{pass}").as_bytes()))
        });
        Ok(Proxy {
            host,
            port: url.port().unwrap_or(80),
            authorization,
        })
    }

    /// `host:port`, never the credentials.
    pub fn display(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl ProxyConfig {
    /// From the values of the environment variables (curl's conventions).
    pub fn from_values(https: Option<&str>, http: Option<&str>, no_proxy: Option<&str>) -> Result<Self, String> {
        let parse = |v: Option<&str>| {
            v.filter(|v| !v.trim().is_empty())
                .map(|v| Proxy::parse(v.trim()))
                .transpose()
        };
        Ok(ProxyConfig {
            https: parse(https)?,
            http: parse(http)?,
            no_proxy: no_proxy
                .unwrap_or_default()
                .split(',')
                .map(|p| {
                    p.trim()
                        .trim_start_matches("*.")
                        .trim_start_matches('.')
                        .to_ascii_lowercase()
                })
                .filter(|p| !p.is_empty())
                .collect(),
        })
    }

    pub fn for_url(&self, url: &Url) -> Option<&Proxy> {
        let proxy = if url.scheme() == "https" {
            self.https.as_ref()
        } else {
            self.http.as_ref()
        }?;
        let host = url
            .host_str()?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let ip: Option<IpAddr> = host.parse().ok();
        let bypass = self
            .no_proxy
            .iter()
            .any(|p| p == "*" || host == *p || host.ends_with(&format!(".{p}")) || ip.is_some_and(|ip| in_cidr(ip, p)));
        (!bypass).then_some(proxy)
    }
}

/// `10.0.0.0/8` style entries, as curl accepts in `NO_PROXY`.
fn in_cidr(ip: IpAddr, entry: &str) -> bool {
    let Some((net, bits)) = entry.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// Asks the proxy for a tunnel to `host:port` and waits for its 2xx answer.
pub async fn tunnel(stream: &mut TcpStream, proxy: &Proxy, host: &Host<String>, port: u16) -> Result<(), String> {
    let authority = match host {
        Host::Ipv6(ip) => format!("[{ip}]:{port}"),
        other => format!("{other}:{port}"),
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = &proxy.authorization {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("could not talk to proxy {}: {e}", proxy.display()))?;

    // Read byte by byte up to the end of the head, so nothing of the tunnel is consumed.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("proxy {} closed the connection: {e}", proxy.display()))?;
        if n == 0 {
            return Err(format!(
                "proxy {} closed the connection before answering",
                proxy.display()
            ));
        }
        head.push(byte[0]);
        if head.len() > MAX_RESPONSE_HEAD {
            return Err(format!("proxy {} sent an oversized answer", proxy.display()));
        }
    }
    let status_line = String::from_utf8_lossy(&head);
    let status_line = status_line.lines().next().unwrap_or_default();
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(200..=299) => Ok(()),
        _ => Err(format!(
            "proxy {} refused the tunnel to {authority}: {status_line}",
            proxy.display()
        )),
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(byte) = text.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Standard base64 with padding, for `Proxy-Authorization: Basic`.
pub fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_urls_with_credentials() {
        let p = Proxy::parse("http://user:p%40ss@proxy.corp:3128").unwrap();
        assert_eq!(p.display(), "proxy.corp:3128");
        assert_eq!(p.authorization.as_deref(), Some("Basic dXNlcjpwQHNz"));
        assert_eq!(Proxy::parse("10.0.0.1:8080").unwrap().display(), "10.0.0.1:8080");
        assert!(Proxy::parse("socks5://x:1080").is_err());
    }

    #[test]
    fn no_proxy_matches_hosts_and_suffixes() {
        let config =
            ProxyConfig::from_values(Some("http://p:3128"), None, Some("localhost, .internal.corp,10.1.2.3")).unwrap();
        let url = |u: &str| Url::parse(u).unwrap();
        assert!(config.for_url(&url("https://example.com/")).is_some());
        assert!(config.for_url(&url("https://intranet.internal.corp/")).is_none());
        assert!(config.for_url(&url("https://internal.corp/")).is_none());
        assert!(config.for_url(&url("https://localhost:8443/")).is_none());
        assert!(config.for_url(&url("https://10.1.2.3/")).is_none());
        // No HTTP_PROXY: plain HTTP goes direct.
        assert!(config.for_url(&url("http://example.com/")).is_none());
    }

    #[test]
    fn no_proxy_cidr_and_wildcards() {
        let config =
            ProxyConfig::from_values(Some("http://p:3128"), None, Some("10.0.0.0/8,::1,*.svc.cluster.local")).unwrap();
        let url = |u: &str| Url::parse(u).unwrap();
        assert!(config.for_url(&url("https://10.20.30.40/")).is_none());
        assert!(config.for_url(&url("https://11.0.0.1/")).is_some());
        assert!(config.for_url(&url("https://[::1]:8443/")).is_none());
        assert!(config.for_url(&url("https://api.svc.cluster.local/")).is_none());
        assert!(in_cidr("0.0.0.1".parse().unwrap(), "0.0.0.0/0"));
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in vectors {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }
}
