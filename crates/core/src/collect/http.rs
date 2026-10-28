//! HTTP over the socket we opened ourselves. hyper only parses the protocol.

use std::io::Read;
use std::time::Instant;

use http::header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, HOST, USER_AGENT};
use http::{Request, Response};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use url::Url;

use crate::snapshot::{HttpVersion, RequestProfile};

pub const ACCEPT_VALUE: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
/// zstd is not offered: the report says which encodings we asked for.
pub const ACCEPT_ENCODING_VALUE: &str = "gzip, deflate, br";

pub enum Sender {
    Http1(http1::SendRequest<Empty<Bytes>>),
    Http2(http2::SendRequest<Empty<Bytes>>),
}

impl Sender {
    pub async fn handshake<IO>(io: IO, version: HttpVersion) -> Result<Self, hyper::Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(io);
        Ok(match version {
            HttpVersion::Http1 => {
                let (sender, conn) = http1::handshake(io).await?;
                tokio::spawn(conn);
                Sender::Http1(sender)
            }
            HttpVersion::Http2 => {
                let (sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
                tokio::spawn(conn);
                Sender::Http2(sender)
            }
        })
    }

    pub fn is_closed(&self) -> bool {
        match self {
            Sender::Http1(sender) => sender.is_closed(),
            Sender::Http2(sender) => sender.is_closed(),
        }
    }

    pub fn version(&self) -> HttpVersion {
        match self {
            Sender::Http1(_) => HttpVersion::Http1,
            Sender::Http2(_) => HttpVersion::Http2,
        }
    }

    /// Sends a GET and returns when the response headers arrive, with the instant
    /// the request was handed to hyper.
    pub async fn get(
        &mut self,
        url: &Url,
        profile: &RequestProfile,
    ) -> Result<(Instant, Response<Incoming>), hyper::Error> {
        match self {
            Sender::Http1(sender) => {
                sender.ready().await?;
                let request = build(url, profile, false);
                let sent = Instant::now();
                Ok((sent, sender.send_request(request).await?))
            }
            Sender::Http2(sender) => {
                sender.ready().await?;
                let request = build(url, profile, true);
                let sent = Instant::now();
                Ok((sent, sender.send_request(request).await?))
            }
        }
    }
}

fn build(url: &Url, profile: &RequestProfile, absolute: bool) -> Request<Empty<Bytes>> {
    // HTTP/2 carries the authority in the URI; HTTP/1.1 needs the path and a Host header.
    let mut builder = if absolute {
        Request::get(url.as_str())
    } else {
        let path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        let authority = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        Request::get(path).header(HOST, authority)
    };
    builder = builder
        .header(USER_AGENT, &profile.user_agent)
        .header(ACCEPT, ACCEPT_VALUE)
        .header(ACCEPT_ENCODING, &profile.accept_encoding)
        .header(ACCEPT_LANGUAGE, &profile.accept_language);
    builder
        .body(Empty::new())
        .expect("request built from a parsed URL is valid")
}

pub struct RawBody {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    /// The deadline expired mid-body; what arrived until then is kept.
    pub deadline_hit: bool,
    pub error: Option<String>,
}

/// Reads the body until the end, `limit` bytes on the wire or `deadline`.
pub async fn read_body(mut body: Incoming, limit: usize, deadline: tokio::time::Instant) -> RawBody {
    let mut raw = RawBody {
        bytes: Vec::new(),
        truncated: false,
        deadline_hit: false,
        error: None,
    };
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => {
                raw.deadline_hit = true;
                raw.truncated = true;
                return raw;
            }
            Ok(None) => return raw,
            Ok(Some(Err(e))) => {
                raw.error = Some(e.to_string());
                raw.truncated = true;
                return raw;
            }
            Ok(Some(Ok(frame))) => frame,
        };
        if let Ok(data) = frame.into_data() {
            let room = limit - raw.bytes.len();
            if data.len() > room {
                raw.bytes.extend_from_slice(&data[..room]);
                raw.truncated = true;
                return raw;
            }
            raw.bytes.extend_from_slice(&data);
        }
    }
}

pub struct Decoded {
    pub body: Vec<u8>,
    pub truncated: bool,
    pub error: Option<String>,
}

/// Undoes `Content-Encoding`, stopping at `limit` decoded bytes so a compression
/// bomb cannot exhaust memory.
pub fn decode(raw: &[u8], encoding: Option<&str>, limit: usize) -> Decoded {
    let encoding = encoding.map(|e| e.trim().to_ascii_lowercase());
    let reader: Box<dyn Read + '_> = match encoding.as_deref() {
        None | Some("") | Some("identity") => return capped(raw.to_vec(), limit),
        Some("gzip") | Some("x-gzip") => Box::new(flate2::read::MultiGzDecoder::new(raw)),
        // "deflate" is meant to be zlib-wrapped, but some servers send raw deflate.
        Some("deflate") if has_zlib_header(raw) => Box::new(flate2::read::ZlibDecoder::new(raw)),
        Some("deflate") => Box::new(flate2::read::DeflateDecoder::new(raw)),
        Some("br") => Box::new(brotli_decompressor::Decompressor::new(raw, 4096)),
        Some(other) => {
            return Decoded {
                body: raw[..raw.len().min(limit)].to_vec(),
                truncated: raw.len() > limit,
                error: Some(format!("unsupported content-encoding `{other}`; body kept as received")),
            };
        }
    };
    let mut body = Vec::new();
    match reader.take(limit as u64 + 1).read_to_end(&mut body) {
        Ok(_) => capped(body, limit),
        Err(e) => {
            let mut decoded = capped(body, limit);
            decoded.error = Some(format!("could not decode {} body: {e}", encoding.unwrap_or_default()));
            decoded
        }
    }
}

fn has_zlib_header(raw: &[u8]) -> bool {
    match raw {
        [cmf, flg, ..] => cmf & 0x0f == 8 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0,
        _ => false,
    }
}

fn capped(mut body: Vec<u8>, limit: usize) -> Decoded {
    let truncated = body.len() > limit;
    body.truncate(limit);
    Decoded {
        body,
        truncated,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn decodes_gzip_and_both_deflate_flavours() {
        let text = b"<html>ola</html>".repeat(50);
        assert_eq!(decode(&gzip(&text), Some("gzip"), 1 << 20).body, text);

        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&text).unwrap();
        assert_eq!(decode(&z.finish().unwrap(), Some("deflate"), 1 << 20).body, text);

        let mut d = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(&text).unwrap();
        assert_eq!(decode(&d.finish().unwrap(), Some("deflate"), 1 << 20).body, text);
    }

    #[test]
    fn compression_bomb_stops_at_the_limit() {
        let bomb = gzip(&vec![0u8; 20 << 20]);
        assert!(bomb.len() < 100 << 10);
        let decoded = decode(&bomb, Some("gzip"), 5 << 20);
        assert_eq!(decoded.body.len(), 5 << 20);
        assert!(decoded.truncated);
    }

    #[test]
    fn unknown_encoding_is_reported_not_guessed() {
        let decoded = decode(b"abc", Some("zstd"), 10);
        assert_eq!(decoded.body, b"abc");
        assert!(decoded.error.unwrap().contains("zstd"));
    }
}
