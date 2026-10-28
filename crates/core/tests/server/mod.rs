//! Local HTTP(S) and DNS servers for the integration tests. Each test crate uses
//! only part of this module.
#![allow(dead_code)]

pub mod dns;
pub mod proxy;

use std::convert::Infallible;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::{Request, Response};
use http_body_util::Full;
use hyper::body::{Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub enum TlsMode {
    Plain,
    /// TLS with these ALPN protocols, under a certificate for `localhost` issued by a
    /// test CA (`Server::ca_der`).
    Tls(&'static [&'static [u8]]),
}

pub type Body = http_body_util::Either<Full<Bytes>, drip::Drip>;

type Handler = Arc<dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> + Send + Sync>;

pub struct Server {
    pub addr: SocketAddr,
    pub ca_der: Option<Vec<u8>>,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

impl Server {
    /// Starts serving on 127.0.0.1. The first `drop_first` TCP connections are
    /// closed right after accept, to exercise retries.
    pub async fn start<F, Fut, B>(tls: TlsMode, drop_first: usize, handler: F) -> Server
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response<B>> + Send + 'static,
        B: IntoBody,
    {
        let handler: Handler = Arc::new(move |req| {
            let fut = handler(req);
            Box::pin(async move { fut.await.map(IntoBody::into_body) })
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (acceptor, ca_der) = match tls {
            TlsMode::Plain => (None, None),
            TlsMode::Tls(alpn) => {
                let (acceptor, ca) = tls_acceptor(alpn);
                (Some(acceptor), Some(ca))
            }
        };
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (conns, reqs) = (connections.clone(), requests.clone());

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let n = conns.fetch_add(1, Ordering::SeqCst);
                if n < drop_first {
                    drop(tcp);
                    continue;
                }
                let (handler, reqs, acceptor) = (handler.clone(), reqs.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        reqs.fetch_add(1, Ordering::SeqCst);
                        let fut = handler(req);
                        async move { Ok::<_, Infallible>(fut.await) }
                    });
                    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                let _ = builder.serve_connection(TokioIo::new(stream), service).await;
                            }
                        }
                        None => {
                            let _ = builder.serve_connection(TokioIo::new(tcp), service).await;
                        }
                    }
                });
            }
        });
        Server {
            addr,
            ca_der,
            connections,
            requests,
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

fn tls_acceptor(alpn: &[&[u8]]) -> (TlsAcceptor, Vec<u8>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "insite test CA");
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone(), ca.der().clone()], key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    (TlsAcceptor::from(Arc::new(config)), ca.der().to_vec())
}

/// A port with nothing listening on it.
pub async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

pub fn ok(body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::new(Full::new(body.into()))
}

pub fn redirect(status: u16, location: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("location", location)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// A body sent as `count` chunks with `delay` between them.
pub fn dripping(chunk: &'static [u8], count: usize, delay: Duration) -> Response<drip::Drip> {
    Response::new(drip::Drip::new(chunk, count, delay))
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

pub fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::CompressorWriter::new(&mut out, 4096, 5, 22)
        .write_all(data)
        .unwrap();
    out
}

pub trait IntoBody {
    fn into_body(self) -> Body;
}

impl IntoBody for Full<Bytes> {
    fn into_body(self) -> Body {
        http_body_util::Either::Left(self)
    }
}

impl IntoBody for drip::Drip {
    fn into_body(self) -> Body {
        http_body_util::Either::Right(self)
    }
}

/// A body that arrives slowly, one chunk at a time.
pub mod drip {
    use super::*;
    use std::task::{Context, Poll};

    pub struct Drip {
        chunk: &'static [u8],
        left: usize,
        delay: Duration,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl Drip {
        pub fn new(chunk: &'static [u8], count: usize, delay: Duration) -> Self {
            Drip {
                chunk,
                left: count,
                delay,
                sleep: None,
            }
        }
    }

    impl hyper::body::Body for Drip {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            if self.left == 0 {
                return Poll::Ready(None);
            }
            let delay = self.delay;
            let sleep = self.sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
            self.left -= 1;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(self.chunk)))))
        }
    }
}
