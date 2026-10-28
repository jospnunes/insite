//! TLS handshake with a verifier that records instead of rejecting.
//!
//! The recording verifier runs the standard webpki validation, keeps the result
//! and lets the handshake continue, so an invalid certificate becomes a finding in
//! the report instead of aborting the analysis. This is safe here because insite
//! only reads public pages: it never sends credentials or anything else that
//! trusting the server would protect.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{AlertDescription, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Host;

use crate::snapshot::{CertProblem, FailureKind, TlsInfo, Verification};

#[derive(Clone)]
pub struct Tls {
    provider: Arc<CryptoProvider>,
    webpki: Arc<WebPkiServerVerifier>,
}

pub struct TlsError {
    pub kind: FailureKind,
    pub message: String,
    /// The connection broke during the handshake; a refusal by the server is final.
    pub retryable: bool,
}

impl Tls {
    /// Trusts the embedded Mozilla roots, or the operating system's store when
    /// `native` (needed behind corporate TLS inspection), plus `extra_roots` (DER),
    /// which tests use.
    pub fn new(extra_roots: &[Vec<u8>], native: bool) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        if native {
            let found = rustls_native_certs::load_native_certs();
            if found.certs.is_empty() {
                let errors: Vec<String> = found.errors.iter().map(ToString::to_string).collect();
                return Err(format!(
                    "no certificates in the system trust store: {}",
                    errors.join("; ")
                ));
            }
            roots.add_parsable_certificates(found.certs);
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for der in extra_roots {
            roots
                .add(CertificateDer::from(der.clone()))
                .map_err(|e| format!("invalid extra root certificate: {e}"))?;
        }
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| format!("cannot build the certificate verifier: {e}"))?;
        Ok(Tls { provider, webpki })
    }

    pub async fn handshake(
        &self,
        tcp: TcpStream,
        host: &Host<String>,
    ) -> Result<(TlsStream<TcpStream>, TlsInfo), TlsError> {
        let recorder = Arc::new(RecordingVerifier {
            inner: self.webpki.clone(),
            recorded: Mutex::new(None),
        });
        let mut config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| fatal(FailureKind::Tls, e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(recorder.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let (server_name, sni) = match host {
            Host::Domain(domain) => {
                let name = ServerName::try_from(domain.clone()).map_err(|e| fatal(FailureKind::Tls, e.to_string()))?;
                (name, Some(domain.clone()))
            }
            // No SNI for IP literals; the certificate is checked against its IP SANs.
            Host::Ipv4(ip) => (ServerName::IpAddress((*ip).into()), None),
            Host::Ipv6(ip) => (ServerName::IpAddress((*ip).into()), None),
        };

        let start = Instant::now();
        let stream = TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await
            .map_err(classify)?;
        let handshake = start.elapsed();

        let info = describe(&stream, handshake, sni, recorder.take());
        Ok((stream, info))
    }
}

fn describe(
    stream: &TlsStream<TcpStream>,
    handshake: Duration,
    sni: Option<String>,
    recorded: Option<Recorded>,
) -> TlsInfo {
    let conn = stream.get_ref().1;
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".to_owned(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".to_owned(),
        Some(other) => format!("{other:?}"),
        None => "unknown".to_owned(),
    };
    let recorded = recorded.unwrap_or(Recorded {
        verification: Verification::Invalid {
            problem: CertProblem::Other,
            message: "the server sent no certificate".into(),
        },
        certificates: Vec::new(),
        ocsp_stapled: false,
    });
    TlsInfo {
        handshake,
        sni,
        version,
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_default(),
        key_exchange: conn.negotiated_key_exchange_group().map(|g| format!("{:?}", g.name())),
        alpn: conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
        verification: recorded.verification,
        certificates: recorded.certificates,
        ocsp_stapled: recorded.ocsp_stapled,
    }
}

fn classify(e: std::io::Error) -> TlsError {
    let Some(tls) = e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) else {
        // Connection reset or closed mid-handshake.
        return TlsError {
            kind: FailureKind::Tls,
            message: format!("connection broke during the TLS handshake: {e}"),
            retryable: true,
        };
    };
    match tls {
        rustls::Error::AlertReceived(
            alert @ (AlertDescription::ProtocolVersion
            | AlertDescription::HandshakeFailure
            | AlertDescription::InsufficientSecurity),
        ) => fatal(
            FailureKind::TlsIncompatible,
            format!(
                "the server refused the handshake ({alert:?} alert); it probably only accepts TLS 1.0/1.1 or legacy cipher suites"
            ),
        ),
        rustls::Error::PeerIncompatible(reason) => fatal(
            FailureKind::TlsIncompatible,
            format!("the server only offers parameters we do not support: {reason:?}"),
        ),
        other => fatal(FailureKind::Tls, format!("TLS handshake failed: {other}")),
    }
}

fn fatal(kind: FailureKind, message: String) -> TlsError {
    TlsError {
        kind,
        message,
        retryable: false,
    }
}

fn problem(e: &rustls::Error) -> CertProblem {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => CertProblem::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => CertProblem::NotYetValid,
            C::UnknownIssuer => CertProblem::UnknownIssuer,
            C::NotValidForName | C::NotValidForNameContext { .. } => CertProblem::NameMismatch,
            C::Revoked => CertProblem::Revoked,
            C::BadSignature => CertProblem::BadSignature,
            _ => CertProblem::Other,
        },
        _ => CertProblem::Other,
    }
}

struct Recorded {
    verification: Verification,
    certificates: Vec<Vec<u8>>,
    ocsp_stapled: bool,
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    recorded: Mutex<Option<Recorded>>,
}

impl RecordingVerifier {
    fn take(&self) -> Option<Recorded> {
        self.recorded.lock().ok()?.take()
    }
}

impl std::fmt::Debug for Recorded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorded")
            .field("verification", &self.verification)
            .finish()
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verification =
            match self
                .inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            {
                Ok(_) => Verification::Valid,
                Err(e) => Verification::Invalid {
                    problem: problem(&e),
                    message: e.to_string(),
                },
            };
        let certificates = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|c| c.as_ref().to_vec())
            .collect();
        if let Ok(mut slot) = self.recorded.lock() {
            *slot = Some(Recorded {
                verification,
                certificates,
                ocsp_stapled: !ocsp_response.is_empty(),
            });
        }
        Ok(ServerCertVerified::assertion())
    }

    // The handshake signatures prove the server holds the certificate's key. A
    // failure here is a broken server, not a certificate problem, so it stays fatal.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
