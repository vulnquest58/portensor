//! TLS support for the distributed coordinator and push agents.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::serve::Listener;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::error::AppError;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 64;

#[derive(Clone, Default)]
pub struct ClientTls {
    config: Option<Arc<ClientConfig>>,
}

impl ClientTls {
    pub fn load(ca_cert: Option<&Path>, insecure: bool) -> Result<Self, AppError> {
        if insecure {
            let config = client_builder()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth();
            return Ok(Self {
                config: Some(Arc::new(config)),
            });
        }
        let Some(path) = ca_cert else {
            return Ok(Self::default());
        };
        let certs = load_certs(path)?;
        if certs.is_empty() {
            return Err(AppError::usage(format!(
                "{} contains no PEM certificates",
                path.display()
            )));
        }
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|error| {
                AppError::usage(format!(
                    "cannot trust certificate in {}: {error}",
                    path.display()
                ))
            })?;
        }
        let config = client_builder()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            config: Some(Arc::new(config)),
        })
    }

    pub(crate) fn agent(&self, timeout: Duration) -> ureq::Agent {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(timeout);
        if let Some(config) = &self.config {
            builder = builder.tls_config(config.clone());
        }
        builder.build()
    }
}

pub fn server_config(
    cert: Option<&Path>,
    key: Option<&Path>,
) -> Result<Option<Arc<ServerConfig>>, AppError> {
    match (cert, key) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(AppError::usage(
            "--tls-cert and --tls-key must be provided together",
        )),
        (Some(cert), Some(key)) => {
            let certs = load_certs(cert)?;
            if certs.is_empty() {
                return Err(AppError::usage(format!(
                    "{} contains no PEM certificates",
                    cert.display()
                )));
            }
            let key = load_private_key(key)?;
            let config = ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| AppError::runtime(format!("cannot configure TLS: {error}")))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|error| {
                AppError::usage(format!("invalid TLS certificate or private key: {error}"))
            })?;
            Ok(Some(Arc::new(config)))
        }
    }
}

fn client_builder() -> Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>, AppError>
{
    ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| AppError::runtime(format!("cannot configure TLS: {error}")))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, AppError> {
    CertificateDer::pem_file_iter(path)
        .map_err(|error| {
            AppError::usage(format!(
                "cannot read TLS certificate {}: {error}",
                path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::usage(format!(
                "cannot parse TLS certificate {}: {error}",
                path.display()
            ))
        })
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, AppError> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| {
        AppError::usage(format!(
            "{} contains no readable RSA, PKCS#8, or SEC1 private key: {error}",
            path.display()
        ))
    })
}

pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
    accepted_tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
    accepted_rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    slots: Arc<Semaphore>,
}

impl TlsListener {
    pub async fn bind(listen: &str, config: Arc<ServerConfig>) -> Result<Self, AppError> {
        let inner = TcpListener::bind(listen)
            .await
            .map_err(|error| AppError::runtime(format!("cannot listen on {listen}: {error}")))?;
        let (accepted_tx, accepted_rx) = mpsc::channel(MAX_PENDING_HANDSHAKES);
        Ok(Self {
            inner,
            acceptor: TlsAcceptor::from(config),
            accepted_tx,
            accepted_rx,
            slots: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
        })
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                accepted = self.inner.accept() => {
                    match accepted {
                        Ok((stream, addr)) => {
                            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                                eprintln!("[tls] too many pending handshakes; dropping {addr}");
                                continue;
                            };
                            let acceptor = self.acceptor.clone();
                            let tx = self.accepted_tx.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                                    Ok(Ok(stream)) => {
                                        let _ = tx.send((stream, addr)).await;
                                    }
                                    Ok(Err(error)) => {
                                        eprintln!("[tls] handshake from {addr} failed: {error}");
                                    }
                                    Err(_) => {
                                        eprintln!("[tls] handshake from {addr} timed out");
                                    }
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("[tls] accept failed: {error}");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
                Some(stream) = self.accepted_rx.recv() => return stream,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::routing::post;
    use serde_json::{Value, json};

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(name)
    }

    async fn echo(Json(value): Json<Value>) -> Json<Value> {
        Json(value)
    }

    #[test]
    fn server_tls_requires_both_files() {
        assert!(server_config(None, None).unwrap().is_none());
        assert!(server_config(Some(&fixture("server.pem")), None).is_err());
        assert!(server_config(None, Some(&fixture("server.key"))).is_err());
        assert!(
            server_config(Some(&fixture("server.pem")), Some(&fixture("server.key")))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn client_tls_loads_a_private_ca() {
        assert!(ClientTls::load(None, false).unwrap().config.is_none());
        assert!(
            ClientTls::load(Some(&fixture("ca.pem")), false)
                .unwrap()
                .config
                .is_some()
        );
        assert!(ClientTls::load(None, true).unwrap().config.is_some());
        assert!(ClientTls::load(Some(&fixture("server.key")), false).is_err());
    }

    #[tokio::test]
    async fn tls_listener_serves_https_with_verified_certificate() {
        let config = server_config(Some(&fixture("server.pem")), Some(&fixture("server.key")))
            .unwrap()
            .unwrap();
        let listener = TlsListener::bind("127.0.0.1:0", config).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/v1/echo", post(echo));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let tls = ClientTls::load(Some(&fixture("ca.pem")), false).unwrap();
        let body = json!({ "probe": "ok" });
        let base = format!("https://localhost:{}", addr.port());
        let response = tokio::task::spawn_blocking(move || {
            crate::distributed::post_json(
                &base,
                "test-token-0123456789",
                "/v1/echo",
                &body,
                Duration::from_secs(10),
                &tls,
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response["probe"], "ok");
        server.abort();
    }

    #[tokio::test]
    async fn tls_client_enforces_default_verification_and_allows_insecure_opt_in() {
        let config = server_config(Some(&fixture("server.pem")), Some(&fixture("server.key")))
            .unwrap()
            .unwrap();
        let listener = TlsListener::bind("127.0.0.1:0", config).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/v1/echo", post(echo));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("https://localhost:{}", addr.port());

        let verified_base = base.clone();
        let rejected = tokio::task::spawn_blocking(move || {
            crate::distributed::post_json(
                &verified_base,
                "test-token-0123456789",
                "/v1/echo",
                &json!({ "probe": "untrusted" }),
                Duration::from_secs(10),
                &ClientTls::default(),
            )
        })
        .await
        .unwrap();
        assert!(rejected.is_err());

        let tls = ClientTls::load(None, true).unwrap();
        let accepted = tokio::task::spawn_blocking(move || {
            crate::distributed::post_json(
                &base,
                "test-token-0123456789",
                "/v1/echo",
                &json!({ "probe": "insecure" }),
                Duration::from_secs(10),
                &tls,
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(accepted["probe"], "insecure");
        server.abort();
    }
}
