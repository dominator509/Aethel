#![forbid(unsafe_code)]

use quinn::{Endpoint, ServerConfig, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::crypto::aws_lc_rs::default_provider;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};
use sha2::{Sha256, Digest};
use quinn::crypto::rustls::{QuicServerConfig, QuicClientConfig};

pub mod dht;

#[derive(Debug)]
struct PeerIdVerifier {
    expected_peer_id: Vec<u8>,
}

impl PeerIdVerifier {
    fn new(expected_peer_id: Vec<u8>) -> Arc<Self> {
        Arc::new(Self { expected_peer_id })
    }
}

impl ServerCertVerifier for PeerIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let cert_hash = hasher.finalize().to_vec();

        if cert_hash == self.expected_peer_id {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Peer ID mismatch! MITM attack suspected.".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let subject_alt_names = vec!["aethel.network".to_string(), "localhost".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;

    let key = PrivateKeyDer::try_from(cert.key_pair.serialize_der())?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());

    Ok((cert_der, key))
}

pub fn derive_peer_id(cert: &CertificateDer<'_>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    hasher.finalize().to_vec()
}

pub struct Node {
    pub endpoint: Endpoint,
    pub cert: CertificateDer<'static>,
}

impl Node {
    pub fn new(bind_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let (cert, key) = generate_self_signed_cert()?;
        let cert_clone = cert.clone();

        let server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        let quic_server_crypto = QuicServerConfig::try_from(server_crypto)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_crypto));

        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_uni_streams(1024_u32.into());

        let endpoint = Endpoint::server(server_config, bind_addr)?;
        Ok(Self { endpoint, cert: cert_clone })
    }

    pub fn make_client_config(expected_peer_id: Vec<u8>) -> ClientConfig {
        let crypto = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions().unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PeerIdVerifier::new(expected_peer_id))
            .with_no_client_auth();

        let quic_client_crypto = QuicClientConfig::try_from(crypto).unwrap();
        ClientConfig::new(Arc::new(quic_client_crypto))
    }

    pub async fn broadcast_transaction(&self, tx_bytes: &[u8], peers: &[(SocketAddr, Vec<u8>)]) {
        for (addr, expected_peer_id) in peers {
            let endpoint = self.endpoint.clone();
            let client_config = Self::make_client_config(expected_peer_id.clone());
            let addr_clone = *addr;
            let tx_bytes_clone = tx_bytes.to_vec();

            tokio::spawn(async move {
                // Anti-Blocking: Ensure a slow peer doesn't hang the broadcast task
                let _ = timeout(Duration::from_secs(3), async {
                    if let Ok(conn) = endpoint.connect_with(client_config, addr_clone, "aethel.network") {
                        if let Ok(connection) = conn.await {
                            if let Ok(mut stream) = connection.open_uni().await {
                                let _ = stream.write_all(&tx_bytes_clone).await;
                            }
                        }
                    }
                }).await;
            });
        }
    }

    pub async fn listen_for_transactions(&self) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let endpoint_clone = self.endpoint.clone();

        tokio::spawn(async move {
            // Anti-DoS: Hard limit on active incoming connections
            let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(10_000));

            while let Some(incoming) = endpoint_clone.accept().await {
                if let Ok(permit) = connection_semaphore.clone().acquire_owned().await {
                    if let Ok(connection) = incoming.await {
                        let tx_clone = tx.clone();
                        tokio::spawn(async move {
                            let _permit_holder = permit; // Hold permit until connection closes

                            while let Ok(mut stream) = connection.accept_uni().await {
                                // Anti-Slowloris: 5-second strict timeout on reading transaction payload
                                if let Ok(Ok(buf)) = timeout(Duration::from_secs(5), stream.read_to_end(1024 * 1024)).await {
                                    let _ = tx_clone.send(buf).await;
                                }
                            }
                        });
                    }
                }
            }
        });

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[tokio::test]
    async fn test_node_initialization() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
        let node = Node::new(addr).expect("Failed to initialize node");
        assert!(node.endpoint.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_client_config() {
        let dummy_peer_id = vec![0; 32];
        let _config = Node::make_client_config(dummy_peer_id);
    }
}
