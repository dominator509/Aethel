#![forbid(unsafe_code)]

use quinn::{Endpoint, ServerConfig, ClientConfig};
use rustls::{Certificate, PrivateKey};
use std::sync::Arc;
use std::net::SocketAddr;
use sha2::{Sha256, Digest};

pub mod dht;

/// Custom certificate verifier that validates a node's identity based on its certificate hash.
/// In a real P2P network, you'd verify this against the expected PeerID (e.g., hash of public key).
struct PeerIdVerifier {
    expected_peer_id: Vec<u8>,
}

impl PeerIdVerifier {
    fn new(expected_peer_id: Vec<u8>) -> Arc<Self> {
        Arc::new(Self { expected_peer_id })
    }
}

impl rustls::client::ServerCertVerifier for PeerIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(&end_entity.0);
        let cert_hash = hasher.finalize().to_vec();

        // Prevent MITM by ensuring the presented certificate hash matches the expected Peer ID
        if cert_hash == self.expected_peer_id {
            Ok(rustls::client::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Peer ID mismatch! MITM attack suspected.".to_string()))
        }
    }
}

/// Generates a self-signed certificate and private key for QUIC communication.
pub fn generate_self_signed_cert() -> Result<(Certificate, PrivateKey), Box<dyn std::error::Error>> {
    let subject_alt_names = vec!["aethel.network".to_string(), "localhost".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;

    let key = PrivateKey(cert.serialize_private_key_der());
    let cert = Certificate(cert.serialize_der()?);

    Ok((cert, key))
}

/// Helper function to derive a PeerID (SHA256 hash) from a certificate.
pub fn derive_peer_id(cert: &Certificate) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&cert.0);
    hasher.finalize().to_vec()
}

/// Aethel Network Node representing a QUIC endpoint
pub struct Node {
    pub endpoint: Endpoint,
    pub cert: Certificate,
}

impl Node {
    /// Initialize a new P2P Node on the given address
    pub fn new(bind_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let (cert, key) = generate_self_signed_cert()?;
        let cert_clone = cert.clone();

        let server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_uni_streams(1024_u32.into());

        let endpoint = Endpoint::server(server_config, bind_addr)?;
        Ok(Self { endpoint, cert: cert_clone })
    }

    /// Create a client configuration that rigorously validates the target Peer ID
    pub fn make_client_config(expected_peer_id: Vec<u8>) -> ClientConfig {
        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(PeerIdVerifier::new(expected_peer_id))
            .with_no_client_auth();

        ClientConfig::new(Arc::new(crypto))
    }

    /// Broadcasts a serialized transaction to a list of peer addresses.
    pub async fn broadcast_transaction(&self, tx_bytes: &[u8], peers: &[(SocketAddr, Vec<u8>)]) {
        for (addr, expected_peer_id) in peers {
            let client_config = Self::make_client_config(expected_peer_id.clone());
            // quinn 0.10 endpoint.connect_with
            if let Ok(conn) = self.endpoint.connect_with(client_config, *addr, "aethel.network") {
                if let Ok(connection) = conn.await {
                    if let Ok(mut stream) = connection.open_uni().await {
                        // We ignore write errors for broadcast "fire and forget"
                        let _ = stream.write_all(tx_bytes).await;
                    }
                }
            }
        }
    }

    /// Listens for incoming transaction streams on the endpoint.
    /// Returns a channel receiver that yields serialized transactions.
    pub async fn listen_for_transactions(&self) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);

        let endpoint_clone = self.endpoint.clone();

        tokio::spawn(async move {
            while let Some(incoming) = endpoint_clone.accept().await {
                if let Ok(connection) = incoming.await {
                    let tx_clone = tx.clone();
                    tokio::spawn(async move {
                        while let Ok(mut stream) = connection.accept_uni().await {
                            // limit to 1MB per transaction to prevent DoS
                            if let Ok(buf) = stream.read_to_end(1024 * 1024).await {
                                let _ = tx_clone.send(buf).await;
                            }
                        }
                    });
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
        // Just verify it doesn't panic when building the config
    }
}
