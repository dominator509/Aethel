use quinn::{
    ClientConfig, Connection, Endpoint, ServerConfig,
};
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use sha2::{Sha256, Digest};
use tokio::sync::RwLock;

mod dht;
pub use dht::RoutingTable;

use std::collections::HashMap;
use std::sync::Mutex;

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::server::WebPkiClientVerifier;

// Re-exports
pub use quinn::RecvStream;

// Mock implementation of a simple verifier that only accepts the peer id hash
#[derive(Debug)]
pub struct PeerIdVerifier {
    expected_peer_id: Vec<u8>,
}

impl PeerIdVerifier {
    pub fn new(expected_peer_id: Vec<u8>) -> Arc<Self> {
        Arc::new(Self { expected_peer_id })
    }
}

impl rustls::client::danger::ServerCertVerifier for PeerIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual_peer_id = derive_peer_id(end_entity);
        if actual_peer_id == self.expected_peer_id {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Peer ID mismatch".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not supported".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}


pub fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));
    let cert_der = CertificateDer::from(cert.serialize_der()?);
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
    pub dht: Arc<RwLock<RoutingTable>>,
    pub client_configs: Arc<Mutex<HashMap<Vec<u8>, ClientConfig>>>,
}

impl Node {
    pub fn new(bind_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let (cert, key) = generate_self_signed_cert()?;
        let cert_clone = cert.clone();

        let server_crypto =
            rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)?;

        let quic_server_crypto = QuicServerConfig::try_from(server_crypto)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_crypto));

        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_uni_streams(1024_u32.into());

        let endpoint = Endpoint::server(server_config, bind_addr)?;

        let local_peer_id = derive_peer_id(&cert_clone);
        let dht = Arc::new(RwLock::new(RoutingTable::new(local_peer_id)));

        Ok(Self {
            endpoint,
            cert: cert_clone,
            dht,
            client_configs: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn make_client_config(expected_peer_id: Vec<u8>) -> ClientConfig {
        let crypto = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PeerIdVerifier::new(expected_peer_id))
            .with_no_client_auth();

        let quic_client_crypto = QuicClientConfig::try_from(crypto).unwrap();
        ClientConfig::new(Arc::new(quic_client_crypto))
    }

    pub async fn broadcast_transaction(&self, tx_bytes: &[u8], peers: &[(SocketAddr, Vec<u8>)]) {
        // Pre-fetch or generate ClientConfigs
        let mut configs_to_use = Vec::with_capacity(peers.len());
        for (addr, expected_peer_id) in peers {
            let config = {
                let cache = self.client_configs.lock().unwrap();
                cache.get(expected_peer_id).cloned()
            };

            let client_config = match config {
                Some(c) => c,
                None => {
                    let new_config = Self::make_client_config(expected_peer_id.clone());
                    self.client_configs
                        .lock()
                        .unwrap()
                        .insert(expected_peer_id.clone(), new_config.clone());
                    new_config
                }
            };
            configs_to_use.push((*addr, client_config));
        }

        for (addr_clone, client_config) in configs_to_use {
            let endpoint = self.endpoint.clone();
            let tx_clone = tx_bytes.to_vec();

            tokio::spawn(async move {
                if let Ok(conn) = endpoint.connect_with(client_config, addr_clone, "localhost") {
                    if let Ok(connection) = conn.await {
                        if let Ok(mut send) = connection.open_uni().await {
                            let _ = send.write_all(&tx_clone).await;
                            let _ = send.finish();
                        }
                    }
                }
            });
        }
    }
}
