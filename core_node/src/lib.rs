#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::Bytes;
use sha2::Digest;

use consensus::Dag;
use crypto::{generate_kyber_keypair, generate_dilithium_keypair};
use network::Node as NetworkNode;
use storage::StorageEngine;
use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;

pub mod recovery;

/// The Core Aethel Node integrating all Phase sub-components.
pub struct AethelNode {
    /// Post-Quantum identity and encryption keys
    pub kyber_keys: (kyber1024::PublicKey, kyber1024::SecretKey),
    pub dilithium_keys: (dilithium5::PublicKey, dilithium5::SecretKey),

    /// QUIC Transport layer
    pub network: Arc<NetworkNode>,

    /// LSM-Tree Storage Engine
    pub storage: Arc<StorageEngine>,

    /// The Sharded DAG Consensus states (one for each shard)
    pub dags: Arc<RwLock<Vec<Dag>>>,
}

impl AethelNode {
    /// Bootstraps a new Aethel Node
    pub async fn bootstrap(bind_addr: SocketAddr, storage_path: PathBuf) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        // 1. Initialize Cryptographic Identity (PQC)
        let kyber_keys = generate_kyber_keypair();
        let dilithium_keys = generate_dilithium_keypair();

        // 2. Initialize Networking (QUIC)
        let network = Arc::new(NetworkNode::new(bind_addr)?);

        // 3. Initialize Storage (LSM-Tree)
        let storage = Arc::new(StorageEngine::new(storage_path).await?);

        // 4. Initialize Consensus (Sharded DAG)
        let mut shards = Vec::with_capacity(consensus::NUM_SHARDS);
        for i in 0..consensus::NUM_SHARDS {
            shards.push(Dag::new(i));
        }
        let dags = Arc::new(RwLock::new(shards));

        let node = Arc::new(Self {
            kyber_keys,
            dilithium_keys,
            network,
            storage,
            dags,
        });

        // 5. Start background transaction listener loop
        node.start_transaction_listener().await;

        Ok(node)
    }

    /// Spawns a background task to process incoming network transactions
    async fn start_transaction_listener(self: &Arc<Self>) {
        let network = self.network.clone();
        let dags = self.dags.clone();
        let storage = self.storage.clone();

        tokio::spawn(async move {
            let mut rx = network.listen_for_transactions().await;

            while let Some(tx_bytes) = rx.recv().await {
                // In a real implementation, we would deserialize `tx_bytes` into a `crypto::transaction::Transaction`.
                // For this milestone, we simulate the pipeline if the bytes were valid:

                // 1. Write the raw bytes to the LSM-Tree Storage Engine for persistence
                // We use a dummy key (e.g. SHA256 of the bytes)
                let tx_key = Bytes::from(sha2::Sha256::digest(&tx_bytes).to_vec());
                let tx_val = Bytes::from(tx_bytes);

                let _ = storage.put(tx_key.clone(), tx_val).await;

                // 2. In a real system, we'd pass the deserialized `Transaction` to:
                // let shard_id = Dag::hash_to_shard(&tx.id);
                // let mut all_dags = dags.write().await;
                // let _ = all_dags[shard_id].validate_and_add_tx(tx);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_node_bootstrap() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
        let temp_file = NamedTempFile::new().unwrap();

        let node_result = AethelNode::bootstrap(addr, temp_file.path().to_path_buf()).await;

        assert!(node_result.is_ok(), "Failed to bootstrap Aethel Node");

        let node = node_result.unwrap();

        // Verify DAG initialization
        let dags = node.dags.read().await;
        assert_eq!(dags.len(), consensus::NUM_SHARDS);
    }
}
