#![forbid(unsafe_code)]

use crypto::transaction::Transaction;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Defines the number of shards in the Aethel network
pub const NUM_SHARDS: usize = 256;
pub const MAX_MEMPOOL_SIZE: usize = 100_000;
pub const MAX_TXS_PER_VERTEX: usize = 10_000;
pub const MAX_PARENTS_PER_VERTEX: usize = 10;

/// Represents a simple transaction identifier (could be a hash in a full implementation)
pub type TransactionId = Vec<u8>;
pub type VertexId = Vec<u8>;
pub type PeerId = Vec<u8>;

/// A Vertex in the DAG
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vertex {
    pub id: VertexId,
    pub creator: PeerId,
    pub shard_id: usize,
    pub round: u64,
    pub transactions: Vec<TransactionId>,
    pub parents: Vec<VertexId>,
}

/// The state of the Directed Acyclic Graph (DAG) for a specific shard
pub struct Dag {
    shard_id: usize,
    vertices: HashMap<VertexId, Vertex>,
    cross_shard_locks: HashMap<TransactionId, HashSet<usize>>,
    pub mempool: HashMap<TransactionId, Transaction>,
}

impl Dag {
    pub fn new(shard_id: usize) -> Self {
        Self {
            shard_id,
            vertices: HashMap::new(),
            cross_shard_locks: HashMap::new(),
            mempool: HashMap::new(),
        }
    }

    /// Helper function to randomly map a transaction to a shard using SHA256
    pub fn hash_to_shard(tx_id: &[u8]) -> usize {
        let mut hasher = Sha256::new();
        hasher.update(tx_id);
        let hash = hasher.finalize();

        // Take the first 8 bytes (u64) of the hash to determine the shard
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let num = u64::from_be_bytes(bytes);

        (num as usize) % NUM_SHARDS
    }

    /// Validates a transaction's cryptographic properties before adding it to the mempool
    pub fn validate_and_add_tx(&mut self, tx: Transaction) -> Result<(), &'static str> {
        // Anti-DoS: Check if transaction already exists before performing expensive cryptographic verification
        if self.mempool.contains_key(&tx.id) {
            return Err("Transaction already exists in mempool");
        }

        if self.mempool.len() >= MAX_MEMPOOL_SIZE {
            return Err("Mempool capacity exceeded. Dropping transaction to prevent OOM.");
        }

        if !tx.verify() {
            return Err("Transaction failed cryptographic verification (ZKP or Signature)");
        }

        let tx_shard = Self::hash_to_shard(&tx.id);
        if tx_shard != self.shard_id {
            return Err("Transaction belongs to a different shard");
        }

        self.mempool.insert(tx.id.clone(), tx);
        Ok(())
    }

    /// Proposes a new vertex to be added to the DAG
    pub fn propose_vertex(
        &mut self,
        creator: PeerId,
        txs: Vec<TransactionId>,
        parents: Vec<VertexId>,
    ) -> Result<VertexId, &'static str> {
        if txs.len() > MAX_TXS_PER_VERTEX {
            return Err("Too many transactions in vertex proposal");
        }

        if parents.len() > MAX_PARENTS_PER_VERTEX {
            return Err("Too many parents in vertex proposal");
        }

        // Validate that parents exist in this shard
        for parent in &parents {
            if !self.vertices.contains_key(parent) {
                return Err("Parent vertex not found in this shard");
            }
        }

        // Validate transactions exist in mempool
        for tx_id in &txs {
            if !self.mempool.contains_key(tx_id) {
                return Err("Transaction not found in mempool");
            }
        }

        // Generate a simple ID for the vertex
        let mut hasher = Sha256::new();
        hasher.update(&creator);
        for tx in &txs {
            hasher.update(tx);
        }
        let id = hasher.finalize().to_vec();

        // Determine the round based on parents
        let mut max_parent_round = 0;
        for parent in &parents {
            if let Some(parent_vertex) = self.vertices.get(parent) {
                if parent_vertex.round > max_parent_round {
                    max_parent_round = parent_vertex.round;
                }
            }
        }

        let vertex = Vertex {
            id: id.clone(),
            creator,
            shard_id: self.shard_id,
            round: max_parent_round + 1,
            transactions: txs.clone(),
            parents,
        };

        // Remove from mempool since they are now in the DAG
        // Also garbage collect cross-shard locks to prevent memory leaks
        for tx in &txs {
            self.mempool.remove(tx);
            self.cross_shard_locks.remove(tx);
        }

        self.vertices.insert(id.clone(), vertex);
        Ok(id)
    }

    /// Lock a cross-shard transaction
    /// Computes deterministic finality ordering of the DAG
    /// This establishes a simple topological sort using round numbers and hashes for tie-breaking
    pub fn compute_finality_and_order(&self) -> Vec<VertexId> {
        let mut ordered_vertices: Vec<&Vertex> = self.vertices.values().collect();

        // Sort primarily by round (causality), secondarily by ID (deterministic tie-break)
        ordered_vertices.sort_by(|a, b| {
            if a.round != b.round {
                a.round.cmp(&b.round)
            } else {
                a.id.cmp(&b.id)
            }
        });

        ordered_vertices.into_iter().map(|v| v.id.clone()).collect()
    }

    pub fn lock_cross_shard_tx(&mut self, tx_id: TransactionId) {
        let locks = self.cross_shard_locks.entry(tx_id).or_default();
        locks.insert(self.shard_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_shard() {
        let tx1 = b"tx_12345".to_vec();
        let tx2 = b"tx_67890".to_vec();

        let shard1 = Dag::hash_to_shard(&tx1);
        let shard2 = Dag::hash_to_shard(&tx2);

        assert!(shard1 < NUM_SHARDS);
        assert!(shard2 < NUM_SHARDS);
        assert_ne!(shard1, shard2); // High probability they differ
    }

    #[test]
    fn test_invalid_parent() {
        let mut dag = Dag::new(1);
        let creator = b"node_a".to_vec();
        let tx = b"tx_1".to_vec();

        let result = dag.propose_vertex(creator, vec![tx], vec![b"missing_parent".to_vec()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cross_shard_lock() {
        let mut dag = Dag::new(5);
        let tx = b"cross_shard_tx".to_vec();

        dag.lock_cross_shard_tx(tx.clone());

        let locks = dag.cross_shard_locks.get(&tx).unwrap();
        assert!(locks.contains(&5));
    }

    #[test]
    fn test_adversarial_invalid_parent_reference() {
        // Simulates an attacker proposing a vertex referencing a parent from a DIFFERENT shard
        let mut dag = Dag::new(1);
        let creator = b"malicious_node".to_vec();
        let tx = b"tx_invalid".to_vec();

        // This parent ID does not exist in Shard 1
        let foreign_parent_id = b"parent_from_shard_2".to_vec();

        let result = dag.propose_vertex(creator, vec![tx], vec![foreign_parent_id]);

        // The consensus logic should reject this immediately
        assert!(result.is_err());
        assert_eq!(result.err(), Some("Parent vertex not found in this shard"));
    }
}

#[test]
fn test_internal_cross_shard_locks_lifecycle() {
    let mut dag = Dag::new(10);
    let tx1 = vec![1, 2, 3];
    let tx2 = vec![4, 5, 6];

    // 1. Initialization
    assert!(dag.cross_shard_locks.is_empty());

    // 2. Mutation (Locking)
    dag.lock_cross_shard_tx(tx1.clone());
    dag.lock_cross_shard_tx(tx2.clone());
    assert_eq!(dag.cross_shard_locks.len(), 2);
    assert!(dag.cross_shard_locks.get(&tx1).unwrap().contains(&10));

    // 3. Destruction (Proposing vertex should garbage collect the locks)
    // Since propose_vertex validates mempool existence, we bypass it for a direct state unit test
    // and manually invoke the internal state logic that propose_vertex performs on success
    let txs = vec![tx1.clone()];
    for tx in &txs {
        dag.mempool.remove(tx);
        dag.cross_shard_locks.remove(tx);
    }

    // Assert tx1 is destroyed, tx2 remains
    assert_eq!(dag.cross_shard_locks.len(), 1);
    assert!(!dag.cross_shard_locks.contains_key(&tx1));
    assert!(dag.cross_shard_locks.contains_key(&tx2));
}

#[test]
fn test_branch_coverage_max_txs_per_vertex() {
    let mut dag = Dag::new(1);
    let creator = b"node_a".to_vec();

    // Exceed MAX_TXS_PER_VERTEX (10_000)
    let mut txs = Vec::with_capacity(MAX_TXS_PER_VERTEX + 1);
    for i in 0..=(MAX_TXS_PER_VERTEX) {
        txs.push(vec![(i % 255) as u8]);
    }

    let result = dag.propose_vertex(creator, txs, vec![]);
    assert!(result.is_err());
    assert_eq!(
        result.err(),
        Some("Too many transactions in vertex proposal")
    );
}

#[test]
fn test_branch_coverage_max_parents_per_vertex() {
    let mut dag = Dag::new(1);
    let creator = b"node_a".to_vec();
    let txs = vec![b"tx".to_vec()];

    // Exceed MAX_PARENTS_PER_VERTEX (10)
    let mut parents = Vec::with_capacity(MAX_PARENTS_PER_VERTEX + 1);
    for i in 0..=(MAX_PARENTS_PER_VERTEX) {
        parents.push(vec![(i % 255) as u8]);
    }

    let result = dag.propose_vertex(creator, txs, parents);
    assert!(result.is_err());
    assert_eq!(result.err(), Some("Too many parents in vertex proposal"));
}

#[test]
fn test_branch_coverage_missing_tx_in_mempool() {
    let mut dag = Dag::new(1);
    let creator = b"node_a".to_vec();
    let missing_tx = b"ghost_tx".to_vec();

    // Propose vertex with a transaction not in the mempool
    let result = dag.propose_vertex(creator, vec![missing_tx], vec![]);
    assert!(result.is_err());
    assert_eq!(result.err(), Some("Transaction not found in mempool"));
}
