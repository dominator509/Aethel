#![forbid(unsafe_code)]

use crate::zkp::ZkTransactionAmount;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::PublicKey;
use sha2::{Digest, Sha256};

/// Represents an end-to-end asset transfer
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// SHA256 hash of the transaction body
    pub id: Vec<u8>,
    /// Sender's Dilithium Public Key
    pub sender: dilithium5::PublicKey,
    /// Receiver's Dilithium Public Key
    pub receiver: dilithium5::PublicKey,
    /// Zero-Knowledge proof of the transaction amount
    pub amount_proof: ZkTransactionAmount,
    /// Dilithium signature over the transaction hash
    pub signature: Option<dilithium5::SignedMessage>,
}

impl Transaction {
    /// Creates a new, unsigned transaction
    pub fn new(
        sender: dilithium5::PublicKey,
        receiver: dilithium5::PublicKey,
        amount_proof: ZkTransactionAmount,
    ) -> Self {
        let mut tx = Self {
            id: Vec::new(),
            sender,
            receiver,
            amount_proof,
            signature: None,
        };
        tx.id = tx.hash();
        tx
    }

    /// Computes the hash of the transaction components
    /// Computes the hash of the transaction components using Domain Separation
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        // Domain Separation: Prevents Mainnet/Testnet Replay Attacks
        hasher.update(b"AETHEL_MAINNET_V1");
        hasher.update(self.sender.as_bytes());
        hasher.update(self.receiver.as_bytes());
        hasher.update(self.amount_proof.commitment.as_bytes());
        // In a real implementation, we'd also hash the proof bytes, but the commitment anchors it.
        hasher.finalize().to_vec()
    }

    /// Signs the transaction using the sender's private key
    pub fn sign(&mut self, sk: &dilithium5::SecretKey) {
        let sig = dilithium5::sign(&self.id, sk);
        self.signature = Some(sig);
    }

    /// Verifies the transaction:
    /// 1. Verifies the Zero-Knowledge Range Proof
    /// 2. Verifies the Dilithium signature matches the sender's public key
    pub fn verify(&self) -> bool {
        // 1. Verify ZKP
        if !self.amount_proof.verify_proof() {
            return false;
        }

        // 2. Verify Signature
        if let Some(sig) = &self.signature {
            match dilithium5::open(sig, &self.sender) {
                Ok(recovered_hash) => recovered_hash == self.id,
                Err(_) => false,
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::ZkTransactionAmount;

    #[test]
    fn test_transaction_lifecycle() {
        let (sender_pk, sender_sk) = dilithium5::keypair();
        let (receiver_pk, _) = dilithium5::keypair();

        // Generate valid ZKP for amount 100
        let (zkp, _) = ZkTransactionAmount::create_proof(100).unwrap();

        let mut tx = Transaction::new(sender_pk, receiver_pk, zkp);

        // Unsigned transaction should fail verification
        assert!(!tx.verify());

        // Sign the transaction
        tx.sign(&sender_sk);

        // Signed transaction with valid ZKP should pass
        assert!(tx.verify());
    }
}
