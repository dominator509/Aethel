#![forbid(unsafe_code)]

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;

/// A Zero-Knowledge Range Proof representing a hidden transaction amount
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ZkTransactionAmount {
    pub proof: RangeProof,
    pub commitment: CompressedRistretto,
}

impl ZkTransactionAmount {
    /// Creates a new Zero-Knowledge Range Proof for a transaction amount.
    /// This proves that the amount is within [0, 2^64) without revealing it.
    pub fn create_proof(amount: u64) -> Result<(Self, Scalar), &'static str> {
        // According to Bulletproofs, if we pass `n` bits (32 here), the input must be less than 2^n.
        // The bulletproof library might panic or generate an invalid proof if we pass a larger value,
        // but let's handle it manually to be safe.
        if amount >= (1u64 << 32) {
            return Err("Amount too large for a 32-bit range proof");
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);

        // The blinding factor (secret)
        let mut rng = rand::thread_rng();
        let blinding_factor = Scalar::random(&mut rng);

        let mut transcript = Transcript::new(b"AethelTransactionZKP");

        // Generate the range proof
        let (proof, commitments) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            amount,
            &blinding_factor,
            32, // Support up to 32 bits for the proof initially
        )
        .map_err(|_| "Failed to generate range proof")?;

        Ok((
            Self {
                proof,
                commitment: commitments,
            },
            blinding_factor,
        ))
    }

    /// Verifies the Zero-Knowledge Range Proof.
    pub fn verify_proof(&self) -> bool {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);

        let mut transcript = Transcript::new(b"AethelTransactionZKP");

        self.proof
            .verify_single(&bp_gens, &pc_gens, &mut transcript, &self.commitment, 32)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_range_proof() {
        let amount = 42;
        let (zkp, _blinding) =
            ZkTransactionAmount::create_proof(amount).expect("Proof creation failed");

        // Proof should verify correctly
        assert!(zkp.verify_proof());
    }

    #[test]
    fn test_proof_out_of_range() {
        // Amount larger than 2^32 (since we configured 32 bits above)
        let amount = (1u64 << 33) + 1;
        let result = ZkTransactionAmount::create_proof(amount);

        // Generating a proof for an out-of-range value should fail
        assert!(result.is_err());
    }
}
