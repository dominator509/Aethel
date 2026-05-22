use pqcrypto_mldsa::mldsa87;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::sign::VerificationError;

/// Generate a Kyber keypair for encapsulation
pub fn generate_mlkem_keypair() -> (mlkem1024::PublicKey, mlkem1024::SecretKey) {
    mlkem1024::keypair()
}

/// Encapsulate a shared secret using a public key
pub fn encapsulate(pk: &mlkem1024::PublicKey) -> (mlkem1024::SharedSecret, mlkem1024::Ciphertext) {
    mlkem1024::encapsulate(pk)
}

/// Decapsulate a shared secret using a secret key and ciphertext
pub fn decapsulate(
    ct: &mlkem1024::Ciphertext,
    sk: &mlkem1024::SecretKey,
) -> mlkem1024::SharedSecret {
    mlkem1024::decapsulate(ct, sk)
}

/// Generate a Dilithium keypair for signing
pub fn generate_mldsa_keypair() -> (mldsa87::PublicKey, mldsa87::SecretKey) {
    mldsa87::keypair()
}

/// Sign a message using a Dilithium secret key
pub fn sign(message: &[u8], sk: &mldsa87::SecretKey) -> mldsa87::SignedMessage {
    mldsa87::sign(message, sk)
}

/// Verify a Dilithium signature
pub fn verify(
    signed_message: &mldsa87::SignedMessage,
    pk: &mldsa87::PublicKey,
) -> Result<Vec<u8>, VerificationError> {
    mldsa87::open(signed_message, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::SharedSecret;

    #[test]
    fn test_mlkem_encapsulation() {
        let (pk, sk) = generate_mlkem_keypair();
        let (ss1, ct) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);

        assert_eq!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "Shared secrets do not match!"
        );
    }

    #[test]
    fn test_mldsa_signing() {
        let (pk, sk) = generate_mldsa_keypair();
        let message = b"Hello Aethel Network!";

        let signed_message = sign(message, &sk);
        let verified_message = verify(&signed_message, &pk).expect("Signature verification failed");

        assert_eq!(
            message,
            verified_message.as_slice(),
            "Recovered message does not match original"
        );
    }
}
pub mod transaction;
pub mod zkp;
