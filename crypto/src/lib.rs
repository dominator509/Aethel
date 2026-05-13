use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::VerificationError;

/// Generate a Kyber keypair for encapsulation
pub fn generate_kyber_keypair() -> (kyber1024::PublicKey, kyber1024::SecretKey) {
    kyber1024::keypair()
}

/// Encapsulate a shared secret using a public key
pub fn encapsulate(pk: &kyber1024::PublicKey) -> (kyber1024::SharedSecret, kyber1024::Ciphertext) {
    kyber1024::encapsulate(pk)
}

/// Decapsulate a shared secret using a secret key and ciphertext
pub fn decapsulate(ct: &kyber1024::Ciphertext, sk: &kyber1024::SecretKey) -> kyber1024::SharedSecret {
    kyber1024::decapsulate(ct, sk)
}

/// Generate a Dilithium keypair for signing
pub fn generate_dilithium_keypair() -> (dilithium5::PublicKey, dilithium5::SecretKey) {
    dilithium5::keypair()
}

/// Sign a message using a Dilithium secret key
pub fn sign(message: &[u8], sk: &dilithium5::SecretKey) -> dilithium5::SignedMessage {
    dilithium5::sign(message, sk)
}

/// Verify a Dilithium signature
pub fn verify(signed_message: &dilithium5::SignedMessage, pk: &dilithium5::PublicKey) -> Result<Vec<u8>, VerificationError> {
    dilithium5::open(signed_message, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::SharedSecret;
    use pqcrypto_traits::sign::SignedMessage;

    #[test]
    fn test_kyber_encapsulation() {
        let (pk, sk) = generate_kyber_keypair();
        let (ss1, ct) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);

        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "Shared secrets do not match!");
    }

    #[test]
    fn test_dilithium_signing() {
        let (pk, sk) = generate_dilithium_keypair();
        let message = b"Hello Aethel Network!";

        let signed_message = sign(message, &sk);
        let verified_message = verify(&signed_message, &pk).expect("Signature verification failed");

        assert_eq!(message, verified_message.as_slice(), "Recovered message does not match original");
    }
}
pub mod zkp;
