use bincode;
use crypto::transaction::Transaction;
use crypto::zkp::ZkTransactionAmount;
use pqcrypto_mldsa::mldsa87;

#[test]
fn test_api_auth_bincode_deserialization_tampering() {
    let (pk_sender, sk_sender) = mldsa87::keypair();
    let (pk_receiver, _sk_receiver) = mldsa87::keypair();

    let (amount_proof, _blinding_factor) = ZkTransactionAmount::create_proof(100).unwrap();
    let mut tx = Transaction::new(pk_sender, pk_receiver, amount_proof);
    tx.sign(&sk_sender);

    let mut serialized_tx = bincode::serialize(&tx).unwrap();
    let len = serialized_tx.len();
    serialized_tx[len - 1] ^= 0xFF; // flip last bit of signature

    let result: Result<Transaction, _> = bincode::deserialize(&serialized_tx);

    if let Ok(tampered_tx) = result {
        let verified = tampered_tx.verify();
        assert!(
            !verified,
            "Tampered transaction payload bypassed cryptographic signature verification"
        );
    }
}
