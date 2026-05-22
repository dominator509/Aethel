use consensus::Dag;
use crypto::transaction::Transaction;
use crypto::zkp::ZkTransactionAmount;
use pqcrypto_mldsa::mldsa87;

#[test]
fn test_regression_v2_consensus_crypto_tampering() {
    let (pk_sender, sk_sender) = mldsa87::keypair();
    let (pk_receiver, _sk_receiver) = mldsa87::keypair();

    let (amount_proof1, _) = ZkTransactionAmount::create_proof(100).unwrap();
    let tx1 = Transaction::new(pk_sender, pk_receiver, amount_proof1);

    let target_shard = Dag::hash_to_shard(&tx1.id);
    let mut dag = Dag::new(target_shard);

    let unsigned_res = dag.validate_and_add_tx(tx1);
    assert_eq!(
        unsigned_res.unwrap_err(),
        "Transaction failed cryptographic verification (ZKP or Signature)",
        "Consensus bypassed signature check on unsigned TX"
    );

    // Test 2: Tampering should drop TX
    let (amount_proof2, _) = ZkTransactionAmount::create_proof(100).unwrap();
    let mut tx2 = Transaction::new(pk_sender, pk_receiver, amount_proof2);
    tx2.sign(&sk_sender);

    // Abstractly modify the tx by setting a blank signature
    tx2.signature = None;

    let tampered_res = dag.validate_and_add_tx(tx2);
    assert_eq!(
        tampered_res.unwrap_err(),
        "Transaction failed cryptographic verification (ZKP or Signature)"
    );
}
