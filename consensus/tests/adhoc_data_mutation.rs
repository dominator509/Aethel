use consensus::Dag;
use crypto::transaction::Transaction;
use crypto::zkp::ZkTransactionAmount;
use pqcrypto_mldsa::mldsa87;

#[test]
fn test_adhoc_mutation_truncated_crypto() {
    let (pk_sender, sk_sender) = mldsa87::keypair();
    let (pk_receiver, _) = mldsa87::keypair();

    // Create a real proof to satisfy the struct bounds natively without deep mock bypassing
    let (amount_proof, _) = ZkTransactionAmount::create_proof(100).unwrap();

    // Inject massive payload directly into public struct field mapping bounds
    let mut tx = Transaction::new(pk_sender, pk_receiver, amount_proof);

    // Mutating public struct data to bypass validation
    tx.id = vec![0xFF; 50_000]; // 50KB ID where normally ~32 bytes is expected
    tx.sign(&sk_sender);

    let target_shard = Dag::hash_to_shard(&tx.id);
    let mut dag = Dag::new(target_shard);

    // If memory expands uncapped or bounds arrays panic, test fails.
    // If it gracefully rejects or processes it properly, test passes.
    let result = dag.validate_and_add_tx(tx);

    // The DAG should either gracefully accept it (if no ID length constraint is built in)
    // or gracefully reject it, but it MUST NOT panic.
    if result.is_err() {
        assert_eq!(
            result.unwrap_err(),
            "Transaction failed cryptographic verification (ZKP or Signature)"
        );
    }
}
