use consensus::Dag;
use crypto::transaction::Transaction;
use crypto::zkp::ZkTransactionAmount;
use pqcrypto_mldsa::mldsa87;

#[test]
fn test_regression_v2_dag_parent_bounds_immutability() {
    let (pk_sender, sk_sender) = mldsa87::keypair();
    let (pk_receiver, _sk_receiver) = mldsa87::keypair();

    let (amount_proof, _bf) = ZkTransactionAmount::create_proof(100).unwrap();
    let mut tx = Transaction::new(pk_sender, pk_receiver, amount_proof);
    tx.sign(&sk_sender);

    let target_shard = Dag::hash_to_shard(&tx.id);
    let mut dag = Dag::new(target_shard);

    let res = dag.validate_and_add_tx(tx);
    assert!(res.is_ok(), "Failed to add valid TX");

    assert_eq!(dag.mempool.len(), 1);
}
