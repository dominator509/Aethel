use consensus::Dag;
use crypto::transaction::Transaction;
use crypto::zkp::ZkTransactionAmount;
use pqcrypto_dilithium::dilithium5;
use std::time::Instant;

#[test]
fn test_stress_mempool_ram_exhaustion() {
    let mut dag = Dag::new(0);

    let (pk_sender, sk_sender) = dilithium5::keypair();
    let (pk_receiver, _) = dilithium5::keypair();

    let start = Instant::now();
    let stress_limit = 2_000usize; // A limit large enough to test allocations, small enough for GitHub actions bounds.

    // We do one proof and serialize it so we can bypass ZKP overhead inside the loop
    let (amount_proof, _) = ZkTransactionAmount::create_proof(100).unwrap();
    let mut base_tx = Transaction::new(pk_sender, pk_receiver, amount_proof);
    base_tx.sign(&sk_sender);

    let serialized_tx = bincode::serialize(&base_tx).unwrap();

    for i in 0..stress_limit {
        let mut tx: Transaction = bincode::deserialize(&serialized_tx).unwrap();

        let mut id = vec![0u8; 32];
        let bytes = i.to_be_bytes();
        for j in 0..bytes.len() {
            id[j] = bytes[j];
        }
        tx.id = id.clone();

        dag.mempool.insert(id, tx);
    }

    let _duration = start.elapsed();
    assert_eq!(dag.mempool.len(), stress_limit);
}
