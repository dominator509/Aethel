use consensus::Dag;
use crypto::transaction::Transaction;
use crypto::zkp::ZkTransactionAmount;
use pqcrypto_dilithium::dilithium5;
use std::sync::{Arc, Mutex};
use std::thread;

#[test]
fn test_adhoc_concurrency_state_disruption() {
    let (pk_sender, sk_sender) = dilithium5::keypair();
    let (pk_receiver, _) = dilithium5::keypair();

    let mut transactions_to_add = vec![];
    for _ in 0..10 {
        let (amount_proof, _) = ZkTransactionAmount::create_proof(100).unwrap();
        let mut tx = Transaction::new(pk_sender, pk_receiver, amount_proof);
        tx.sign(&sk_sender);
        transactions_to_add.push(tx);
    }

    let mut dag = Dag::new(0);
    for tx in transactions_to_add {
        // Just inject into mempool directly or bypass to test lock_cross_shard_tx
        let tx_id = tx.id.clone();
        dag.mempool.insert(tx_id, tx);
    }

    let dag = Arc::new(Mutex::new(dag));
    let mut handles = vec![];

    let ids: Vec<_> = dag.lock().unwrap().mempool.keys().cloned().collect();
    for _ in 0..50 {
        let dag_clone = Arc::clone(&dag);
        let tx_ids = ids.clone();
        let handle = thread::spawn(move || {
            let mut locked_dag = dag_clone.lock().unwrap();
            for id in tx_ids {
                locked_dag.lock_cross_shard_tx(id);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let final_dag = dag.lock().unwrap();
    assert!(final_dag.mempool.len() > 0, "Mempool drained unexpectedly");
}
