# Static Execution Tracing & Logic Auditing

## Critical Path Analysis: Transaction Ingestion
1.  Payload arrives at `network::Node::listen_for_transactions`. The semaphore prevents more than 10,000 active streams. A 5-second `read_to_end` timeout prevents slowloris. Valid byte vectors are sent over the `mpsc::channel`.
2.  `core_node::AethelNode::start_transaction_listener` loops indefinitely over the receiver.
3.  The listener computes a mock hash and calls `storage.put(tx_key, tx_val)`.
4.  `storage::StorageEngine::put` locks the WAL, appends the data (returning `Err` if `MAX_WAL_SIZE` is exceeded), drops the WAL lock, and locks the `MemTable`.
5.  It checks `memtable.map.len() >= MAX_MEMTABLE_SIZE`. If true, it rejects the transaction with an OOM safeguard error. If false, it inserts the key/value pair.

## Systemic Risks Identified
*   **Concurrency & State:** The `start_transaction_listener` does not handle errors from `storage.put()`.
*   **Resource Leaks / Deadlocks:** The system correctly bounds the `MemTable` and `WAL` to prevent disk/RAM exhaustion. However, there is no code executing a flush of the `MemTable` to `SSTables`. Therefore, once the node receives 1,000,000 transactions, the `MemTable` is full, and the node permanently deadlocks (enters a perpetual fail-closed state where all new transactions are dropped).

## Fault Isolation & Hypothesis Generation
*   **Target Node:** `core_node::AethelNode::bootstrap` and `storage::StorageEngine`
*   **Hypothesis:** The AethelNode bootstraps the storage engine but never spawns a background worker to flush the MemTable to disk. Consequently, once `MAX_MEMTABLE_SIZE` is hit, the `put()` operation fails continuously and silently (due to unhandled Results in the listener), permanently dropping all incoming network traffic.
