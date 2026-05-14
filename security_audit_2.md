# Aethel Network Security Audit & Hardening Report v2

## Red Team: State-Space Execution Path Vulnerability Assessment
Following the initial dependency audit, a rigorous manual and automated state-space audit of the execution paths within the node architecture revealed critical Resource Exhaustion vectors:

1. **Unbounded Mempool Growth (Consensus Crate):** The `Dag::validate_and_add_tx` function accepts transactions into an unbounded `HashMap`. A malicious actor can spam valid transactions (or a network partition could prevent blocks from forming), leading to an Out-Of-Memory (OOM) crash of the core node.
2. **Unbounded DAG Vertex Proposal (Consensus Crate):** The `Dag::propose_vertex` function does not cap the number of transactions or parents a single vertex can reference. A malicious proposer could submit a vertex referencing 1 million parents, triggering massive compute overhead during verification and a potential DoS.
3. **SSTable Compaction OOM (Storage Crate):** The `SSTable::compact` function iterates over an array of SSTables and reads the *entirety* of their contents into an in-memory `BTreeMap` before flushing. If the SSTables are gigabytes in size (expected at 3M TPS), this immediately triggers an OOM crash.

## Blue Team: Defense and Mitigation
To defend against these execution path vectors, strict boundaries must be established.

- **Consensus Limits:** Implement hard constants for `MAX_MEMPOOL_SIZE` (e.g., 100,000 txs per shard), `MAX_TXS_PER_VERTEX` (e.g., 10,000), and `MAX_PARENTS_PER_VERTEX` (e.g., 10). If limits are reached, the node must reject new data gracefully (fail-safe) rather than panic.
- **Storage Limits:** Implement safety boundary checks in the SSTable reader. Specifically, ensure `key_len` and `val_len` do not exceed a massive integer (e.g., preventing a corrupted file from requesting a 4GB vector allocation).

## Purple Team: Logging and Patch Execution
- **Refactored `consensus/src/lib.rs`:** Added constant limit parameters and integrated bounding checks into `validate_and_add_tx` and `propose_vertex`.
- **Refactored `storage/src/sstable.rs`:** Added strict `MAX_ALLOCATION_SIZE` checks before creating vectors to prevent memory exhaustion from maliciously crafted or corrupted SSTable files.
