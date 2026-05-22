# REGRESSION_BASELINE_MATRIX_V2

## Baseline State Capture (Post-API & Post-Storage Integration)
- **Target Context**: Aethel Project.
- **Core Legacy Workflows Verified in V1**:
  - `storage` Module OOM Prevention limits & N-Way compaction structures.
  - `network` Module QUIC/UDP concurrency bounds & semantic validation constraints.
  - Basic `bincode` deserialization structure bounds.

## Expanded V2 Immutable Workflows
1. **DAG Consensus Immutability**:
   - `add_transaction`: Must enforce parent hashing limits (`MAX_PARENTS_PER_VERTEX`).
   - `compute_finality_and_order`: Must remain deterministic under varying topological ingestion orders.
   - Cross-shard locking bounds: Must isolate state effectively.
2. **Cryptographic ZKP & PQC Resiliency**:
   - `verify_proof` and ML-DSA signatures must remain non-bypassable, even when wrapped deeply inside `consensus::Vertex` objects rather than just on the wire.
