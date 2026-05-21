# REGRESSION_BASELINE_MATRIX

## Baseline State Capture
- **Target Context**: Aethel Project (High-performance Rust, Sharded DAG Consensus, ML-KEM/ML-DSA, ZKP, custom UDP/QUIC).
- **Core Legacy Workflows**:
  1. `crypto` Module: PQ-Safe encapsulation (ML-KEM) and signing (ML-DSA). Range proofs (Bulletproofs).
  2. `consensus` Module: Leaderless BFT DAG structure, parent validation, hash-to-shard mapping, finality ordering.
  3. `storage` Module: Custom LSM-Tree, MemTable mutability, SSTable flush and N-Way streaming compaction limits (OOM prevention).
  4. `network` Module: QUIC/UDP connectivity, routing layers, DHT configuration limits.
  5. `core_node` Module: E2E bootstrap, storage cleanup loops, system recovery behaviors.
- **Architectural Rules (Immutable)**:
  - Fail Closed mechanism in `recovery` protocols.
  - Hard bounds: `MAX_ALLOCATION_SIZE`, `MAX_KEYS_PER_COMPACTION`, QUIC connection bounds.

## Integration Targets
- Ensure cross-crate logic remains intact specifically where `network` routing passes payloads via bincode deserialization into `storage` -> `consensus`.
