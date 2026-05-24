# SYSTEM_MAP_CHECK

## Architectural Mapping
The repository `aethel` is structured as a distributed microservice framework operating as a Layer 1 DAG.

### Core Entry Points
1.  `core_node::AethelNode::bootstrap`: The primary initialization routine. Binds the QUIC network socket, initializes the LSM-Tree storage, provisions 256 consensus shards, and triggers the network listener.
2.  `network::Node::listen_for_transactions`: Asynchronous UDP listener. Yields serialized transaction payloads over a Tokio MPSC channel to the core node.
3.  `network::Node::broadcast_transaction`: Asynchronous fan-out routine transmitting serialized payloads via QUIC to known peers.

### State Mutators (Dependency Graph)
*   `network` -> `core_node`: Transaction bytes are fed into the system.
*   `core_node` -> `storage`: Raw transaction bytes are persisted to the Write-Ahead Log (WAL) and inserted into the `MemTable`.
*   `core_node` -> `consensus`: In a fully wired implementation, transactions are routed to their respective shard and verified cryptographically via `crypto::zkp` and `crypto::transaction`.

### Conclusion
Data enters through `network`, is durably persisted by `storage`, mathematically verified by `crypto`, and organized topologically by `consensus`.
