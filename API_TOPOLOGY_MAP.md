# API_TOPOLOGY_MAP

## Overview
Aethel operates purely as a highly optimized, fully decentralized Sharded DAG with Leaderless BFT over QUIC/UDP. There are no traditional REST, GraphQL, or gRPC interfaces. The "API" is defined by the Peer-to-Peer network protocols, consensus logic parameters, and binary serialization schema (`bincode`).

## P2P Network Protocol API (QUIC / UDP)
- **Transport**: QUIC over UDP (via `quinn` and `rustls`).
- **Data Serialization**: `bincode` serialization of Rust native structs.
- **Connection Logic**: Maximum concurrent streams restricted via a localized semaphore.

### Core Exposed Topology Interfaces:
1. `P2PNetwork::new(config: NetworkConfig)`
   - **Inputs**: `NetworkConfig` containing binding address strings and bootstrap peer arrays.
   - **Outputs**: Network handle and stream listeners.

2. `DHT (Distributed Hash Table)`
   - **Interface**: Kademlia-inspired routing lookup.
   - **Inputs**: Node ID byte arrays.
   - **Security Bounds**: Max `K_BUCKET_SIZE` set to limit memory exhaustion vectors.

3. `Network Listener Handlers`
   - **Interface**: Background tokio task looping on incoming QUIC connections.
   - **Payload Expectation**: A byte stream that can be deserialized using `bincode` into a `crypto::transaction::Transaction` struct.

4. `Consensus API`
   - `validate_and_add_tx(tx: Transaction)`
   - **Inputs**: Deserialized `Transaction`.
   - **Constraints**: Validates structural limits and cryptographic ML-DSA signatures. Bounds are placed on `MAX_TXS_PER_VERTEX`.
