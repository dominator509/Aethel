# SATURATION_TARGET_MAP

## Overview
Aethel's highly optimized decentralized networking structure is uniquely designed for 3M TPS. Stressing this theoretical limit requires mathematically exhausting specific hardware bounds using localized saturation testing.

## Baseline Hardware Saturation Bottlenecks
1. **CPU Saturation: ML-DSA Cryptographic Validations**
   - *Target Constraint*: Post-Quantum Cryptographic verification (`pqcrypto-mldsa`) is computationally expensive compared to ECDSA.
   - *Saturation Event*: Spamming thousands of unverified transaction bounds simultaneously will pin CPU utilization to 100%.

2. **RAM Exhaustion: `Dag::mempool` and Cross-Shard Vectors**
   - *Target Constraint*: Transactions held dynamically in the memory-pool waiting for cross-shard locks before vertex graph mapping.
   - *Saturation Event*: Injecting a massive volume of valid transactions without running the proposer vertex loop. The memory footprint will linearly scale until `OOM`.

3. **Disk I/O Latency: `StorageEngine::flush_memtable`**
   - *Target Constraint*: Dumping 500k memory-buffered transactions out onto the local filesystem via LSM-tree SSTables concurrently.
   - *Saturation Event*: Disk bottleneck resulting in IO blocking, which then starves the main Tokio network listener thread.

4. **Network Bandwidth / Descriptor Exhaustion: P2P Streams**
   - *Target Constraint*: UDP QUIC handles constrained by local semaphores.
   - *Saturation Event*: Sustaining 20,000 parallel streams sending half-finished data frames, simulating a Slowloris-over-QUIC DoS vector targeting open File Descriptors.
