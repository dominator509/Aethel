# INTERNAL_STRUCTURE_MAP

## Cyclomatic Complexity & Control Flow Mapping

| Module | File | Estimated Cyclomatic Complexity |
|---|---|---|
| crypto | zkp.rs | 9 |
| crypto | transaction.rs | 6 |
| crypto | lib.rs | 5 |
| network | lib.rs | 20 |
| network | dht.rs | 8 |
| consensus | lib.rs | 16 |
| storage | sstable.rs | 18 |
| storage | lib.rs | 20 |
| core_node | recovery.rs | 8 |
| core_node | lib.rs | 13 |

### High-Risk Targeting
The `consensus/src/lib.rs` and `network/src/lib.rs` modules exhibit the highest branch density due to deep validation logic, loop constraints, and ? operator unwrapping. Phase 2-4 testing will heavily target the internal paths of `Dag::propose_vertex`, `StorageEngine::put`, and `listen_for_transactions`.
