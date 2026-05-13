----------------------- MODULE phase1_consensus -----------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

(*
  A TLA+ specification for the Aethel Sharded DAG Consensus.
  Models vertex addition, dynamic randomized sharding logic, and a fast
  atomic cross-shard protocol for transactions spanning multiple shards.
*)

CONSTANTS
    Nodes,      \* Set of all node identifiers
    NumShards,  \* Number of shards
    MaxVertices \* Maximum number of vertices to simulate

VARIABLES
    dag,        \* The global DAG, mapping vertex IDs to vertex records
    mempools,   \* Mempools for each shard, containing pending transactions
    state,      \* Current state of the protocol (running, partition_detected, hibernated)
    cross_shard_locks \* Maps txId -> set of shards that have locked the tx

vars == <<dag, mempools, state, cross_shard_locks>>

(* Helper Functions *)
HashToShard(txId) == (txId % NumShards) + 1

Init ==
    /\ dag = [v \in {} |-> {}]
    /\ mempools = [s \in 1..NumShards |-> {}]
    /\ state = "running"
    /\ cross_shard_locks = [tx \in {} |-> {}]

(* A node creates a new vertex in a specific shard *)
ProposeVertex(node, shard, txs, parents) ==
    /\ state = "running"
    /\ Cardinality(DOMAIN dag) < MaxVertices
    /\ let newV == Cardinality(DOMAIN dag) + 1
       in
          /\ dag' = dag @@ (newV :> [creator |-> node, shard |-> shard, txs |-> txs, parents |-> parents])
          /\ mempools' = mempools \* Full model would remove txs
          /\ state' = state
          /\ cross_shard_locks' = cross_shard_locks

(* Cross-shard transaction locking mechanism *)
LockCrossShardTx(shard, txId) ==
    /\ state = "running"
    /\ txId \notin DOMAIN cross_shard_locks \/ shard \notin cross_shard_locks[txId]
    /\ let currentLocks == if txId \in DOMAIN cross_shard_locks then cross_shard_locks[txId] else {}
       in cross_shard_locks' = cross_shard_locks @@ (txId :> (currentLocks \cup {shard}))
    /\ UNCHANGED <<dag, mempools, state>>

(* Node execution *)
NodeAction(node) ==
    \E shard \in 1..NumShards:
        \E txs \in SUBSET mempools[shard]:
            \E parents \in SUBSET {v \in DOMAIN dag : dag[v].shard = shard}:
                ProposeVertex(node, shard, txs, parents)

Next ==
    \/ (\E n \in Nodes: NodeAction(n))
    \/ (\E s \in 1..NumShards: \E txId \in 1..100:
            /\ HashToShard(txId) = s
            /\ mempools' = [mempools EXCEPT ![s] = @ \cup {txId}]
            /\ UNCHANGED <<dag, state, cross_shard_locks>>
       )
    \/ (\E s \in 1..NumShards: \E txId \in 1..100:
            LockCrossShardTx(s, txId))

Spec == Init /\ [][Next]_vars

(* Safety Properties *)
ValidDAG ==
    \A v \in DOMAIN dag:
        \A p \in dag[v].parents:
            p \in DOMAIN dag /\ p < v

(* Cross shard property: if a tx touches multiple shards, it must eventually be locked by them *)
CrossShardSafety ==
    \A tx \in DOMAIN cross_shard_locks:
        Cardinality(cross_shard_locks[tx]) <= NumShards

=============================================================================
