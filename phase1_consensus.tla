----------------------- MODULE phase1_consensus -----------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

(*
  A simplified TLA+ specification for the Aethel Sharded DAG Consensus.
  Models basic vertex addition, sharding logic based on a hash, and a basic
  leaderless approach.
*)

CONSTANTS
    Nodes,      \* Set of all node identifiers
    NumShards,  \* Number of shards
    MaxVertices \* Maximum number of vertices to simulate

VARIABLES
    dag,        \* The global DAG, mapping vertex IDs to vertex records
    mempools,   \* Mempools for each shard, containing pending transactions
    state       \* Current state of the protocol

vars == <<dag, mempools, state>>

(* Helper Functions *)
HashToShard(txId) == (txId % NumShards) + 1

Init ==
    /\ dag = [v \in {} |-> {}]
    /\ mempools = [s \in 1..NumShards |-> {}]
    /\ state = "running"

(* A node creates a new vertex in a specific shard *)
ProposeVertex(node, shard, txs, parents) ==
    /\ state = "running"
    /\ Cardinality(DOMAIN dag) < MaxVertices
    /\ let newV == Cardinality(DOMAIN dag) + 1
       in
          /\ dag' = dag @@ (newV :> [creator |-> node, shard |-> shard, txs |-> txs, parents |-> parents])
          \* In a full model, this would remove txs from mempool
          /\ mempools' = mempools
          /\ state' = state

(* Node execution *)
NodeAction(node) ==
    \E shard \in 1..NumShards:
        \E txs \in SUBSET mempools[shard]:
            \* Select some parents from the existing DAG in the same shard
            \E parents \in SUBSET {v \in DOMAIN dag : dag[v].shard = shard}:
                ProposeVertex(node, shard, txs, parents)

Next ==
    \/ (\E n \in Nodes: NodeAction(n))
    \/ (\E s \in 1..NumShards: \E txId \in 1..100:
            /\ HashToShard(txId) = s
            /\ mempools' = [mempools EXCEPT ![s] = @ \cup {txId}]
            /\ UNCHANGED <<dag, state>>
       )

Spec == Init /\ [][Next]_vars

(* Safety Properties *)
\* 1. Valid DAG: A vertex only references parents that exist in the DAG
ValidDAG ==
    \A v \in DOMAIN dag:
        \A p \in dag[v].parents:
            p \in DOMAIN dag /\ p < v

\* 2. Valid Sharding: A vertex in a shard only references parents in the same shard
\* (Simplified: assuming no cross-shard links for now)
ValidSharding ==
    \A v \in DOMAIN dag:
        \A p \in dag[v].parents:
            dag[p].shard = dag[v].shard

=============================================================================
