use consensus::Dag;

#[test]
fn test_adhoc_persona_out_of_sequence_ingestion() {
    let mut dag = Dag::new(0);

    let creator_id = vec![0x11; 32];
    let fake_parents = vec![vec![0x99; 32]];
    let fake_txs = vec![vec![0x55; 32]];

    let _ = dag.propose_vertex(creator_id, fake_parents, fake_txs);

    let finalized = dag.compute_finality_and_order();

    assert_eq!(
        finalized.len(),
        0,
        "Out-of-sequence DAG vertex bypassed structural constraints and finalized an orphan graph"
    );
}
