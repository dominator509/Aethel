use crypto::transaction::Transaction;

#[test]
fn test_api_schema_bincode_boundary_coercions() {
    // Injecting massive payload to attempt an integer overflow or Out of Bounds memory issue during routing
    let large_payload = vec![0xFF; 50 * 1024 * 1024]; // 50MB of junk

    let result: Result<Transaction, _> = bincode::deserialize(&large_payload);

    // Test should pass because it should cleanly fail to map the arbitrary payload to the Tx schema bounds
    assert!(result.is_err());

    // Attempting a tiny truncated payload
    let truncated_payload = vec![0x00, 0x01];
    let result_truncated: Result<Transaction, _> = bincode::deserialize(&truncated_payload);
    assert!(result_truncated.is_err());
}
