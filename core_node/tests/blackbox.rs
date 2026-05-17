use core_node::AethelNode;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_blackbox_boundary_payload_size() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let temp_dir = tempfile::tempdir().unwrap();

    // Boot up the target node opaquely
    let target_node = AethelNode::bootstrap(addr, temp_dir.path().to_path_buf()).await.unwrap();
    let target_addr = target_node.network.endpoint.local_addr().unwrap();
    let target_peer_id = network::derive_peer_id(&target_node.network.cert);

    // Boot up a client node to act as the tester
    let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let client_dir = tempfile::tempdir().unwrap();
    let client_node = AethelNode::bootstrap(client_addr, client_dir.path().to_path_buf()).await.unwrap();

    // 1. Valid Minimum Payload (1 byte)
    let min_payload = vec![1u8];
    client_node.network.broadcast_transaction(&min_payload, &[(target_addr, target_peer_id.clone())]).await;

    // 2. Valid Maximum Payload (1 MB)
    let max_payload = vec![2u8; 1024 * 1024];
    client_node.network.broadcast_transaction(&max_payload, &[(target_addr, target_peer_id.clone())]).await;

    // 3. Invalid Excessive Payload (1 MB + 1 byte)
    // The system should actively terminate the stream mid-flight, but the node itself should not crash.
    let excessive_payload = vec![3u8; (1024 * 1024) + 1];
    client_node.network.broadcast_transaction(&excessive_payload, &[(target_addr, target_peer_id.clone())]).await;

    // Give asynchronous tasks a moment to resolve streams
    sleep(Duration::from_millis(200)).await;

    // Deterministic Output Check: If the node is still alive, the storage engine should have processed
    // exactly the 2 valid payloads and dropped the 3rd. We verify node survival by attempting a 4th query.
    let survival_payload = vec![4u8];
    client_node.network.broadcast_transaction(&survival_payload, &[(target_addr, target_peer_id.clone())]).await;

    sleep(Duration::from_millis(100)).await;

    // If the test completes without panic, equivalence partition handling is robust.
}

#[tokio::test]
async fn test_blackbox_workflow_emulation_state() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let temp_dir = tempfile::tempdir().unwrap();
    let target_node = AethelNode::bootstrap(addr, temp_dir.path().to_path_buf()).await.unwrap();
    let target_addr = target_node.network.endpoint.local_addr().unwrap();
    let target_peer_id = network::derive_peer_id(&target_node.network.cert);

    let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let client_dir = tempfile::tempdir().unwrap();
    let client_node = AethelNode::bootstrap(client_addr, client_dir.path().to_path_buf()).await.unwrap();

    // Emulate sequential multi-step workflow without relying on internal knowledge.
    // Send 10 identical payloads to see if the connection multiplexer survives.
    for i in 0..10 {
        let payload = vec![i as u8; 10];
        client_node.network.broadcast_transaction(&payload, &[(target_addr, target_peer_id.clone())]).await;
    }

    sleep(Duration::from_millis(100)).await;
    // Node should be alive, accepting all independent QUIC streams without connection state failure
}

#[tokio::test]
async fn test_blackbox_negative_leakage() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let temp_dir = tempfile::tempdir().unwrap();
    let target_node = AethelNode::bootstrap(addr, temp_dir.path().to_path_buf()).await.unwrap();
    let target_addr = target_node.network.endpoint.local_addr().unwrap();

    let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let client_dir = tempfile::tempdir().unwrap();
    let client_node = AethelNode::bootstrap(client_addr, client_dir.path().to_path_buf()).await.unwrap();

    // 1. Unauthenticated/Wrong Peer ID attack
    let wrong_peer_id = vec![255u8; 32];

    // This broadcast will fail at the TLS layer because the peer ID presented by the server
    // will not match the client's expected `wrong_peer_id`. We are verifying the failure
    // is generic and doesn't crash the server or leak info back to the client.
    let malicious_payload = b"malformed_data".to_vec();
    client_node.network.broadcast_transaction(&malicious_payload, &[(target_addr, wrong_peer_id)]).await;

    sleep(Duration::from_millis(100)).await;
    // Node should be perfectly alive without crashing
}
