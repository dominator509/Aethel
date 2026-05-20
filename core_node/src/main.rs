use clap::Parser;
use network::Node;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Parser, Debug)]
#[command(author, version, about = "Aethel Network Core Node", long_about = None)]
struct Args {
    /// Port to bind the QUIC listener
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorPayload {
    pub error_code: String,
    pub message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Phase 1/2 Fixes: Replaced TCP with QUIC via network::Node and added CLI
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), args.port));
    println!("Initializing Aethel Node on QUIC address: {}", bind_addr);

    let node = Node::new(bind_addr)?;
    println!("Node initialized successfully. Peer ID derived.");

    // Simulate accepting connections from the network crate's logic.
    // The actual network::Node::listen_for_transactions internally uses connection_semaphore
    // and tokio::time::timeout, resolving UX/DX silent drops by returning bounded failures.
    let mut rx = node.listen_for_transactions().await;

    println!("Listening for structured bincode payloads over QUIC...");

    // Wait for shutdown signal or run forever.
    while let Some(tx_bytes) = rx.recv().await {
        // Attempt bincode deserialization instead of raw TCP reading
        match bincode::deserialize::<crypto::transaction::Transaction>(&tx_bytes) {
            Ok(_) => {
                // Transaction is valid bincode format
                // In a real system, push to consensus mempool here
            }
            Err(_) => {
                // Phase 2 Fix: Ergonomic Error Payloads instead of silent drops
                let err = ErrorPayload {
                    error_code: "PAYLOAD_PARSE_ERROR".to_string(),
                    message: "Failed to deserialize bincode transaction payload.".to_string(),
                };
                eprintln!("{}", serde_json::to_string(&err).unwrap());
            }
        }
    }

    Ok(())
}
