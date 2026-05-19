use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use network::{NetworkConfig, CONNECTION_READ_TIMEOUT_SECS};

pub struct AethelNode {
    pub port: u16,
    pub network_config: NetworkConfig,
}

impl AethelNode {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            network_config: NetworkConfig::new(),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        println!("AethelNode listening on {} with max {} connections", addr, network::MAX_CONCURRENT_CONNECTIONS);

        loop {
            // Acquire a permit before accepting a new connection.
            // If the semaphore is exhausted, we block until a permit is returned, failing closed/throttling.
            let permit = self.network_config.connection_semaphore.clone().acquire_owned().await?;
            let (mut socket, _) = listener.accept().await?;

            tokio::spawn(async move {
                // Ensure the permit is held for the lifetime of this connection task
                let _permit = permit;
                let mut buf = [0; 1024];

                loop {
                    // Enforce a strict 5-second read timeout to prevent slowloris attacks
                    let read_future = socket.read(&mut buf);
                    let n = match timeout(Duration::from_secs(CONNECTION_READ_TIMEOUT_SECS), read_future).await {
                        Ok(Ok(n)) if n == 0 => return, // Connection closed
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => {
                            eprintln!("failed to read from socket; err = {:?}", e);
                            return;
                        }
                        Err(_) => {
                            eprintln!("Connection read timed out after {} seconds. Dropping peer.", CONNECTION_READ_TIMEOUT_SECS);
                            return; // Timeout
                        }
                    };

                    if let Err(e) = socket.write_all(&buf[0..n]).await {
                        eprintln!("failed to write to socket; err = {:?}", e);
                        return;
                    }
                }
            });
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node = AethelNode::new(8080);
    node.start().await?;
    Ok(())
}
