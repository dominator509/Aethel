use std::sync::Arc;
use tokio::sync::Semaphore;

/// Strict architectural limits for the Aethel network to prevent DoS.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 10_000;
pub const CONNECTION_READ_TIMEOUT_SECS: u64 = 5;

pub struct NetworkConfig {
    pub connection_semaphore: Arc<Semaphore>,
}

impl NetworkConfig {
    pub fn new() -> Self {
        Self {
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        }
    }
}
