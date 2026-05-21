use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_api_high_concurrency_semaphore_limits() {
    // Aethel networking limits total concurrent requests across the swarm to prevent DDoS and memory exhaustion.
    // The configured target is typically 10,000 requests. We'll simulate 100 concurrently attempting
    // to access a resource gated by a much smaller simulated concurrency semaphore.
    let semaphore_limit = 10;
    let concurrency_semaphore = Arc::new(Semaphore::new(semaphore_limit));

    let mut handles = vec![];

    for _ in 0..100 {
        let sem_clone = Arc::clone(&concurrency_semaphore);
        let handle = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            // Simulate short async task like routing a transaction
            sleep(Duration::from_millis(5)).await;
        });
        handles.push(handle);
    }

    // We await all handles to ensure they resolve cleanly despite contention
    for handle in handles {
        handle.await.unwrap();
    }

    // Test successfully mapped without panics, deadlocks, or lock starvation
    assert_eq!(concurrency_semaphore.available_permits(), semaphore_limit);
}
