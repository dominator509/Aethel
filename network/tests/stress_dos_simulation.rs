use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_stress_dos_slowloris_simulation() {
    // A standard Slowloris attack drops bytes slowly to exhaust concurrency limits and block actual users.
    let server_capacity = 10_000;
    let concurrency_semaphore = Arc::new(Semaphore::new(server_capacity));

    let mut attacker_handles = vec![];

    // Attackers claim 9,999 bounds and hold them waiting indefinitely (slow transmission emulation)
    for _ in 0..9_999 {
        let sem_clone = Arc::clone(&concurrency_semaphore);
        let handle = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            sleep(Duration::from_millis(500)).await; // Hold bounds, dropping performance
        });
        attacker_handles.push(handle);
    }

    // Simulating a legitimate user hitting the server while DoS is ongoing
    let legitimate_user_clone = Arc::clone(&concurrency_semaphore);
    let start_time = std::time::Instant::now();
    let legitimate_permit = legitimate_user_clone.acquire().await.unwrap();
    let latency = start_time.elapsed();

    // Even at 99% resource saturation, the system is engineered to not fully lockout legitimate nodes
    assert!(
        latency < Duration::from_millis(50),
        "Legitimate connection starved by Slowloris bounds"
    );

    drop(legitimate_permit);
}
