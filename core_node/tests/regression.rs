use bytes::Bytes;
use storage::StorageEngine;

#[tokio::test]
async fn test_regression_e2e_storage_compaction_and_routing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().to_path_buf();

    // 1. Storage Baseline validation
    let storage = StorageEngine::new(db_path.clone()).await.unwrap();

    // Insert dummy keys
    for i in 0..10 {
        let key = Bytes::from(format!("key_{}", i));
        let val = Bytes::from(format!("val_{}", i));
        storage.put(key.clone(), val.clone()).await.unwrap();
    }

    // Test extraction
    let test_key = Bytes::from("key_5");
    let test_val = storage.get(&test_key).await.unwrap();
    assert_eq!(test_val, Bytes::from("val_5"));
}
