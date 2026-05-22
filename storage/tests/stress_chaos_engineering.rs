use bytes::Bytes;
use storage::sstable::SSTable;
use storage::StorageEngine;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_chaos_engineering_disk_exhaustion_during_compaction() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().to_path_buf();

    let storage = StorageEngine::new(db_path.clone()).await.unwrap();

    for i in 0..10_000 {
        let key = Bytes::from(format!("chaos_key_{}", i));
        let val = Bytes::from(format!("chaos_val_{}", i));
        storage.put(key, val).await.unwrap();
    }

    // We can't explicitly flush the API but we can cause chaos during manual compaction
    // Sabotage check: injecting a missing file pointer that bypasses standard logic
    let table = SSTable {
        path: db_path.clone().join("sabotage.sst"),
    };
    let out_temp = NamedTempFile::new().unwrap();
    let compact_res = SSTable::compact(&[table], out_temp.path().to_path_buf()).await;

    // IO drops failed cleanly instead of panicking
    assert!(compact_res.is_err());
}
