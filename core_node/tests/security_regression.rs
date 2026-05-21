use storage::sstable::SSTable;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_security_regression_oom_prevention() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_path_buf();

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .await
        .unwrap();

    // Constant limit is 10 * 1024 * 1024 (10MB)
    let malicious_key_len: u32 = 10 * 1024 * 1024 + 1;
    let val_len: u32 = 10;

    file.write_u32(malicious_key_len).await.unwrap();
    file.write_u32(val_len).await.unwrap();
    file.sync_all().await.unwrap();

    let table = SSTable { path };
    let out_temp = NamedTempFile::new().unwrap();

    let result = SSTable::compact(&[table], out_temp.path().to_path_buf()).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
}
