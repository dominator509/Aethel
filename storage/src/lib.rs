#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::Bytes;

/// Basic entry in the Write-Ahead Log and MemTable
pub const MAX_WAL_SIZE: u64 = 64 * 1024 * 1024; // 64MB
pub const MAX_MEMTABLE_SIZE: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: Bytes,
    pub value: Bytes,
}

/// An extremely simplified Write-Ahead Log (WAL) to ensure durability
pub struct Wal {
    file: File,
}

impl Wal {
    pub async fn new(path: PathBuf) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self { file })
    }

    /// Appends a key-value pair to the WAL.
    /// In a production system, this would be heavily optimized with buffering,
    /// batching, and `fsync` grouping to achieve 3M TPS.
    pub async fn append(&mut self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        // Anti-Exhaustion: Ensure the WAL does not grow infinitely and consume the entire disk
        let metadata = self.file.metadata().await?;
        if metadata.len() >= MAX_WAL_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "WAL has reached maximum capacity and requires rotation"
            ));
        }

        let key_len = key.len() as u32;
        let val_len = value.len() as u32;

        // Write lengths and data sequentially
        self.file.write_u32(key_len).await?;
        self.file.write_u32(val_len).await?;
        self.file.write_all(key).await?;
        self.file.write_all(value).await?;

        // For maximum safety, we sync all data immediately.
        // NOTE: Doing this per-transaction physically prevents 3M TPS on standard hardware.
        // This must be batched in a full implementation.
        self.file.sync_data().await?;
        Ok(())
    }
}

/// MemTable acts as the fast, in-memory component of the LSM tree
pub struct MemTable {
    map: BTreeMap<Bytes, Bytes>,
}

impl Default for MemTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MemTable {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: Bytes, value: Bytes) {
        self.map.insert(key, value);
    }

    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.map.get(key).cloned()
    }
}

/// The high-level Storage Engine combining WAL and MemTable
pub struct StorageEngine {
    wal: Arc<RwLock<Wal>>,
    memtable: Arc<RwLock<MemTable>>,
}

impl StorageEngine {
    pub async fn new(base_dir: PathBuf) -> std::io::Result<Self> {
        // Create the base directory if it doesn't exist
        tokio::fs::create_dir_all(&base_dir).await?;

        let mut wal_path = base_dir.clone();
        wal_path.push("wal.log");

        let wal = Wal::new(wal_path).await?;
        let memtable = MemTable::new();

        // In a real system, you would replay the WAL here to populate the MemTable

        Ok(Self {
            wal: Arc::new(RwLock::new(wal)),
            memtable: Arc::new(RwLock::new(memtable)),
        })
    }

    /// Fast write path: Append to WAL, then insert into MemTable
    pub async fn put(&self, key: Bytes, value: Bytes) -> std::io::Result<()> {
        let mut memtable = self.memtable.write().await;
        if memtable.map.len() >= MAX_MEMTABLE_SIZE {
            // Anti-Exhaustion: Apply backpressure and prevent OOM if the MemTable is full
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "MemTable is at capacity and requires an SSTable flush before accepting new writes"
            ));
        }

        let mut wal = self.wal.write().await;
        wal.append(&key, &value).await?;
        drop(wal); // Drop lock early

        memtable.insert(key, value);

        Ok(())
    }

    /// Fast read path: Check MemTable.
    /// (SSTable lookups would be added here if MemTable misses)
    pub async fn get(&self, key: &[u8]) -> Option<Bytes> {
        let memtable = self.memtable.read().await;
        memtable.get(key)
    }

    /// Safely flushes the current MemTable to an SSTable on disk and clears it.
    pub async fn flush_to_disk(&self, base_dir: &std::path::Path) -> std::io::Result<()> {
        let mut sstable_dir = base_dir.to_path_buf();
        sstable_dir.push("sstables");
        tokio::fs::create_dir_all(&sstable_dir).await?;
        let mut memtable = self.memtable.write().await;

        if memtable.map.is_empty() {
            return Ok(());
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let mut path = sstable_dir.to_path_buf();
        path.push(format!("sstable_{}.sst", timestamp));

        // Flush using the SSTable module logic
        sstable::SSTable::flush_memtable(&memtable.map, path).await?;

        // Clear the in-memory map to free capacity
        memtable.map.clear();

        // In a full implementation, you would also truncate/cycle the WAL here
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_engine_put_and_get() {
        let temp_dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::new(temp_dir.path().to_path_buf()).await.unwrap();

        let key = Bytes::from("tx_123");
        let value = Bytes::from("tx_data_payload");

        // Put data
        engine.put(key.clone(), value.clone()).await.unwrap();

        // Get data
        let retrieved = engine.get(&key).await;
        assert_eq!(retrieved, Some(value));

        // Get non-existent data
        let missing = engine.get(b"missing_key").await;
        assert_eq!(missing, None);
    }
}
pub mod sstable;
