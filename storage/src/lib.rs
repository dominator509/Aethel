#![forbid(unsafe_code)]

use bytes::Bytes;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

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
    current_size: u64,
    base_dir: PathBuf,
    file_index: u32,
}

impl Wal {
    pub async fn new(base_dir: PathBuf) -> std::io::Result<Self> {
        tokio::fs::create_dir_all(&base_dir).await?;

        let mut wal_path = base_dir.clone();
        wal_path.push("wal_0.log");

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .await?;

        let metadata = file.metadata().await?;

        Ok(Self {
            file,
            current_size: metadata.len(),
            base_dir,
            file_index: 0,
        })
    }

    async fn rotate(&mut self) -> std::io::Result<()> {
        self.file.sync_all().await?;
        self.file_index += 1;

        let mut wal_path = self.base_dir.clone();
        wal_path.push(format!("wal_{}.log", self.file_index));

        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .await?;

        self.current_size = 0;
        Ok(())
    }

    pub async fn append(&mut self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        let entry_size = (8 + key.len() + value.len()) as u64;

        if self.current_size + entry_size >= MAX_WAL_SIZE {
            self.rotate().await?;
        }

        let key_len = key.len() as u32;
        let val_len = value.len() as u32;

        self.file.write_u32(key_len).await?;
        self.file.write_u32(val_len).await?;
        self.file.write_all(key).await?;
        self.file.write_all(value).await?;
        self.current_size += entry_size;

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
                "MemTable is at capacity and requires an SSTable flush before accepting new writes",
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
        let engine = StorageEngine::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();

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

#[tokio::test]
async fn test_internal_memtable_state_mutation() {
    let mut memtable = MemTable::new();
    let key = Bytes::from("internal_key");
    let val = Bytes::from("internal_val");

    // State Initialization
    assert!(memtable.map.is_empty());

    // State Mutation
    memtable.insert(key.clone(), val.clone());
    assert_eq!(memtable.map.len(), 1);

    // Edge Case Injection: Overwriting existing keys
    let new_val = Bytes::from("new_internal_val");
    memtable.insert(key.clone(), new_val.clone());

    // Internal state length shouldn't grow, value should be updated
    assert_eq!(memtable.map.len(), 1);
    assert_eq!(memtable.map.get(&key), Some(&new_val));
}
