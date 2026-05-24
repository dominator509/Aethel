use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, RwLock};

// Strict storage limits to prevent OOM deadlocks during extreme workload spikes.

// 64 MB
pub const MAX_WAL_SIZE: usize = 64 * 1024 * 1024;

// 1 Million Keys maximum in memory before forced flush
pub const MAX_MEMTABLE_SIZE: usize = 1_000_000;

// Hard cap on keys per SSTable compaction cycle
pub const MAX_COMPACTION_KEYS: usize = 500_000;

// Maximum size for a single block allocation
pub const MAX_ALLOCATION_SIZE_BYTES: usize = 10 * 1024 * 1024; // 10MB

pub struct StorageEngineConfig {
    pub max_wal_size: usize,
    pub max_memtable_size: usize,
    pub max_compaction_keys: usize,
    pub max_allocation_size_bytes: usize,
}

impl Default for StorageEngineConfig {
    fn default() -> Self {
        Self {
            max_wal_size: MAX_WAL_SIZE,
            max_memtable_size: MAX_MEMTABLE_SIZE,
            max_compaction_keys: MAX_COMPACTION_KEYS,
            max_allocation_size_bytes: MAX_ALLOCATION_SIZE_BYTES,
        }
    }
}

pub mod sstable;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub key: Bytes,
    pub value: Option<Bytes>,
    pub timestamp: u64,
}

pub struct LSMTree {
    memtable: Arc<RwLock<BTreeMap<Bytes, Operation>>>,
    wal_file: Arc<Mutex<File>>,
    config: StorageEngineConfig,
    data_dir: PathBuf,
}

impl LSMTree {
    pub async fn new(data_dir: PathBuf, config: StorageEngineConfig) -> std::io::Result<Self> {
        let wal_path = data_dir.join("wal.log");
        let wal_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .await?;

        Ok(Self {
            memtable: Arc::new(RwLock::new(BTreeMap::new())),
            wal_file: Arc::new(Mutex::new(wal_file)),
            config,
            data_dir,
        })
    }

    pub async fn put(&self, key: Bytes, value: Bytes, timestamp: u64) -> std::io::Result<()> {
        let op = Operation {
            key: key.clone(),
            value: Some(value),
            timestamp,
        };

        // Write to WAL
        let op_bytes = bincode::serialize(&op)
            .map_err(std::io::Error::other)?;
        let mut wal = self.wal_file.lock().await;
        wal.write_all(&(op_bytes.len() as u32).to_le_bytes())
            .await?;
        wal.write_all(&op_bytes).await?;
        wal.flush().await?;
        drop(wal);

        // Write to MemTable
        let mut memtable = self.memtable.write().await;
        memtable.insert(key, op);

        if memtable.len() >= self.config.max_memtable_size {
            // Initiate flush
            // In a real implementation, this would spawn a background task
            self.flush_memtable(&mut memtable).await?;
        }

        Ok(())
    }

    pub async fn get(&self, key: &Bytes) -> std::io::Result<Option<Bytes>> {
        let memtable = self.memtable.read().await;
        if let Some(op) = memtable.get(key) {
            return Ok(op.value.clone());
        }

        // In a real implementation, search SSTables here
        Ok(None)
    }

    async fn flush_memtable(
        &self,
        memtable: &mut BTreeMap<Bytes, Operation>,
    ) -> std::io::Result<()> {
        if memtable.is_empty() {
            return Ok(());
        }

        // 1. Create SSTable from memtable
        // 2. Clear memtable
        memtable.clear();

        // 3. Truncate WAL
        let wal_path = self.data_dir.join("wal.log");
        let new_wal = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&wal_path)
            .await?;

        let mut wal = self.wal_file.lock().await;
        *wal = new_wal;

        Ok(())
    }
}
