/// Strict storage limits to prevent OOM deadlocks during extreme workload spikes.

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
