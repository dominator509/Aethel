#![forbid(unsafe_code)]

use bytes::Bytes;
use std::collections::BTreeMap;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::path::PathBuf;

/// An SSTable (Sorted String Table) represents immutable, flushed data on disk.
#[derive(Debug)]
pub struct SSTable {
    pub path: PathBuf,
}

const MAX_ALLOCATION_SIZE: u32 = 10 * 1024 * 1024; // 10MB
const MAX_KEYS_PER_COMPACTION: usize = 500_000;

impl SSTable {
    /// Flushes an in-memory MemTable (BTreeMap) to an SSTable on disk.
    pub async fn flush_memtable(memtable: &BTreeMap<Bytes, Bytes>, path: PathBuf) -> std::io::Result<Self> {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .await?;

        // SSTables are sorted by definition because BTreeMap is sorted
        for (key, value) in memtable.iter() {
            let key_len = key.len() as u32;
            let val_len = value.len() as u32;

            file.write_u32(key_len).await?;
            file.write_u32(val_len).await?;
            file.write_all(key).await?;
            file.write_all(value).await?;
        }

        file.sync_all().await?;
        Ok(Self { path })
    }

    /// Basic compaction: Merges multiple SSTables into a new one.
    /// In a real system, this runs in the background.
    pub async fn compact(tables: &[SSTable], out_path: PathBuf) -> std::io::Result<Self> {
        // Very simplified: read all, merge in memory, write out.
        // A real system uses an N-way merge algorithm to avoid OOM.
        let mut merged: BTreeMap<Bytes, Bytes> = BTreeMap::new();

        for table in tables {
            let mut file = File::open(&table.path).await?;

            loop {
                if merged.len() >= MAX_KEYS_PER_COMPACTION {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "Compaction aborted: Too many keys requested, potential OOM detected."
                    ));
                }

                let key_len = match file.read_u32().await {
                    Ok(len) => len,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                };
                let val_len = file.read_u32().await?;

                if key_len > MAX_ALLOCATION_SIZE || val_len > MAX_ALLOCATION_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Data chunk exceeds maximum safe allocation limit (Potential OOM DoS)"
                    ));
                }

                let mut key = vec![0u8; key_len as usize];
                file.read_exact(&mut key).await?;

                let mut value = vec![0u8; val_len as usize];
                file.read_exact(&mut value).await?;

                merged.insert(Bytes::from(key), Bytes::from(value));
            }
        }

        Self::flush_memtable(&merged, out_path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_sstable_flush_and_compact() {
        let mut memtable = BTreeMap::new();
        memtable.insert(Bytes::from("a"), Bytes::from("1"));
        memtable.insert(Bytes::from("b"), Bytes::from("2"));

        let temp1 = NamedTempFile::new().unwrap();
        let sstable1 = SSTable::flush_memtable(&memtable, temp1.path().to_path_buf()).await.unwrap();

        let mut memtable2 = BTreeMap::new();
        memtable2.insert(Bytes::from("b"), Bytes::from("3")); // Update 'b'
        memtable2.insert(Bytes::from("c"), Bytes::from("4"));

        let temp2 = NamedTempFile::new().unwrap();
        let sstable2 = SSTable::flush_memtable(&memtable2, temp2.path().to_path_buf()).await.unwrap();

        let out_temp = NamedTempFile::new().unwrap();
        let _compacted = SSTable::compact(&[sstable1, sstable2], out_temp.path().to_path_buf()).await.unwrap();

        // At this point, the compacted file should contain a, b(3), and c.
        // We verify the compaction ran without errors.
    }
    #[tokio::test]
    async fn test_internal_exception_max_allocation_size() {
        use tempfile::NamedTempFile;
        use tokio::io::AsyncWriteExt;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        // Construct a maliciously crafted SSTable file bypassing flush_memtable
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .unwrap();

        let malicious_key_len: u32 = MAX_ALLOCATION_SIZE + 1;
        let val_len: u32 = 10;

        file.write_u32(malicious_key_len).await.unwrap();
        file.write_u32(val_len).await.unwrap();
        // Don't actually write the data, we just want it to read the lengths and fail
        file.sync_all().await.unwrap();

        let table = SSTable { path };
        let out_temp = NamedTempFile::new().unwrap();

        // Attempt compaction. It should catch the malicious length and abort to prevent OOM
        let result = SSTable::compact(&[table], out_temp.path().to_path_buf()).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }
}
