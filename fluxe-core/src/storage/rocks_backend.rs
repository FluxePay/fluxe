//! RocksDB-based persistent block store
//!
//! This module provides persistent storage using RocksDB.
//! Only available when the "persistence" feature is enabled.

use std::path::Path;
use std::sync::RwLock;

use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, DB};

use crate::types::ChainId;
use super::block_store::{BlockStore, BlockStoreConfig};
use super::error::StorageError;
use super::schema::*;

/// RocksDB-backed block store
pub struct RocksBlockStore {
    /// RocksDB instance
    db: DB,

    /// Configuration
    config: BlockStoreConfig,

    /// Cached metadata
    metadata_cache: RwLock<Option<StorageMetadata>>,
}

impl RocksBlockStore {
    /// Open or create a RocksDB block store
    pub fn open(config: BlockStoreConfig) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.create_missing_column_families(true);

        if config.compression {
            opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        }

        // Set up column families
        let cf_descriptors: Vec<_> = cf::ALL.iter()
            .map(|name| {
                let cf_opts = Options::default();
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&opts, &config.db_path, cf_descriptors)?;

        Ok(Self {
            db,
            config,
            metadata_cache: RwLock::new(None),
        })
    }

    /// Get a column family handle
    fn cf(&self, name: &str) -> Result<&ColumnFamily, StorageError> {
        self.db.cf_handle(name)
            .ok_or_else(|| StorageError::Database(format!("Column family not found: {}", name)))
    }

    /// Serialize a value using bincode
    fn serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, StorageError> {
        bincode::serialize(value).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Deserialize a value using bincode
    fn deserialize<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, StorageError> {
        bincode::deserialize(data).map_err(|e| StorageError::Deserialization(e.to_string()))
    }

    /// Update cached metadata
    fn update_metadata_cache(&self, meta: StorageMetadata) -> Result<(), StorageError> {
        let mut cache = self.metadata_cache.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        *cache = Some(meta);
        Ok(())
    }
}

impl BlockStore for RocksBlockStore {
    fn init(&self) -> Result<(), StorageError> {
        // Check if metadata exists
        let cf = self.cf(cf::METADATA)?;

        match self.db.get_cf(cf, keys::METADATA)? {
            Some(data) => {
                // Load existing metadata
                let meta: StorageMetadata = Self::deserialize(&data)?;
                self.update_metadata_cache(meta)?;
            }
            None => {
                // Create new metadata
                let meta = StorageMetadata {
                    schema_version: 1,
                    last_finalized_batch: 0,
                    total_blocks: 0,
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    updated_at: 0,
                    chain_ids: vec![],
                };

                let data = Self::serialize(&meta)?;
                self.db.put_cf(cf, keys::METADATA, &data)?;
                self.update_metadata_cache(meta)?;
            }
        }

        Ok(())
    }

    fn store_block(&self, block: &StoredBlock) -> Result<(), StorageError> {
        let cf_blocks = self.cf(cf::BLOCKS)?;
        let cf_meta = self.cf(cf::METADATA)?;

        // Get current metadata
        let mut meta = self.get_metadata()?;

        // Validate sequence
        if block.batch_id != meta.last_finalized_batch + 1 && meta.last_finalized_batch > 0 {
            return Err(StorageError::InvalidBatchId {
                expected: meta.last_finalized_batch + 1,
                got: block.batch_id,
            });
        }

        // Check for duplicate
        let key = keys::block_key(block.batch_id);
        if self.db.get_cf(cf_blocks, &key)?.is_some() {
            return Err(StorageError::BlockExists(block.batch_id));
        }

        // Store block
        let data = Self::serialize(block)?;
        self.db.put_cf(cf_blocks, &key, &data)?;

        // Update metadata
        meta.last_finalized_batch = block.batch_id;
        meta.total_blocks += 1;
        meta.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let meta_data = Self::serialize(&meta)?;
        self.db.put_cf(cf_meta, keys::METADATA, &meta_data)?;
        self.update_metadata_cache(meta)?;

        Ok(())
    }

    fn get_block(&self, batch_id: u64) -> Result<Option<StoredBlock>, StorageError> {
        let cf = self.cf(cf::BLOCKS)?;
        let key = keys::block_key(batch_id);

        match self.db.get_cf(cf, &key)? {
            Some(data) => {
                let block: StoredBlock = Self::deserialize(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    fn last_finalized_batch(&self) -> Result<u64, StorageError> {
        // Try cache first
        {
            let cache = self.metadata_cache.read().map_err(|e| {
                StorageError::Database(format!("Lock error: {}", e))
            })?;
            if let Some(ref meta) = *cache {
                return Ok(meta.last_finalized_batch);
            }
        }

        // Fall back to database
        let meta = self.get_metadata()?;
        Ok(meta.last_finalized_batch)
    }

    fn get_blocks_range(
        &self,
        start_batch: u64,
        end_batch: u64,
    ) -> Result<Vec<StoredBlock>, StorageError> {
        let cf = self.cf(cf::BLOCKS)?;
        let mut result = Vec::new();

        let start_key = keys::block_key(start_batch);
        let end_key = keys::block_key(end_batch + 1);

        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );

        for item in iter {
            let (key, value) = item?;

            // Stop if past end key
            if key.as_ref() >= end_key.as_slice() {
                break;
            }

            let block: StoredBlock = Self::deserialize(&value)?;
            result.push(block);
        }

        Ok(result)
    }

    fn store_chain_status(&self, status: &ChainFinalityStatus) -> Result<(), StorageError> {
        let cf = self.cf(cf::CHAIN_STATUS)?;
        let key = keys::chain_status_key(status.chain_id);
        let data = Self::serialize(status)?;
        self.db.put_cf(cf, &key, &data)?;

        // Update chain_ids in metadata
        let mut meta = self.get_metadata()?;
        if !meta.chain_ids.contains(&status.chain_id) {
            meta.chain_ids.push(status.chain_id);
            let cf_meta = self.cf(cf::METADATA)?;
            let meta_data = Self::serialize(&meta)?;
            self.db.put_cf(cf_meta, keys::METADATA, &meta_data)?;
            self.update_metadata_cache(meta)?;
        }

        Ok(())
    }

    fn get_chain_status(&self, chain_id: ChainId) -> Result<Option<ChainFinalityStatus>, StorageError> {
        let cf = self.cf(cf::CHAIN_STATUS)?;
        let key = keys::chain_status_key(chain_id);

        match self.db.get_cf(cf, &key)? {
            Some(data) => {
                let status: ChainFinalityStatus = Self::deserialize(&data)?;
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    fn store_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), StorageError> {
        let cf = self.cf(cf::SNAPSHOTS)?;
        let key = keys::snapshot_key(snapshot.batch_id);
        let data = Self::serialize(snapshot)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    fn get_latest_snapshot(&self) -> Result<Option<StateSnapshot>, StorageError> {
        let cf = self.cf(cf::SNAPSHOTS)?;

        // Iterate in reverse to find latest
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::End);

        for item in iter {
            let (_, value) = item?;
            let snapshot: StateSnapshot = Self::deserialize(&value)?;
            return Ok(Some(snapshot));
        }

        Ok(None)
    }

    fn get_snapshot(&self, batch_id: u64) -> Result<Option<StateSnapshot>, StorageError> {
        let cf = self.cf(cf::SNAPSHOTS)?;
        let key = keys::snapshot_key(batch_id);

        // Try exact match
        if let Some(data) = self.db.get_cf(cf, &key)? {
            let snapshot: StateSnapshot = Self::deserialize(&data)?;
            return Ok(Some(snapshot));
        }

        // Find nearest earlier
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&key, rocksdb::Direction::Reverse),
        );

        for item in iter {
            let (_, value) = item?;
            let snapshot: StateSnapshot = Self::deserialize(&value)?;
            if snapshot.batch_id <= batch_id {
                return Ok(Some(snapshot));
            }
        }

        Ok(None)
    }

    fn store_ingress(&self, record: &IngressRecord) -> Result<(), StorageError> {
        let cf = self.cf(cf::INGRESS)?;
        let data = Self::serialize(record)?;
        self.db.put_cf(cf, &record.hash, &data)?;
        Ok(())
    }

    fn get_ingress_by_hash(&self, hash: &[u8; 32]) -> Result<Option<IngressRecord>, StorageError> {
        let cf = self.cf(cf::INGRESS)?;

        match self.db.get_cf(cf, hash)? {
            Some(data) => {
                let record: IngressRecord = Self::deserialize(&data)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    fn store_exit(&self, record: &ExitRecord) -> Result<(), StorageError> {
        let cf = self.cf(cf::EXIT)?;
        let data = Self::serialize(record)?;
        self.db.put_cf(cf, &record.hash, &data)?;
        Ok(())
    }

    fn get_exit_by_hash(&self, hash: &[u8; 32]) -> Result<Option<ExitRecord>, StorageError> {
        let cf = self.cf(cf::EXIT)?;

        match self.db.get_cf(cf, hash)? {
            Some(data) => {
                let record: ExitRecord = Self::deserialize(&data)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    fn get_pending_exits(&self, chain_id: ChainId) -> Result<Vec<ExitRecord>, StorageError> {
        let cf = self.cf(cf::EXIT)?;
        let mut result = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item?;
            let record: ExitRecord = Self::deserialize(&value)?;
            if record.dest_chain == chain_id && !record.claimed {
                result.push(record);
            }
        }

        Ok(result)
    }

    fn mark_exit_claimed(
        &self,
        hash: &[u8; 32],
        claim_tx: [u8; 32],
    ) -> Result<(), StorageError> {
        let cf = self.cf(cf::EXIT)?;

        match self.db.get_cf(cf, hash)? {
            Some(data) => {
                let mut record: ExitRecord = Self::deserialize(&data)?;
                record.claimed = true;
                record.claim_tx = Some(claim_tx);

                let updated_data = Self::serialize(&record)?;
                self.db.put_cf(cf, hash, &updated_data)?;
                Ok(())
            }
            None => Err(StorageError::BlockNotFound(0)),
        }
    }

    fn get_metadata(&self) -> Result<StorageMetadata, StorageError> {
        // Try cache first
        {
            let cache = self.metadata_cache.read().map_err(|e| {
                StorageError::Database(format!("Lock error: {}", e))
            })?;
            if let Some(ref meta) = *cache {
                return Ok(meta.clone());
            }
        }

        // Fall back to database
        let cf = self.cf(cf::METADATA)?;
        match self.db.get_cf(cf, keys::METADATA)? {
            Some(data) => {
                let meta: StorageMetadata = Self::deserialize(&data)?;
                self.update_metadata_cache(meta.clone())?;
                Ok(meta)
            }
            None => Err(StorageError::NotInitialized),
        }
    }

    fn compact(&self) -> Result<(), StorageError> {
        for cf_name in cf::ALL {
            if let Some(cf) = self.db.cf_handle(cf_name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            }
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.db.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_config() -> BlockStoreConfig {
        let dir = tempdir().unwrap();
        BlockStoreConfig {
            db_path: dir.into_path(),
            create_if_missing: true,
            cache_size: 100,
            snapshot_interval: 10,
            compression: false,
        }
    }

    fn create_test_block(batch_id: u64) -> StoredBlock {
        StoredBlock {
            batch_id,
            prev_roots_hash: [0u8; 32],
            new_roots_hash: [1u8; 32],
            prev_roots: vec![0, 1, 2, 3],
            new_roots: vec![4, 5, 6, 7],
            agg_proof: vec![8, 9, 10],
            timestamp: 1000 + batch_id,
            tx_count: 10,
            chain_tx_counts: vec![(1, 5), (501, 5)],
        }
    }

    #[test]
    fn test_rocks_store_init() {
        let config = create_test_config();
        let store = RocksBlockStore::open(config).unwrap();
        store.init().unwrap();

        let meta = store.get_metadata().unwrap();
        assert_eq!(meta.last_finalized_batch, 0);
        assert_eq!(meta.schema_version, 1);
    }

    #[test]
    fn test_rocks_store_blocks() {
        let config = create_test_config();
        let store = RocksBlockStore::open(config).unwrap();
        store.init().unwrap();

        // Store blocks
        for i in 1..=5 {
            let block = create_test_block(i);
            store.store_block(&block).unwrap();
        }

        // Verify
        assert_eq!(store.last_finalized_batch().unwrap(), 5);

        let block = store.get_block(3).unwrap().unwrap();
        assert_eq!(block.batch_id, 3);
    }

    #[test]
    fn test_rocks_store_persistence() {
        let config = create_test_config();
        let db_path = config.db_path.clone();

        // Store some blocks
        {
            let store = RocksBlockStore::open(config.clone()).unwrap();
            store.init().unwrap();

            for i in 1..=3 {
                let block = create_test_block(i);
                store.store_block(&block).unwrap();
            }
            store.flush().unwrap();
        }

        // Reopen and verify
        {
            let config2 = BlockStoreConfig {
                db_path,
                ..config
            };
            let store = RocksBlockStore::open(config2).unwrap();
            store.init().unwrap();

            assert_eq!(store.last_finalized_batch().unwrap(), 3);
            assert!(store.get_block(2).unwrap().is_some());
        }
    }

    #[test]
    fn test_rocks_ingress_exit() {
        let config = create_test_config();
        let store = RocksBlockStore::open(config).unwrap();
        store.init().unwrap();

        // Store ingress
        let ingress = IngressRecord {
            hash: [1u8; 32],
            source_chain: 1,
            asset_type: 1,
            amount: 1000000,
            beneficiary_cm: [2u8; 32],
            nonce: 0,
            source_block: 100,
            source_tx: [3u8; 32],
            included_batch: 1,
            timestamp: 12345,
        };
        store.store_ingress(&ingress).unwrap();

        // Store exit
        let exit = ExitRecord {
            hash: [4u8; 32],
            dest_chain: 501,
            asset_type: 1,
            amount: 500000,
            recipient: vec![5u8; 32],
            nonce: 0,
            created_batch: 1,
            claimed: false,
            claim_tx: None,
            timestamp: 12345,
        };
        store.store_exit(&exit).unwrap();

        // Verify
        let retrieved_ingress = store.get_ingress_by_hash(&[1u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved_ingress.amount, 1000000);

        let pending = store.get_pending_exits(501).unwrap();
        assert_eq!(pending.len(), 1);

        store.mark_exit_claimed(&[4u8; 32], [6u8; 32]).unwrap();

        let pending = store.get_pending_exits(501).unwrap();
        assert_eq!(pending.len(), 0);
    }
}
