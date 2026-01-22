//! Block store trait and implementations
//!
//! Provides an abstraction over block storage with both in-memory
//! and persistent (RocksDB) implementations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::types::{BlockHeader, ChainId, StateRoots, Time};
use super::error::StorageError;
use super::schema::*;

/// Configuration for the block store
#[derive(Clone, Debug)]
pub struct BlockStoreConfig {
    /// Path to the database directory
    pub db_path: PathBuf,

    /// Whether to create the database if it doesn't exist
    pub create_if_missing: bool,

    /// Maximum number of blocks to keep in memory cache
    pub cache_size: usize,

    /// Interval for creating state snapshots (in blocks)
    pub snapshot_interval: u64,

    /// Whether to enable compression
    pub compression: bool,
}

impl Default for BlockStoreConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("./fluxe-data"),
            create_if_missing: true,
            cache_size: 1000,
            snapshot_interval: 100,
            compression: true,
        }
    }
}

/// Block store trait for block persistence operations
pub trait BlockStore: Send + Sync {
    /// Initialize the store (create tables, load metadata, etc.)
    fn init(&self) -> Result<(), StorageError>;

    /// Store a finalized block
    fn store_block(&self, block: &StoredBlock) -> Result<(), StorageError>;

    /// Get a block by batch ID
    fn get_block(&self, batch_id: u64) -> Result<Option<StoredBlock>, StorageError>;

    /// Get the last finalized batch ID
    fn last_finalized_batch(&self) -> Result<u64, StorageError>;

    /// Get blocks in a range (inclusive)
    fn get_blocks_range(
        &self,
        start_batch: u64,
        end_batch: u64,
    ) -> Result<Vec<StoredBlock>, StorageError>;

    /// Store chain finality status
    fn store_chain_status(&self, status: &ChainFinalityStatus) -> Result<(), StorageError>;

    /// Get chain finality status
    fn get_chain_status(&self, chain_id: ChainId) -> Result<Option<ChainFinalityStatus>, StorageError>;

    /// Store a state snapshot
    fn store_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), StorageError>;

    /// Get the latest state snapshot
    fn get_latest_snapshot(&self) -> Result<Option<StateSnapshot>, StorageError>;

    /// Get a snapshot by batch ID (or the nearest earlier snapshot)
    fn get_snapshot(&self, batch_id: u64) -> Result<Option<StateSnapshot>, StorageError>;

    /// Store an ingress record
    fn store_ingress(&self, record: &IngressRecord) -> Result<(), StorageError>;

    /// Get an ingress record by hash
    fn get_ingress_by_hash(&self, hash: &[u8; 32]) -> Result<Option<IngressRecord>, StorageError>;

    /// Store an exit record
    fn store_exit(&self, record: &ExitRecord) -> Result<(), StorageError>;

    /// Get an exit record by hash
    fn get_exit_by_hash(&self, hash: &[u8; 32]) -> Result<Option<ExitRecord>, StorageError>;

    /// Get pending (unclaimed) exits for a chain
    fn get_pending_exits(&self, chain_id: ChainId) -> Result<Vec<ExitRecord>, StorageError>;

    /// Mark an exit as claimed
    fn mark_exit_claimed(
        &self,
        hash: &[u8; 32],
        claim_tx: [u8; 32],
    ) -> Result<(), StorageError>;

    /// Get storage metadata
    fn get_metadata(&self) -> Result<StorageMetadata, StorageError>;

    /// Compact the database (optional, noop for in-memory)
    fn compact(&self) -> Result<(), StorageError> {
        Ok(())
    }

    /// Flush any pending writes
    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

/// In-memory block store for testing
pub struct MemoryBlockStore {
    blocks: RwLock<HashMap<u64, StoredBlock>>,
    chain_status: RwLock<HashMap<ChainId, ChainFinalityStatus>>,
    snapshots: RwLock<HashMap<u64, StateSnapshot>>,
    ingress: RwLock<HashMap<[u8; 32], IngressRecord>>,
    exits: RwLock<HashMap<[u8; 32], ExitRecord>>,
    metadata: RwLock<StorageMetadata>,
}

impl MemoryBlockStore {
    /// Create a new in-memory block store
    pub fn new() -> Self {
        Self {
            blocks: RwLock::new(HashMap::new()),
            chain_status: RwLock::new(HashMap::new()),
            snapshots: RwLock::new(HashMap::new()),
            ingress: RwLock::new(HashMap::new()),
            exits: RwLock::new(HashMap::new()),
            metadata: RwLock::new(StorageMetadata::default()),
        }
    }
}

impl Default for MemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore for MemoryBlockStore {
    fn init(&self) -> Result<(), StorageError> {
        let mut meta = self.metadata.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        meta.created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(())
    }

    fn store_block(&self, block: &StoredBlock) -> Result<(), StorageError> {
        let mut blocks = self.blocks.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;

        // Check for duplicate
        if blocks.contains_key(&block.batch_id) {
            return Err(StorageError::BlockExists(block.batch_id));
        }

        // Check sequence
        let mut meta = self.metadata.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;

        if block.batch_id != meta.last_finalized_batch + 1 && meta.last_finalized_batch > 0 {
            return Err(StorageError::InvalidBatchId {
                expected: meta.last_finalized_batch + 1,
                got: block.batch_id,
            });
        }

        blocks.insert(block.batch_id, block.clone());
        meta.last_finalized_batch = block.batch_id;
        meta.total_blocks += 1;
        meta.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }

    fn get_block(&self, batch_id: u64) -> Result<Option<StoredBlock>, StorageError> {
        let blocks = self.blocks.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        Ok(blocks.get(&batch_id).cloned())
    }

    fn last_finalized_batch(&self) -> Result<u64, StorageError> {
        let meta = self.metadata.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        Ok(meta.last_finalized_batch)
    }

    fn get_blocks_range(
        &self,
        start_batch: u64,
        end_batch: u64,
    ) -> Result<Vec<StoredBlock>, StorageError> {
        let blocks = self.blocks.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;

        let mut result = Vec::new();
        for batch_id in start_batch..=end_batch {
            if let Some(block) = blocks.get(&batch_id) {
                result.push(block.clone());
            }
        }
        Ok(result)
    }

    fn store_chain_status(&self, status: &ChainFinalityStatus) -> Result<(), StorageError> {
        let mut chain_status = self.chain_status.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        chain_status.insert(status.chain_id, status.clone());

        // Update metadata with chain ID
        let mut meta = self.metadata.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        if !meta.chain_ids.contains(&status.chain_id) {
            meta.chain_ids.push(status.chain_id);
        }

        Ok(())
    }

    fn get_chain_status(&self, chain_id: ChainId) -> Result<Option<ChainFinalityStatus>, StorageError> {
        let chain_status = self.chain_status.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        Ok(chain_status.get(&chain_id).cloned())
    }

    fn store_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), StorageError> {
        let mut snapshots = self.snapshots.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        snapshots.insert(snapshot.batch_id, snapshot.clone());
        Ok(())
    }

    fn get_latest_snapshot(&self) -> Result<Option<StateSnapshot>, StorageError> {
        let snapshots = self.snapshots.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;

        if snapshots.is_empty() {
            return Ok(None);
        }

        let max_batch = *snapshots.keys().max().unwrap();
        Ok(snapshots.get(&max_batch).cloned())
    }

    fn get_snapshot(&self, batch_id: u64) -> Result<Option<StateSnapshot>, StorageError> {
        let snapshots = self.snapshots.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;

        // Find exact match or nearest earlier snapshot
        if let Some(snapshot) = snapshots.get(&batch_id) {
            return Ok(Some(snapshot.clone()));
        }

        // Find nearest earlier
        let earlier: Vec<_> = snapshots.keys().filter(|&&k| k < batch_id).collect();
        if let Some(&&nearest) = earlier.iter().max() {
            return Ok(snapshots.get(&nearest).cloned());
        }

        Ok(None)
    }

    fn store_ingress(&self, record: &IngressRecord) -> Result<(), StorageError> {
        let mut ingress = self.ingress.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        ingress.insert(record.hash, record.clone());
        Ok(())
    }

    fn get_ingress_by_hash(&self, hash: &[u8; 32]) -> Result<Option<IngressRecord>, StorageError> {
        let ingress = self.ingress.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        Ok(ingress.get(hash).cloned())
    }

    fn store_exit(&self, record: &ExitRecord) -> Result<(), StorageError> {
        let mut exits = self.exits.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        exits.insert(record.hash, record.clone());
        Ok(())
    }

    fn get_exit_by_hash(&self, hash: &[u8; 32]) -> Result<Option<ExitRecord>, StorageError> {
        let exits = self.exits.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        Ok(exits.get(hash).cloned())
    }

    fn get_pending_exits(&self, chain_id: ChainId) -> Result<Vec<ExitRecord>, StorageError> {
        let exits = self.exits.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;

        let pending: Vec<_> = exits.values()
            .filter(|e| e.dest_chain == chain_id && !e.claimed)
            .cloned()
            .collect();

        Ok(pending)
    }

    fn mark_exit_claimed(
        &self,
        hash: &[u8; 32],
        claim_tx: [u8; 32],
    ) -> Result<(), StorageError> {
        let mut exits = self.exits.write().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;

        if let Some(exit) = exits.get_mut(hash) {
            exit.claimed = true;
            exit.claim_tx = Some(claim_tx);
            Ok(())
        } else {
            Err(StorageError::BlockNotFound(0)) // Exit not found
        }
    }

    fn get_metadata(&self) -> Result<StorageMetadata, StorageError> {
        let meta = self.metadata.read().map_err(|e| {
            StorageError::Database(format!("Lock error: {}", e))
        })?;
        Ok(meta.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_memory_store_init() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        let meta = store.get_metadata().unwrap();
        assert_eq!(meta.last_finalized_batch, 0);
        assert_eq!(meta.total_blocks, 0);
    }

    #[test]
    fn test_store_and_get_block() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        let block = create_test_block(1);
        store.store_block(&block).unwrap();

        let retrieved = store.get_block(1).unwrap().unwrap();
        assert_eq!(retrieved.batch_id, 1);
        assert_eq!(retrieved.tx_count, 10);
    }

    #[test]
    fn test_sequential_blocks() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        // Store blocks 1, 2, 3
        for i in 1..=3 {
            let block = create_test_block(i);
            store.store_block(&block).unwrap();
        }

        assert_eq!(store.last_finalized_batch().unwrap(), 3);

        // Try to store block 5 (skipping 4) - should fail
        let block5 = create_test_block(5);
        let result = store.store_block(&block5);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_blocks_range() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        for i in 1..=5 {
            let block = create_test_block(i);
            store.store_block(&block).unwrap();
        }

        let range = store.get_blocks_range(2, 4).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].batch_id, 2);
        assert_eq!(range[2].batch_id, 4);
    }

    #[test]
    fn test_chain_status() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        let status = ChainFinalityStatus {
            chain_id: 1,
            last_submitted_batch: 10,
            last_confirmed_batch: 8,
            last_confirmation_block: 1000,
            last_confirmation_tx: [0u8; 32],
            last_update: 12345,
        };

        store.store_chain_status(&status).unwrap();

        let retrieved = store.get_chain_status(1).unwrap().unwrap();
        assert_eq!(retrieved.last_submitted_batch, 10);
        assert_eq!(retrieved.last_confirmed_batch, 8);
    }

    #[test]
    fn test_snapshots() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        let snapshot = StateSnapshot {
            batch_id: 100,
            global_roots: vec![1, 2, 3],
            chain_roots: vec![(1, vec![4, 5, 6])],
            chain_supplies: vec![],
            created_at: 12345,
        };

        store.store_snapshot(&snapshot).unwrap();

        let latest = store.get_latest_snapshot().unwrap().unwrap();
        assert_eq!(latest.batch_id, 100);

        // Get by batch ID
        let by_id = store.get_snapshot(100).unwrap().unwrap();
        assert_eq!(by_id.batch_id, 100);

        // Get earlier snapshot
        let earlier = store.get_snapshot(150).unwrap().unwrap();
        assert_eq!(earlier.batch_id, 100);
    }

    #[test]
    fn test_ingress_records() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        let record = IngressRecord {
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

        store.store_ingress(&record).unwrap();

        let retrieved = store.get_ingress_by_hash(&[1u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved.amount, 1000000);
    }

    #[test]
    fn test_exit_records() {
        let store = MemoryBlockStore::new();
        store.init().unwrap();

        let record = ExitRecord {
            hash: [1u8; 32],
            dest_chain: 501,
            asset_type: 1,
            amount: 500000,
            recipient: vec![4u8; 32],
            nonce: 0,
            created_batch: 1,
            claimed: false,
            claim_tx: None,
            timestamp: 12345,
        };

        store.store_exit(&record).unwrap();

        // Check pending exits
        let pending = store.get_pending_exits(501).unwrap();
        assert_eq!(pending.len(), 1);

        // Mark as claimed
        store.mark_exit_claimed(&[1u8; 32], [5u8; 32]).unwrap();

        // Check no more pending
        let pending = store.get_pending_exits(501).unwrap();
        assert_eq!(pending.len(), 0);

        // Verify claimed
        let retrieved = store.get_exit_by_hash(&[1u8; 32]).unwrap().unwrap();
        assert!(retrieved.claimed);
        assert_eq!(retrieved.claim_tx, Some([5u8; 32]));
    }
}
