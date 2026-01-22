//! Storage schema definitions
//!
//! Defines the data structures stored in the database.

use serde::{Deserialize, Serialize};
use crate::types::{Amount, AssetType, ChainId, Time};

/// Stored block record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredBlock {
    /// Sequential batch identifier
    pub batch_id: u64,

    /// Previous state roots hash (32 bytes)
    pub prev_roots_hash: [u8; 32],

    /// New state roots hash (32 bytes)
    pub new_roots_hash: [u8; 32],

    /// Serialized previous state roots
    pub prev_roots: Vec<u8>,

    /// Serialized new state roots
    pub new_roots: Vec<u8>,

    /// Aggregated proof bytes
    pub agg_proof: Vec<u8>,

    /// Block timestamp
    pub timestamp: Time,

    /// Transaction count in this batch
    pub tx_count: u32,

    /// Per-chain transaction counts
    pub chain_tx_counts: Vec<(ChainId, u32)>,
}

/// Per-chain finality status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainFinalityStatus {
    /// Chain identifier
    pub chain_id: ChainId,

    /// Last batch ID submitted to L1
    pub last_submitted_batch: u64,

    /// Last batch ID confirmed on L1
    pub last_confirmed_batch: u64,

    /// L1 block number of last confirmation
    pub last_confirmation_block: u64,

    /// L1 transaction hash of last confirmation
    pub last_confirmation_tx: [u8; 32],

    /// Timestamp of last update
    pub last_update: Time,
}

/// Global metadata stored in the database
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageMetadata {
    /// Storage schema version for migrations
    pub schema_version: u32,

    /// Last finalized batch ID
    pub last_finalized_batch: u64,

    /// Total number of stored blocks
    pub total_blocks: u64,

    /// Database creation time
    pub created_at: Time,

    /// Last modification time
    pub updated_at: Time,

    /// Registered chain IDs
    pub chain_ids: Vec<ChainId>,
}

impl Default for StorageMetadata {
    fn default() -> Self {
        Self {
            schema_version: 1,
            last_finalized_batch: 0,
            total_blocks: 0,
            created_at: 0,
            updated_at: 0,
            chain_ids: vec![],
        }
    }
}

/// State snapshot for a batch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Batch ID this snapshot corresponds to
    pub batch_id: u64,

    /// Serialized global state roots
    pub global_roots: Vec<u8>,

    /// Per-chain state roots (chain_id -> serialized roots)
    pub chain_roots: Vec<(ChainId, Vec<u8>)>,

    /// Per-chain supply tracking (chain_id -> asset_type -> supply)
    pub chain_supplies: Vec<(ChainId, Vec<(AssetType, SupplySnapshot)>)>,

    /// Snapshot creation time
    pub created_at: Time,
}

/// Supply snapshot for an asset
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupplySnapshot {
    /// Asset type
    pub asset_type: AssetType,

    /// Total deposited amount
    pub deposited: u64,

    /// Total withdrawn amount
    pub withdrawn: u64,
}

impl SupplySnapshot {
    /// Current supply (deposited - withdrawn)
    pub fn current(&self) -> i64 {
        self.deposited as i64 - self.withdrawn as i64
    }
}

/// Ingress receipt record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressRecord {
    /// Receipt hash
    pub hash: [u8; 32],

    /// Source chain ID
    pub source_chain: ChainId,

    /// Asset type
    pub asset_type: AssetType,

    /// Amount deposited
    pub amount: u64,

    /// Beneficiary commitment (32 bytes)
    pub beneficiary_cm: [u8; 32],

    /// Deposit nonce
    pub nonce: u64,

    /// Block number on source chain
    pub source_block: u64,

    /// Transaction hash on source chain
    pub source_tx: [u8; 32],

    /// Batch ID where this was included
    pub included_batch: u64,

    /// Timestamp
    pub timestamp: Time,
}

/// Exit receipt record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitRecord {
    /// Receipt hash
    pub hash: [u8; 32],

    /// Destination chain ID
    pub dest_chain: ChainId,

    /// Asset type
    pub asset_type: AssetType,

    /// Amount to withdraw
    pub amount: u64,

    /// Recipient address (for EVM: 20 bytes, for Solana: 32 bytes)
    pub recipient: Vec<u8>,

    /// Exit nonce
    pub nonce: u64,

    /// Batch ID where this exit was created
    pub created_batch: u64,

    /// Whether withdrawal has been claimed
    pub claimed: bool,

    /// Claim transaction hash (if claimed)
    pub claim_tx: Option<[u8; 32]>,

    /// Timestamp
    pub timestamp: Time,
}

/// Column family names for RocksDB
pub mod cf {
    /// Blocks column family
    pub const BLOCKS: &str = "blocks";

    /// Chain finality status
    pub const CHAIN_STATUS: &str = "chain_status";

    /// State snapshots
    pub const SNAPSHOTS: &str = "snapshots";

    /// Ingress records
    pub const INGRESS: &str = "ingress";

    /// Exit records
    pub const EXIT: &str = "exit";

    /// Metadata
    pub const METADATA: &str = "metadata";

    /// All column family names
    pub const ALL: &[&str] = &[BLOCKS, CHAIN_STATUS, SNAPSHOTS, INGRESS, EXIT, METADATA];
}

/// Key prefixes for organizing data
pub mod keys {
    use super::*;

    /// Block key: batch_id as big-endian bytes
    pub fn block_key(batch_id: u64) -> [u8; 8] {
        batch_id.to_be_bytes()
    }

    /// Chain status key
    pub fn chain_status_key(chain_id: ChainId) -> [u8; 4] {
        chain_id.to_be_bytes()
    }

    /// Snapshot key
    pub fn snapshot_key(batch_id: u64) -> [u8; 8] {
        batch_id.to_be_bytes()
    }

    /// Ingress key: chain_id + nonce
    pub fn ingress_key(chain_id: ChainId, nonce: u64) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[0..4].copy_from_slice(&chain_id.to_be_bytes());
        key[4..12].copy_from_slice(&nonce.to_be_bytes());
        key
    }

    /// Exit key: chain_id + nonce
    pub fn exit_key(chain_id: ChainId, nonce: u64) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[0..4].copy_from_slice(&chain_id.to_be_bytes());
        key[4..12].copy_from_slice(&nonce.to_be_bytes());
        key
    }

    /// Metadata key
    pub const METADATA: &[u8] = b"metadata";
}
