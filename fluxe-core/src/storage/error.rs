//! Storage error types

use thiserror::Error;

/// Errors that can occur during storage operations
#[derive(Error, Debug)]
pub enum StorageError {
    /// Block not found in storage
    #[error("Block not found: batch_id={0}")]
    BlockNotFound(u64),

    /// Chain not found in storage
    #[error("Chain not found: chain_id={0}")]
    ChainNotFound(u32),

    /// State snapshot not found
    #[error("State snapshot not found: batch_id={0}")]
    SnapshotNotFound(u64),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid batch ID sequence
    #[error("Invalid batch ID: expected {expected}, got {got}")]
    InvalidBatchId { expected: u64, got: u64 },

    /// Block already exists
    #[error("Block already exists: batch_id={0}")]
    BlockExists(u64),

    /// Storage not initialized
    #[error("Storage not initialized")]
    NotInitialized,

    /// Corrupted data
    #[error("Corrupted data: {0}")]
    Corrupted(String),
}

impl From<bincode::Error> for StorageError {
    fn from(e: bincode::Error) -> Self {
        StorageError::Serialization(e.to_string())
    }
}

#[cfg(feature = "persistence")]
impl From<rocksdb::Error> for StorageError {
    fn from(e: rocksdb::Error) -> Self {
        StorageError::Database(e.to_string())
    }
}
