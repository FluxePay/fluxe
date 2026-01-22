//! Block and state persistence module
//!
//! This module provides persistent storage for FLUXE blocks, state snapshots,
//! and finality tracking using RocksDB as the backend.

mod block_store;
mod error;
mod schema;

#[cfg(feature = "persistence")]
mod rocks_backend;

pub use block_store::{BlockStore, BlockStoreConfig};
pub use error::StorageError;
pub use schema::*;

#[cfg(feature = "persistence")]
pub use rocks_backend::RocksBlockStore;

/// In-memory block store for testing
pub use block_store::MemoryBlockStore;
