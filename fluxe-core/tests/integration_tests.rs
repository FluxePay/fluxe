//! Integration tests for FLUXE cross-chain functionality.
//!
//! This file includes all end-to-end cross-chain tests:
//! - Basic cross-chain deposits and withdrawals
//! - Parallel multi-chain deposits
//! - Supply imbalance detection
//! - Fee collection and withdrawal

mod integration;

// Re-export tests to make them discoverable
pub use integration::*;
