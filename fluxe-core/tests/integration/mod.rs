//! Integration tests for FLUXE cross-chain functionality.
//!
//! These tests verify end-to-end cross-chain flows including:
//! - Basic cross-chain deposits and withdrawals
//! - Parallel multi-chain deposits
//! - Supply imbalance detection
//! - Fee collection and withdrawal

pub mod test_utils;
pub mod e2e_cross_chain;
pub mod e2e_parallel_deposits;
pub mod e2e_supply_imbalance;
pub mod e2e_fees;
