//! Fee collection and distribution for FLUXE protocol
//!
//! This module provides fee management functionality including:
//! - Fee configuration with static and dynamic pricing
//! - Fee collection per chain and asset
//! - Fee withdrawal via ExitReceipts for sequencer

pub mod collector;
pub mod config;

pub use collector::{FeeCollector, FeeWithdrawalResult};
pub use config::{FeeConfig, TransactionFeeType};

#[cfg(test)]
mod tests;
