//! Fee configuration for FLUXE protocol
//!
//! This module provides fee calculation configuration with support for:
//! - Base fees (minimum fee per transaction)
//! - Size-based fees (fee per byte)
//! - Dynamic pricing with min/max bounds
//! - Transaction type-specific fees

use crate::types::Amount;
use serde::{Deserialize, Serialize};

/// Transaction types for fee calculation
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionFeeType {
    /// Simple transfer between notes
    Transfer,
    /// Mint (deposit from external chain)
    Mint,
    /// Burn (withdrawal to external chain)
    Burn,
    /// Object creation/update
    ObjectUpdate,
    /// Callback execution
    Callback,
    /// Cross-chain transfer (higher fee due to complexity)
    CrossChain,
}

impl TransactionFeeType {
    /// Get the fee multiplier for this transaction type
    ///
    /// Base multiplier is 100 (representing 1.0x)
    /// Higher multipliers for more complex operations
    pub fn multiplier(&self) -> u64 {
        match self {
            TransactionFeeType::Transfer => 100,      // 1.0x
            TransactionFeeType::Mint => 150,          // 1.5x (involves external chain verification)
            TransactionFeeType::Burn => 150,          // 1.5x (involves exit receipt generation)
            TransactionFeeType::ObjectUpdate => 120,  // 1.2x (state updates)
            TransactionFeeType::Callback => 200,      // 2.0x (execution complexity)
            TransactionFeeType::CrossChain => 250,    // 2.5x (multi-chain coordination)
        }
    }
}

/// Fee configuration for the FLUXE protocol
///
/// Supports both static and dynamic fee pricing modes.
/// Fees are calculated as: max(min_fee, base_fee + fee_per_byte * tx_size) * type_multiplier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Minimum fee per transaction (in base units)
    pub base_fee: Amount,

    /// Fee per byte of transaction data (in base units)
    pub fee_per_byte: Amount,

    /// Enable dynamic pricing based on network congestion
    pub dynamic_pricing: bool,

    /// Floor for dynamic pricing (minimum possible fee)
    pub min_fee: Amount,

    /// Ceiling for dynamic pricing (maximum possible fee)
    pub max_fee: Amount,

    /// Current congestion multiplier (100 = 1.0x, updated dynamically)
    /// Only used when dynamic_pricing is enabled
    pub congestion_multiplier: u64,

    /// Target transactions per batch for congestion calculation
    pub target_batch_size: u64,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            base_fee: Amount::new(1000),           // 1000 base units
            fee_per_byte: Amount::new(10),         // 10 base units per byte
            dynamic_pricing: false,
            min_fee: Amount::new(500),             // Minimum 500 base units
            max_fee: Amount::new(100_000),         // Maximum 100,000 base units
            congestion_multiplier: 100,            // 1.0x by default
            target_batch_size: 100,
        }
    }
}

impl FeeConfig {
    /// Create a new fee configuration with the specified base fee
    pub fn new(base_fee: Amount) -> Self {
        Self {
            base_fee,
            ..Default::default()
        }
    }

    /// Builder: Enable dynamic pricing
    pub fn with_dynamic_pricing(mut self, enabled: bool) -> Self {
        self.dynamic_pricing = enabled;
        self
    }

    /// Builder: Set fee per byte
    pub fn with_fee_per_byte(mut self, fee: Amount) -> Self {
        self.fee_per_byte = fee;
        self
    }

    /// Builder: Set minimum fee
    pub fn with_min_fee(mut self, min_fee: Amount) -> Self {
        self.min_fee = min_fee;
        self
    }

    /// Builder: Set maximum fee
    pub fn with_max_fee(mut self, max_fee: Amount) -> Self {
        self.max_fee = max_fee;
        self
    }

    /// Builder: Set target batch size for congestion calculation
    pub fn with_target_batch_size(mut self, target: u64) -> Self {
        self.target_batch_size = target;
        self
    }

    /// Calculate the fee for a transaction
    ///
    /// # Arguments
    /// * `tx_type` - Type of transaction (affects multiplier)
    /// * `tx_size` - Size of transaction in bytes
    ///
    /// # Returns
    /// The calculated fee amount
    pub fn calculate_fee(&self, tx_type: TransactionFeeType, tx_size: usize) -> Amount {
        // Calculate base component
        let size_fee = self.fee_per_byte.value() * (tx_size as u128);
        let base_component = self.base_fee.value() + size_fee;

        // Apply transaction type multiplier
        let type_multiplier = tx_type.multiplier() as u128;
        let with_type_mult = base_component * type_multiplier / 100;

        // Apply congestion multiplier if dynamic pricing is enabled
        let with_congestion = if self.dynamic_pricing {
            with_type_mult * (self.congestion_multiplier as u128) / 100
        } else {
            with_type_mult
        };

        // Clamp to min/max bounds
        let clamped = with_congestion
            .max(self.min_fee.value())
            .min(self.max_fee.value());

        Amount::new(clamped)
    }

    /// Update the congestion multiplier based on current batch utilization
    ///
    /// # Arguments
    /// * `current_batch_size` - Number of transactions in the current batch
    ///
    /// Congestion increases when batches are fuller than target,
    /// decreases when they are less full.
    pub fn update_congestion(&mut self, current_batch_size: u64) {
        if !self.dynamic_pricing || self.target_batch_size == 0 {
            return;
        }

        // Calculate utilization ratio (in percentage points * 100)
        let utilization = (current_batch_size as u128 * 10000) / (self.target_batch_size as u128);

        // Smooth adjustment: move 10% towards the target multiplier
        // If utilization > 100%, increase multiplier
        // If utilization < 100%, decrease multiplier
        let target_multiplier = if utilization > 10000 {
            // Over capacity: increase fees up to 5x
            (utilization / 100).min(500) as u64
        } else {
            // Under capacity: decrease fees down to 0.5x
            (utilization / 100).max(50) as u64
        };

        // Smooth adjustment (EMA-like)
        let current = self.congestion_multiplier as i64;
        let target = target_multiplier as i64;
        let adjustment = (target - current) / 10; // 10% movement
        let new_multiplier = (current + adjustment).max(50).min(500) as u64;

        self.congestion_multiplier = new_multiplier;
    }

    /// Reset congestion multiplier to baseline
    pub fn reset_congestion(&mut self) {
        self.congestion_multiplier = 100;
    }

    /// Get estimated fee for a standard transfer
    ///
    /// Uses typical transfer size of 256 bytes
    pub fn estimate_transfer_fee(&self) -> Amount {
        self.calculate_fee(TransactionFeeType::Transfer, 256)
    }

    /// Get estimated fee for a mint operation
    ///
    /// Uses typical mint size of 512 bytes
    pub fn estimate_mint_fee(&self) -> Amount {
        self.calculate_fee(TransactionFeeType::Mint, 512)
    }

    /// Get estimated fee for a burn operation
    ///
    /// Uses typical burn size of 512 bytes
    pub fn estimate_burn_fee(&self) -> Amount {
        self.calculate_fee(TransactionFeeType::Burn, 512)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FeeConfig::default();
        assert_eq!(config.base_fee.value(), 1000);
        assert_eq!(config.fee_per_byte.value(), 10);
        assert!(!config.dynamic_pricing);
        assert_eq!(config.congestion_multiplier, 100);
    }

    #[test]
    fn test_calculate_fee_basic() {
        let config = FeeConfig::new(Amount::new(1000))
            .with_fee_per_byte(Amount::new(10));

        // Transfer with 256 bytes: (1000 + 10*256) * 100 / 100 = 3560
        let fee = config.calculate_fee(TransactionFeeType::Transfer, 256);
        assert_eq!(fee.value(), 3560);
    }

    #[test]
    fn test_calculate_fee_with_multiplier() {
        let config = FeeConfig::new(Amount::new(1000))
            .with_fee_per_byte(Amount::new(10));

        // Mint with 256 bytes: (1000 + 10*256) * 150 / 100 = 5340
        let mint_fee = config.calculate_fee(TransactionFeeType::Mint, 256);
        assert_eq!(mint_fee.value(), 5340);

        // CrossChain with 256 bytes: (1000 + 10*256) * 250 / 100 = 8900
        let cross_chain_fee = config.calculate_fee(TransactionFeeType::CrossChain, 256);
        assert_eq!(cross_chain_fee.value(), 8900);
    }

    #[test]
    fn test_fee_min_max_clamping() {
        let config = FeeConfig::new(Amount::new(100))
            .with_fee_per_byte(Amount::new(1))
            .with_min_fee(Amount::new(500))
            .with_max_fee(Amount::new(1000));

        // Small tx: should be clamped to min_fee
        let small_fee = config.calculate_fee(TransactionFeeType::Transfer, 10);
        assert_eq!(small_fee.value(), 500);

        // Large tx: should be clamped to max_fee
        let large_fee = config.calculate_fee(TransactionFeeType::CrossChain, 10000);
        assert_eq!(large_fee.value(), 1000);
    }

    #[test]
    fn test_dynamic_pricing() {
        let mut config = FeeConfig::new(Amount::new(1000))
            .with_fee_per_byte(Amount::new(10))
            .with_dynamic_pricing(true)
            .with_target_batch_size(100);

        // Initial fee at 1x congestion
        let base_fee = config.calculate_fee(TransactionFeeType::Transfer, 256);
        assert_eq!(base_fee.value(), 3560);

        // Update congestion with high utilization (200 txs vs 100 target)
        config.update_congestion(200);
        assert!(config.congestion_multiplier > 100, "Congestion should increase");

        // Fee should be higher with increased congestion
        let congested_fee = config.calculate_fee(TransactionFeeType::Transfer, 256);
        assert!(congested_fee.value() > base_fee.value(), "Fee should increase with congestion");
    }

    #[test]
    fn test_congestion_smoothing() {
        let mut config = FeeConfig::new(Amount::new(1000))
            .with_dynamic_pricing(true)
            .with_target_batch_size(100);

        // Start at 100 (1x)
        assert_eq!(config.congestion_multiplier, 100);

        // Sudden spike to 500% utilization
        config.update_congestion(500);

        // Should not jump immediately to 5x, but move smoothly
        assert!(config.congestion_multiplier > 100);
        assert!(config.congestion_multiplier < 500);
    }

    #[test]
    fn test_type_multipliers() {
        assert_eq!(TransactionFeeType::Transfer.multiplier(), 100);
        assert_eq!(TransactionFeeType::Mint.multiplier(), 150);
        assert_eq!(TransactionFeeType::Burn.multiplier(), 150);
        assert_eq!(TransactionFeeType::ObjectUpdate.multiplier(), 120);
        assert_eq!(TransactionFeeType::Callback.multiplier(), 200);
        assert_eq!(TransactionFeeType::CrossChain.multiplier(), 250);
    }

    #[test]
    fn test_estimate_fees() {
        let config = FeeConfig::new(Amount::new(1000))
            .with_fee_per_byte(Amount::new(10));

        let transfer_fee = config.estimate_transfer_fee();
        let mint_fee = config.estimate_mint_fee();
        let burn_fee = config.estimate_burn_fee();

        // Mint and burn should be higher than transfer (1.5x multiplier vs 1.0x)
        assert!(mint_fee.value() > transfer_fee.value());
        assert!(burn_fee.value() > transfer_fee.value());
        assert_eq!(mint_fee.value(), burn_fee.value());
    }
}
