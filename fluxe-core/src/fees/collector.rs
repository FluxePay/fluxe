//! Fee collector for FLUXE protocol
//!
//! This module provides fee collection and withdrawal functionality:
//! - Accumulates fees per chain and asset type
//! - Creates ExitReceipts for sequencer fee withdrawals
//! - Tracks fee history for auditing

use crate::data_structures::ExitReceipt;
use crate::types::{Amount, AssetType, ChainId, Nullifier};
use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Address type for fee recipient (32 bytes to support both EVM and SVM)
pub type Address = [u8; 32];

/// Result of a fee withdrawal operation
#[derive(Clone, Debug)]
pub struct FeeWithdrawalResult {
    /// Exit receipts created for the withdrawal
    pub exit_receipts: Vec<ExitReceipt>,

    /// Total amount withdrawn per asset type
    pub withdrawn_amounts: HashMap<AssetType, Amount>,

    /// Chain ID where the withdrawal is directed
    pub chain_id: ChainId,
}

/// Fee collector for accumulating and distributing protocol fees
///
/// The FeeCollector maintains accumulated fees per chain and asset type,
/// allowing the sequencer to periodically withdraw collected fees.
#[derive(Clone, Debug)]
pub struct FeeCollector {
    /// Accumulated fees per chain, then per asset type
    per_chain_fees: HashMap<ChainId, HashMap<AssetType, Amount>>,

    /// Address where fees are sent (sequencer/treasury address)
    sequencer_address: Address,

    /// Nonce for generating unique exit receipts
    withdrawal_nonce: u64,

    /// Historical withdrawals for auditing
    withdrawal_history: Vec<FeeWithdrawalRecord>,

    /// Total fees ever collected per asset type (for metrics)
    total_collected: HashMap<AssetType, Amount>,
}

/// Record of a fee withdrawal for auditing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeWithdrawalRecord {
    /// Chain ID where fees were withdrawn
    pub chain_id: ChainId,

    /// Asset type
    pub asset_type: AssetType,

    /// Amount withdrawn
    pub amount: Amount,

    /// Timestamp of withdrawal
    pub timestamp: u64,

    /// Withdrawal nonce used
    pub nonce: u64,
}

impl Default for FeeCollector {
    fn default() -> Self {
        Self::new([0u8; 32])
    }
}

impl FeeCollector {
    /// Create a new fee collector with the specified sequencer address
    ///
    /// # Arguments
    /// * `sequencer_address` - Address where fees will be sent on withdrawal
    pub fn new(sequencer_address: Address) -> Self {
        Self {
            per_chain_fees: HashMap::new(),
            sequencer_address,
            withdrawal_nonce: 0,
            withdrawal_history: Vec::new(),
            total_collected: HashMap::new(),
        }
    }

    /// Set the sequencer address for fee withdrawals
    pub fn set_sequencer_address(&mut self, address: Address) {
        self.sequencer_address = address;
    }

    /// Get the current sequencer address
    pub fn sequencer_address(&self) -> &Address {
        &self.sequencer_address
    }

    /// Collect a fee for a transaction
    ///
    /// # Arguments
    /// * `chain_id` - Chain where the fee was collected
    /// * `asset` - Asset type of the fee
    /// * `amount` - Amount of fee collected
    pub fn collect_fee(&mut self, chain_id: ChainId, asset: AssetType, amount: Amount) {
        // Add to per-chain fees
        let chain_fees = self.per_chain_fees.entry(chain_id).or_default();
        let current = chain_fees.entry(asset).or_insert(Amount::zero());
        *current = current.saturating_add(amount);

        // Update total collected
        let total = self.total_collected.entry(asset).or_insert(Amount::zero());
        *total = total.saturating_add(amount);
    }

    /// Get accumulated fees for a specific chain and asset
    ///
    /// # Arguments
    /// * `chain_id` - Chain to query
    /// * `asset` - Asset type to query
    ///
    /// # Returns
    /// The accumulated fee amount, or zero if none
    pub fn get_fees(&self, chain_id: ChainId, asset: AssetType) -> Amount {
        self.per_chain_fees
            .get(&chain_id)
            .and_then(|chain_fees| chain_fees.get(&asset))
            .copied()
            .unwrap_or(Amount::zero())
    }

    /// Get all accumulated fees for a chain
    ///
    /// # Arguments
    /// * `chain_id` - Chain to query
    ///
    /// # Returns
    /// HashMap of asset type to accumulated amount
    pub fn get_chain_fees(&self, chain_id: ChainId) -> HashMap<AssetType, Amount> {
        self.per_chain_fees
            .get(&chain_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get total fees ever collected for an asset type
    pub fn get_total_collected(&self, asset: AssetType) -> Amount {
        self.total_collected
            .get(&asset)
            .copied()
            .unwrap_or(Amount::zero())
    }

    /// Reset fees for a specific chain (called after successful withdrawal)
    ///
    /// # Arguments
    /// * `chain_id` - Chain to reset fees for
    pub fn reset_fees(&mut self, chain_id: ChainId) {
        if let Some(chain_fees) = self.per_chain_fees.get_mut(&chain_id) {
            chain_fees.clear();
        }
    }

    /// Reset fees for a specific chain and asset
    ///
    /// # Arguments
    /// * `chain_id` - Chain to reset fees for
    /// * `asset` - Asset type to reset
    pub fn reset_fees_for_asset(&mut self, chain_id: ChainId, asset: AssetType) {
        if let Some(chain_fees) = self.per_chain_fees.get_mut(&chain_id) {
            chain_fees.remove(&asset);
        }
    }

    /// Create exit receipts for fee withdrawal on a specific chain
    ///
    /// This creates ExitReceipts that can be used to claim fees on the target chain.
    /// After calling this, fees are reset for that chain.
    ///
    /// # Arguments
    /// * `chain_id` - Chain to withdraw fees to
    ///
    /// # Returns
    /// FeeWithdrawalResult containing exit receipts and amounts, or None if no fees
    pub fn create_fee_withdrawal(&mut self, chain_id: ChainId) -> Option<FeeWithdrawalResult> {
        let chain_fees = self.per_chain_fees.get(&chain_id)?;

        if chain_fees.is_empty() {
            return None;
        }

        let mut exit_receipts = Vec::new();
        let mut withdrawn_amounts = HashMap::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create an exit receipt for each asset type with accumulated fees
        for (&asset_type, &amount) in chain_fees {
            if amount.is_zero() {
                continue;
            }

            // Generate a unique nullifier for this fee withdrawal
            // In production, this would be derived deterministically from the fee state
            let mut rng = thread_rng();
            let nullifier: Nullifier = F::rand(&mut rng);

            let mut receipt = ExitReceipt::new(
                chain_id,
                asset_type,
                amount,
                nullifier,
                self.withdrawal_nonce,
            );

            // Set aux to encode the sequencer address
            receipt.set_aux(&self.sequencer_address);

            exit_receipts.push(receipt);
            withdrawn_amounts.insert(asset_type, amount);

            // Record the withdrawal
            self.withdrawal_history.push(FeeWithdrawalRecord {
                chain_id,
                asset_type,
                amount,
                timestamp,
                nonce: self.withdrawal_nonce,
            });

            self.withdrawal_nonce += 1;
        }

        if exit_receipts.is_empty() {
            return None;
        }

        // Reset fees for this chain after creating withdrawal
        self.reset_fees(chain_id);

        Some(FeeWithdrawalResult {
            exit_receipts,
            withdrawn_amounts,
            chain_id,
        })
    }

    /// Create exit receipts for fee withdrawal for a specific asset on a chain
    ///
    /// Similar to create_fee_withdrawal but only for a single asset type.
    ///
    /// # Arguments
    /// * `chain_id` - Chain to withdraw fees to
    /// * `asset` - Asset type to withdraw
    ///
    /// # Returns
    /// Exit receipt and amount, or None if no fees for this asset
    pub fn create_asset_withdrawal(
        &mut self,
        chain_id: ChainId,
        asset: AssetType,
    ) -> Option<(ExitReceipt, Amount)> {
        let amount = self.get_fees(chain_id, asset);

        if amount.is_zero() {
            return None;
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate nullifier
        let mut rng = thread_rng();
        let nullifier: Nullifier = F::rand(&mut rng);

        let mut receipt = ExitReceipt::new(
            chain_id,
            asset,
            amount,
            nullifier,
            self.withdrawal_nonce,
        );

        receipt.set_aux(&self.sequencer_address);

        // Record the withdrawal
        self.withdrawal_history.push(FeeWithdrawalRecord {
            chain_id,
            asset_type: asset,
            amount,
            timestamp,
            nonce: self.withdrawal_nonce,
        });

        self.withdrawal_nonce += 1;

        // Reset fees for this asset
        self.reset_fees_for_asset(chain_id, asset);

        Some((receipt, amount))
    }

    /// Get withdrawal history
    pub fn withdrawal_history(&self) -> &[FeeWithdrawalRecord] {
        &self.withdrawal_history
    }

    /// Get all chains with accumulated fees
    pub fn chains_with_fees(&self) -> Vec<ChainId> {
        self.per_chain_fees
            .iter()
            .filter(|(_, fees)| fees.values().any(|a| !a.is_zero()))
            .map(|(&chain_id, _)| chain_id)
            .collect()
    }

    /// Get total accumulated fees across all chains for an asset
    pub fn total_fees_for_asset(&self, asset: AssetType) -> Amount {
        self.per_chain_fees
            .values()
            .filter_map(|chain_fees| chain_fees.get(&asset))
            .fold(Amount::zero(), |acc, &amount| acc.saturating_add(amount))
    }

    /// Check if there are any fees to withdraw for a chain
    pub fn has_fees(&self, chain_id: ChainId) -> bool {
        self.per_chain_fees
            .get(&chain_id)
            .map(|fees| fees.values().any(|a| !a.is_zero()))
            .unwrap_or(false)
    }

    /// Get summary of all accumulated fees
    pub fn fee_summary(&self) -> HashMap<ChainId, HashMap<AssetType, Amount>> {
        self.per_chain_fees.clone()
    }

    /// Clear all accumulated fees (use with caution)
    pub fn clear_all_fees(&mut self) {
        self.per_chain_fees.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        let mut addr = [0u8; 32];
        addr[0..20].copy_from_slice(&[0xAB; 20]); // Simulated Ethereum address
        addr
    }

    #[test]
    fn test_collector_creation() {
        let addr = test_address();
        let collector = FeeCollector::new(addr);

        assert_eq!(collector.sequencer_address(), &addr);
        assert!(collector.chains_with_fees().is_empty());
    }

    #[test]
    fn test_collect_fee() {
        let mut collector = FeeCollector::new(test_address());

        // Collect fees for chain 1, asset 1
        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 1, Amount::new(500));

        assert_eq!(collector.get_fees(1, 1), Amount::new(1500));

        // Collect fees for different asset on same chain
        collector.collect_fee(1, 2, Amount::new(200));
        assert_eq!(collector.get_fees(1, 2), Amount::new(200));

        // Collect fees for different chain
        collector.collect_fee(2, 1, Amount::new(300));
        assert_eq!(collector.get_fees(2, 1), Amount::new(300));

        // Original fees unchanged
        assert_eq!(collector.get_fees(1, 1), Amount::new(1500));
    }

    #[test]
    fn test_get_chain_fees() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 2, Amount::new(500));
        collector.collect_fee(1, 3, Amount::new(250));

        let chain_fees = collector.get_chain_fees(1);
        assert_eq!(chain_fees.len(), 3);
        assert_eq!(chain_fees.get(&1), Some(&Amount::new(1000)));
        assert_eq!(chain_fees.get(&2), Some(&Amount::new(500)));
        assert_eq!(chain_fees.get(&3), Some(&Amount::new(250)));

        // Non-existent chain
        let empty_fees = collector.get_chain_fees(999);
        assert!(empty_fees.is_empty());
    }

    #[test]
    fn test_reset_fees() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 2, Amount::new(500));
        collector.collect_fee(2, 1, Amount::new(300));

        // Reset chain 1 fees
        collector.reset_fees(1);

        assert_eq!(collector.get_fees(1, 1), Amount::zero());
        assert_eq!(collector.get_fees(1, 2), Amount::zero());
        // Chain 2 should be unaffected
        assert_eq!(collector.get_fees(2, 1), Amount::new(300));
    }

    #[test]
    fn test_reset_fees_for_asset() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 2, Amount::new(500));

        // Reset only asset 1 on chain 1
        collector.reset_fees_for_asset(1, 1);

        assert_eq!(collector.get_fees(1, 1), Amount::zero());
        assert_eq!(collector.get_fees(1, 2), Amount::new(500));
    }

    #[test]
    fn test_create_fee_withdrawal() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 2, Amount::new(500));

        let result = collector.create_fee_withdrawal(1).unwrap();

        assert_eq!(result.chain_id, 1);
        assert_eq!(result.exit_receipts.len(), 2);
        assert_eq!(result.withdrawn_amounts.len(), 2);
        assert_eq!(result.withdrawn_amounts.get(&1), Some(&Amount::new(1000)));
        assert_eq!(result.withdrawn_amounts.get(&2), Some(&Amount::new(500)));

        // Fees should be reset after withdrawal
        assert!(!collector.has_fees(1));
        assert_eq!(collector.get_fees(1, 1), Amount::zero());
    }

    #[test]
    fn test_create_fee_withdrawal_no_fees() {
        let mut collector = FeeCollector::new(test_address());

        // No fees for chain 1
        let result = collector.create_fee_withdrawal(1);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_asset_withdrawal() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 2, Amount::new(500));

        let (receipt, amount) = collector.create_asset_withdrawal(1, 1).unwrap();

        assert_eq!(amount, Amount::new(1000));
        assert_eq!(receipt.destination_chain, 1);
        assert_eq!(receipt.asset_type, 1);
        assert_eq!(receipt.amount, Amount::new(1000));

        // Only asset 1 should be reset
        assert_eq!(collector.get_fees(1, 1), Amount::zero());
        assert_eq!(collector.get_fees(1, 2), Amount::new(500));
    }

    #[test]
    fn test_withdrawal_history() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.create_fee_withdrawal(1);

        collector.collect_fee(2, 1, Amount::new(500));
        collector.create_fee_withdrawal(2);

        let history = collector.withdrawal_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].chain_id, 1);
        assert_eq!(history[0].amount, Amount::new(1000));
        assert_eq!(history[1].chain_id, 2);
        assert_eq!(history[1].amount, Amount::new(500));
    }

    #[test]
    fn test_chains_with_fees() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(3, 1, Amount::new(500));

        let chains = collector.chains_with_fees();
        assert_eq!(chains.len(), 2);
        assert!(chains.contains(&1));
        assert!(chains.contains(&3));
    }

    #[test]
    fn test_total_fees_for_asset() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(2, 1, Amount::new(500));
        collector.collect_fee(3, 1, Amount::new(250));

        let total = collector.total_fees_for_asset(1);
        assert_eq!(total, Amount::new(1750));
    }

    #[test]
    fn test_total_collected_tracking() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 1, Amount::new(500));

        // Total collected should track all fees ever collected
        assert_eq!(collector.get_total_collected(1), Amount::new(1500));

        // Even after withdrawal
        collector.create_fee_withdrawal(1);
        assert_eq!(collector.get_total_collected(1), Amount::new(1500));

        // Collect more
        collector.collect_fee(1, 1, Amount::new(200));
        assert_eq!(collector.get_total_collected(1), Amount::new(1700));
    }

    #[test]
    fn test_exit_receipt_properties() {
        let addr = test_address();
        let mut collector = FeeCollector::new(addr);

        collector.collect_fee(1, 1, Amount::new(1000));

        let result = collector.create_fee_withdrawal(1).unwrap();
        let receipt = &result.exit_receipts[0];

        // Verify receipt properties
        assert_eq!(receipt.destination_chain, 1);
        assert_eq!(receipt.asset_type, 1);
        assert_eq!(receipt.amount, Amount::new(1000));

        // aux should be set to sequencer address
        assert_ne!(receipt.aux, F::from(0));
    }

    #[test]
    fn test_set_sequencer_address() {
        let mut collector = FeeCollector::new([0u8; 32]);

        let new_addr = test_address();
        collector.set_sequencer_address(new_addr);

        assert_eq!(collector.sequencer_address(), &new_addr);
    }

    #[test]
    fn test_has_fees() {
        let mut collector = FeeCollector::new(test_address());

        assert!(!collector.has_fees(1));

        collector.collect_fee(1, 1, Amount::new(1000));
        assert!(collector.has_fees(1));

        collector.reset_fees(1);
        assert!(!collector.has_fees(1));
    }

    #[test]
    fn test_fee_summary() {
        let mut collector = FeeCollector::new(test_address());

        collector.collect_fee(1, 1, Amount::new(1000));
        collector.collect_fee(1, 2, Amount::new(500));
        collector.collect_fee(2, 1, Amount::new(300));

        let summary = collector.fee_summary();

        assert_eq!(summary.len(), 2);
        assert_eq!(summary.get(&1).unwrap().get(&1), Some(&Amount::new(1000)));
        assert_eq!(summary.get(&1).unwrap().get(&2), Some(&Amount::new(500)));
        assert_eq!(summary.get(&2).unwrap().get(&1), Some(&Amount::new(300)));
    }
}
