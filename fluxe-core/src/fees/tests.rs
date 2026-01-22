//! Comprehensive tests for fee collection and distribution
//!
//! These tests verify the integration between FeeConfig and FeeCollector,
//! and ensure the fee system works correctly in realistic scenarios.

use super::*;
use crate::types::Amount;

/// Create a test fee configuration
fn test_config() -> FeeConfig {
    FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10))
        .with_min_fee(Amount::new(500))
        .with_max_fee(Amount::new(50_000))
}

/// Create a test fee collector
fn test_collector() -> FeeCollector {
    let mut addr = [0u8; 32];
    // Simulated sequencer address
    addr[0..20].copy_from_slice(&hex_literal("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
    FeeCollector::new(addr)
}

fn hex_literal(s: &str) -> [u8; 20] {
    let mut result = [0u8; 20];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if i >= 20 {
            break;
        }
        let hex_str = std::str::from_utf8(chunk).unwrap();
        result[i] = u8::from_str_radix(hex_str, 16).unwrap();
    }
    result
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_fee_calculation_and_collection_flow() {
    let config = test_config();
    let mut collector = test_collector();

    // Simulate processing multiple transactions
    let transactions = vec![
        (TransactionFeeType::Transfer, 256, 1), // chain 1
        (TransactionFeeType::Mint, 512, 1),     // chain 1
        (TransactionFeeType::Burn, 512, 1),     // chain 1
        (TransactionFeeType::Transfer, 256, 2), // chain 2
        (TransactionFeeType::CrossChain, 1024, 2), // chain 2
    ];

    let asset_type = 1; // USDC

    for (tx_type, size, chain_id) in transactions {
        let fee = config.calculate_fee(tx_type, size);
        collector.collect_fee(chain_id, asset_type, fee);
    }

    // Verify fees were collected on both chains
    assert!(collector.has_fees(1));
    assert!(collector.has_fees(2));

    // Chain 1 should have 3 transactions worth of fees
    let chain1_fees = collector.get_fees(1, asset_type);
    assert!(chain1_fees.value() > 0);

    // Chain 2 should have 2 transactions worth of fees
    let chain2_fees = collector.get_fees(2, asset_type);
    assert!(chain2_fees.value() > 0);

    // Total should be sum of both
    let total = collector.total_fees_for_asset(asset_type);
    assert_eq!(total, chain1_fees.saturating_add(chain2_fees));
}

#[test]
fn test_withdrawal_creates_valid_exit_receipts() {
    let config = test_config();
    let mut collector = test_collector();

    // Collect some fees
    let fee1 = config.calculate_fee(TransactionFeeType::Transfer, 256);
    let fee2 = config.calculate_fee(TransactionFeeType::Mint, 512);

    collector.collect_fee(1, 1, fee1); // Asset 1 (USDC)
    collector.collect_fee(1, 2, fee2); // Asset 2 (USDT)

    // Create withdrawal
    let result = collector.create_fee_withdrawal(1).unwrap();

    // Should have 2 exit receipts (one per asset)
    assert_eq!(result.exit_receipts.len(), 2);
    assert_eq!(result.chain_id, 1);

    // Verify each receipt
    for receipt in &result.exit_receipts {
        assert_eq!(receipt.destination_chain, 1);
        assert!(receipt.amount.value() > 0);

        // Receipt should have valid hash
        let hash = receipt.hash();
        assert_ne!(hash, ark_bn254::Fr::from(0));
    }

    // Fees should be reset
    assert!(!collector.has_fees(1));
}

#[test]
fn test_dynamic_pricing_with_collection() {
    let mut config = FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10))
        .with_dynamic_pricing(true)
        .with_target_batch_size(100);

    let mut collector = test_collector();

    // Simulate low congestion batch
    config.update_congestion(50); // 50% utilization
    let low_fee = config.calculate_fee(TransactionFeeType::Transfer, 256);
    collector.collect_fee(1, 1, low_fee);

    // Simulate high congestion batch
    config.update_congestion(200); // 200% utilization
    let high_fee = config.calculate_fee(TransactionFeeType::Transfer, 256);
    collector.collect_fee(1, 1, high_fee);

    // High congestion fee should be greater
    assert!(high_fee.value() >= low_fee.value());

    // Total collected should be sum
    let total = collector.get_fees(1, 1);
    assert_eq!(total, low_fee.saturating_add(high_fee));
}

#[test]
fn test_multi_chain_fee_isolation() {
    let mut collector = test_collector();

    // Collect fees on multiple chains
    collector.collect_fee(1, 1, Amount::new(1000));  // Ethereum
    collector.collect_fee(501, 1, Amount::new(2000)); // Solana
    collector.collect_fee(137, 1, Amount::new(1500)); // Polygon

    // Verify isolation
    assert_eq!(collector.get_fees(1, 1), Amount::new(1000));
    assert_eq!(collector.get_fees(501, 1), Amount::new(2000));
    assert_eq!(collector.get_fees(137, 1), Amount::new(1500));

    // Withdraw from Ethereum only
    let eth_result = collector.create_fee_withdrawal(1).unwrap();
    assert_eq!(eth_result.withdrawn_amounts.get(&1), Some(&Amount::new(1000)));

    // Other chains should be unaffected
    assert_eq!(collector.get_fees(501, 1), Amount::new(2000));
    assert_eq!(collector.get_fees(137, 1), Amount::new(1500));
}

#[test]
fn test_multi_asset_fee_collection() {
    let mut collector = test_collector();

    // Collect fees in multiple assets
    collector.collect_fee(1, 1, Amount::new(1000)); // USDC
    collector.collect_fee(1, 2, Amount::new(500));  // USDT
    collector.collect_fee(1, 3, Amount::new(2000)); // DAI

    // Verify each asset
    assert_eq!(collector.get_fees(1, 1), Amount::new(1000));
    assert_eq!(collector.get_fees(1, 2), Amount::new(500));
    assert_eq!(collector.get_fees(1, 3), Amount::new(2000));

    // Get all chain fees
    let chain_fees = collector.get_chain_fees(1);
    assert_eq!(chain_fees.len(), 3);

    // Withdraw single asset
    let (receipt, amount) = collector.create_asset_withdrawal(1, 1).unwrap();
    assert_eq!(amount, Amount::new(1000));
    assert_eq!(receipt.asset_type, 1);

    // Other assets should remain
    assert_eq!(collector.get_fees(1, 2), Amount::new(500));
    assert_eq!(collector.get_fees(1, 3), Amount::new(2000));
}

#[test]
fn test_fee_withdrawal_history_tracking() {
    let mut collector = test_collector();

    // Collect and withdraw multiple times
    collector.collect_fee(1, 1, Amount::new(1000));
    collector.create_fee_withdrawal(1);

    collector.collect_fee(1, 1, Amount::new(2000));
    collector.create_fee_withdrawal(1);

    collector.collect_fee(2, 1, Amount::new(1500));
    collector.create_fee_withdrawal(2);

    // Verify history
    let history = collector.withdrawal_history();
    assert_eq!(history.len(), 3);

    // Verify order and amounts
    assert_eq!(history[0].amount, Amount::new(1000));
    assert_eq!(history[1].amount, Amount::new(2000));
    assert_eq!(history[2].amount, Amount::new(1500));

    // Nonces should be sequential
    assert_eq!(history[0].nonce, 0);
    assert_eq!(history[1].nonce, 1);
    assert_eq!(history[2].nonce, 2);
}

#[test]
fn test_total_collected_persists_after_withdrawal() {
    let mut collector = test_collector();

    // Collect some fees
    collector.collect_fee(1, 1, Amount::new(1000));
    assert_eq!(collector.get_total_collected(1), Amount::new(1000));

    // Withdraw
    collector.create_fee_withdrawal(1);

    // Total collected should persist
    assert_eq!(collector.get_total_collected(1), Amount::new(1000));

    // Current fees should be zero
    assert_eq!(collector.get_fees(1, 1), Amount::zero());

    // Collect more
    collector.collect_fee(1, 1, Amount::new(500));
    assert_eq!(collector.get_total_collected(1), Amount::new(1500));
}

#[test]
fn test_fee_config_builder_pattern() {
    let config = FeeConfig::new(Amount::new(2000))
        .with_fee_per_byte(Amount::new(5))
        .with_min_fee(Amount::new(1000))
        .with_max_fee(Amount::new(100_000))
        .with_dynamic_pricing(true)
        .with_target_batch_size(200);

    assert_eq!(config.base_fee, Amount::new(2000));
    assert_eq!(config.fee_per_byte, Amount::new(5));
    assert_eq!(config.min_fee, Amount::new(1000));
    assert_eq!(config.max_fee, Amount::new(100_000));
    assert!(config.dynamic_pricing);
    assert_eq!(config.target_batch_size, 200);
}

#[test]
fn test_zero_fee_handling() {
    let mut collector = test_collector();

    // Collect zero fee (shouldn't cause issues)
    collector.collect_fee(1, 1, Amount::zero());

    // Should still report no fees
    assert!(!collector.has_fees(1));

    // Withdrawal should return None
    let result = collector.create_fee_withdrawal(1);
    assert!(result.is_none());
}

#[test]
fn test_large_fee_amounts() {
    let mut collector = test_collector();

    // Collect very large amounts (testing overflow protection)
    let large_amount = Amount::new(u128::MAX / 2);
    collector.collect_fee(1, 1, large_amount);
    collector.collect_fee(1, 1, large_amount);

    // Should saturate, not overflow
    let total = collector.get_fees(1, 1);
    assert!(total.value() > 0);

    // Create withdrawal should still work
    let result = collector.create_fee_withdrawal(1);
    assert!(result.is_some());
}

#[test]
fn test_exit_receipt_uniqueness() {
    let mut collector = test_collector();

    // Create multiple withdrawals
    collector.collect_fee(1, 1, Amount::new(1000));
    let result1 = collector.create_fee_withdrawal(1).unwrap();

    collector.collect_fee(1, 1, Amount::new(1000));
    let result2 = collector.create_fee_withdrawal(1).unwrap();

    // Receipts should have different hashes (different nonces and nullifiers)
    let hash1 = result1.exit_receipts[0].hash();
    let hash2 = result2.exit_receipts[0].hash();

    assert_ne!(hash1, hash2, "Exit receipts should have unique hashes");
}

#[test]
fn test_congestion_multiplier_bounds() {
    let mut config = FeeConfig::new(Amount::new(1000))
        .with_dynamic_pricing(true)
        .with_target_batch_size(100);

    // Test extreme low utilization
    for _ in 0..100 {
        config.update_congestion(10); // 10% utilization
    }
    // Should not go below 50 (0.5x)
    assert!(config.congestion_multiplier >= 50);

    // Reset and test extreme high utilization
    config.reset_congestion();
    for _ in 0..100 {
        config.update_congestion(1000); // 1000% utilization
    }
    // Should not go above 500 (5x)
    assert!(config.congestion_multiplier <= 500);
}

#[test]
fn test_fee_estimation_methods() {
    let config = FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10));

    // Estimate methods should return reasonable values
    let transfer_fee = config.estimate_transfer_fee();
    let mint_fee = config.estimate_mint_fee();
    let burn_fee = config.estimate_burn_fee();

    assert!(transfer_fee.value() > 0);
    assert!(mint_fee.value() > 0);
    assert!(burn_fee.value() > 0);

    // Mint/Burn should be more expensive than transfer (higher multiplier)
    assert!(mint_fee.value() > transfer_fee.value());
    assert!(burn_fee.value() > transfer_fee.value());
}

#[test]
fn test_chains_with_fees_tracking() {
    let mut collector = test_collector();

    // Initially no chains
    assert!(collector.chains_with_fees().is_empty());

    // Add fees to multiple chains
    collector.collect_fee(1, 1, Amount::new(100));
    collector.collect_fee(2, 1, Amount::new(200));
    collector.collect_fee(3, 1, Amount::new(300));

    let chains = collector.chains_with_fees();
    assert_eq!(chains.len(), 3);
    assert!(chains.contains(&1));
    assert!(chains.contains(&2));
    assert!(chains.contains(&3));

    // Withdraw from chain 1
    collector.create_fee_withdrawal(1);

    let chains_after = collector.chains_with_fees();
    assert_eq!(chains_after.len(), 2);
    assert!(!chains_after.contains(&1));
}

#[test]
fn test_clear_all_fees() {
    let mut collector = test_collector();

    collector.collect_fee(1, 1, Amount::new(1000));
    collector.collect_fee(2, 1, Amount::new(2000));
    collector.collect_fee(3, 1, Amount::new(3000));

    assert!(collector.has_fees(1));
    assert!(collector.has_fees(2));
    assert!(collector.has_fees(3));

    // Clear all
    collector.clear_all_fees();

    assert!(!collector.has_fees(1));
    assert!(!collector.has_fees(2));
    assert!(!collector.has_fees(3));
    assert!(collector.chains_with_fees().is_empty());

    // Total collected should still be tracked
    assert_eq!(collector.get_total_collected(1), Amount::new(6000));
}
