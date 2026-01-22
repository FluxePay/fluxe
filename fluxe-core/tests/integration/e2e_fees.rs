//! Fee collection and withdrawal flow tests for FLUXE.
//!
//! Tests fee collection and distribution:
//! 1. Process transactions with fees
//! 2. Verify fee collection per chain
//! 3. Verify fee withdrawal creates valid ExitReceipts

use super::test_utils::*;
use fluxe_core::data_structures::ExitReceipt;
use fluxe_core::fees::{FeeCollector, FeeConfig, FeeWithdrawalResult, TransactionFeeType};
use fluxe_core::types::*;

/// Test basic fee collection flow.
#[test]
fn test_basic_fee_collection() {
    let mut env = TestEnvironment::new();

    // ========================================
    // Process transactions with fees
    // ========================================

    // Simulate deposit with fee
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("Deposit should succeed");

    // Collect fee for the deposit transaction
    let deposit_fee = 500_000u128; // 0.5 USDC fee
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, deposit_fee);

    // Seed Solana liquidity for withdrawal
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("Liquidity should succeed");

    // Simulate withdrawal with fee
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 50_000_000u128)
        .expect("Withdrawal should succeed");

    // Collect fee for the withdrawal transaction
    let withdrawal_fee = 1_000_000u128; // 1 USDC fee
    env.collect_fee(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, withdrawal_fee);

    // ========================================
    // Verify fee collection per chain
    // ========================================

    let eth_fees = env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE);
    let sol_fees = env.fee_collector.get_fees(SOLANA_CHAIN_ID, USDC_ASSET_TYPE);

    assert_eq!(eth_fees, Amount::new(deposit_fee));
    assert_eq!(sol_fees, Amount::new(withdrawal_fee));

    // Total fees should be sum
    let total = env.fee_collector.total_fees_for_asset(USDC_ASSET_TYPE);
    assert_eq!(total, Amount::new(deposit_fee + withdrawal_fee));
}

/// Test fee withdrawal creates valid ExitReceipts.
#[test]
fn test_fee_withdrawal_creates_exit_receipts() {
    let mut env = TestEnvironment::new();

    // Collect fees from multiple transactions
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 250_000u128);

    // Total: 1.75 USDC in fees
    let expected_total = 1_750_000u128;

    // ========================================
    // Create fee withdrawal
    // ========================================

    let withdrawal_result = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("Fee withdrawal should succeed");

    // ========================================
    // Verify ExitReceipts
    // ========================================

    assert_eq!(withdrawal_result.chain_id, ETHEREUM_CHAIN_ID);
    assert_eq!(withdrawal_result.exit_receipts.len(), 1); // One receipt for USDC

    let exit_receipt = &withdrawal_result.exit_receipts[0];
    assert_eq!(exit_receipt.destination_chain, ETHEREUM_CHAIN_ID);
    assert_eq!(exit_receipt.asset_type, USDC_ASSET_TYPE);
    assert_eq!(exit_receipt.amount, Amount::new(expected_total));

    // Verify receipt has valid fields
    assert_ne!(exit_receipt.burned_nf, ark_bn254::Fr::from(0));
    assert_ne!(exit_receipt.aux, ark_bn254::Fr::from(0)); // aux contains sequencer address

    // Verify withdrawn amounts match
    assert_eq!(
        withdrawal_result.withdrawn_amounts.get(&USDC_ASSET_TYPE),
        Some(&Amount::new(expected_total))
    );

    // ========================================
    // Verify fees are reset after withdrawal
    // ========================================

    let remaining_fees = env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE);
    assert_eq!(remaining_fees, Amount::zero());

    // But total collected should still track historical fees
    let total_collected = env.fee_collector.get_total_collected(USDC_ASSET_TYPE);
    assert_eq!(total_collected, Amount::new(expected_total));
}

/// Test fee collection across multiple chains.
#[test]
fn test_multi_chain_fee_collection() {
    let mut env = TestEnvironment::new()
        .with_chain(BASE_CHAIN_ID, ChainType::EVM);

    // Collect fees on all chains
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.collect_fee(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 2_000_000u128);
    env.collect_fee(BASE_CHAIN_ID, USDC_ASSET_TYPE, 500_000u128);

    // Verify per-chain fees
    assert_eq!(
        env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::new(1_000_000)
    );
    assert_eq!(
        env.fee_collector.get_fees(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::new(2_000_000)
    );
    assert_eq!(
        env.fee_collector.get_fees(BASE_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::new(500_000)
    );

    // Verify total
    assert_eq!(
        env.fee_collector.total_fees_for_asset(USDC_ASSET_TYPE),
        Amount::new(3_500_000)
    );

    // Verify chains with fees
    let chains_with_fees = env.fee_collector.chains_with_fees();
    assert_eq!(chains_with_fees.len(), 3);
}

/// Test fee withdrawal for multiple asset types.
#[test]
fn test_multi_asset_fee_withdrawal() {
    let mut env = TestEnvironment::new();

    const USDT: AssetType = 2;
    const DAI: AssetType = 3;

    // Collect fees for multiple assets on Ethereum
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, USDT, 2_000_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, DAI, 500_000u128);

    // Create withdrawal for all fees on Ethereum
    let withdrawal_result = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("Fee withdrawal should succeed");

    // Should have 3 exit receipts (one per asset)
    assert_eq!(withdrawal_result.exit_receipts.len(), 3);

    // Verify amounts per asset
    assert_eq!(
        withdrawal_result.withdrawn_amounts.get(&USDC_ASSET_TYPE),
        Some(&Amount::new(1_000_000))
    );
    assert_eq!(
        withdrawal_result.withdrawn_amounts.get(&USDT),
        Some(&Amount::new(2_000_000))
    );
    assert_eq!(
        withdrawal_result.withdrawn_amounts.get(&DAI),
        Some(&Amount::new(500_000))
    );

    // Verify each exit receipt
    for receipt in &withdrawal_result.exit_receipts {
        assert_eq!(receipt.destination_chain, ETHEREUM_CHAIN_ID);
        assert!(
            receipt.asset_type == USDC_ASSET_TYPE
                || receipt.asset_type == USDT
                || receipt.asset_type == DAI
        );
    }
}

/// Test sequential fee collections and withdrawals.
#[test]
fn test_sequential_fee_cycles() {
    let mut env = TestEnvironment::new();

    // Cycle 1: Collect and withdraw
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    let result1 = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("First withdrawal should succeed");
    assert_eq!(result1.exit_receipts.len(), 1);

    // Cycle 2: Collect more and withdraw
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 2_000_000u128);
    let result2 = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("Second withdrawal should succeed");
    assert_eq!(result2.exit_receipts.len(), 1);
    assert_eq!(
        result2.exit_receipts[0].amount,
        Amount::new(2_000_000)
    );

    // Cycle 3: Multiple collections, single withdrawal
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000u128);
    let result3 = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("Third withdrawal should succeed");
    assert_eq!(
        result3.exit_receipts[0].amount,
        Amount::new(1_500_000)
    );

    // Verify total collected across all cycles
    assert_eq!(
        env.fee_collector.get_total_collected(USDC_ASSET_TYPE),
        Amount::new(4_500_000) // 1M + 2M + 1.5M
    );

    // Verify withdrawal history
    let history = env.fee_collector.withdrawal_history();
    assert_eq!(history.len(), 3);
}

/// Test no fees to withdraw returns None.
#[test]
fn test_no_fees_withdrawal_returns_none() {
    let mut env = TestEnvironment::new();

    // No fees collected
    let result = env.create_fee_withdrawal(ETHEREUM_CHAIN_ID);
    assert!(result.is_none(), "Withdrawal with no fees should return None");

    // Collect and withdraw on Ethereum
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.create_fee_withdrawal(ETHEREUM_CHAIN_ID).unwrap();

    // Try to withdraw again - should be None
    let result2 = env.create_fee_withdrawal(ETHEREUM_CHAIN_ID);
    assert!(
        result2.is_none(),
        "Second withdrawal with no fees should return None"
    );

    // Solana never had fees
    let sol_result = env.create_fee_withdrawal(SOLANA_CHAIN_ID);
    assert!(
        sol_result.is_none(),
        "Withdrawal from chain with no fees should return None"
    );
}

/// Test fee withdrawal for specific asset only.
#[test]
fn test_single_asset_fee_withdrawal() {
    let mut env = TestEnvironment::new();

    const USDT: AssetType = 2;

    // Collect fees for multiple assets
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, USDT, 500_000u128);

    // Withdraw only USDC fees
    let (receipt, amount) = env
        .fee_collector
        .create_asset_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE)
        .expect("Asset withdrawal should succeed");

    assert_eq!(receipt.asset_type, USDC_ASSET_TYPE);
    assert_eq!(amount, Amount::new(1_000_000));

    // USDC fees should be zero now
    assert_eq!(
        env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::zero()
    );

    // USDT fees should still be available
    assert_eq!(
        env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDT),
        Amount::new(500_000)
    );
}

/// Test fee summary generation.
#[test]
fn test_fee_summary() {
    let mut env = TestEnvironment::new();

    const USDT: AssetType = 2;

    // Collect various fees
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.collect_fee(ETHEREUM_CHAIN_ID, USDT, 500_000u128);
    env.collect_fee(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 2_000_000u128);

    // Get summary
    let summary = env.fee_collector.fee_summary();

    // Verify structure
    assert_eq!(summary.len(), 2); // Two chains

    // Ethereum fees
    let eth_fees = summary.get(&ETHEREUM_CHAIN_ID).unwrap();
    assert_eq!(eth_fees.get(&USDC_ASSET_TYPE), Some(&Amount::new(1_000_000)));
    assert_eq!(eth_fees.get(&USDT), Some(&Amount::new(500_000)));

    // Solana fees
    let sol_fees = summary.get(&SOLANA_CHAIN_ID).unwrap();
    assert_eq!(sol_fees.get(&USDC_ASSET_TYPE), Some(&Amount::new(2_000_000)));
    assert_eq!(sol_fees.get(&USDT), None);
}

/// Test fee withdrawal history tracking.
#[test]
fn test_fee_withdrawal_history() {
    let mut env = TestEnvironment::new();

    // Multiple withdrawals across chains
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.create_fee_withdrawal(ETHEREUM_CHAIN_ID);

    env.collect_fee(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 2_000_000u128);
    env.create_fee_withdrawal(SOLANA_CHAIN_ID);

    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000u128);
    env.create_fee_withdrawal(ETHEREUM_CHAIN_ID);

    // Check history
    let history = env.fee_collector.withdrawal_history();
    assert_eq!(history.len(), 3);

    // Verify order and amounts
    assert_eq!(history[0].chain_id, ETHEREUM_CHAIN_ID);
    assert_eq!(history[0].amount, Amount::new(1_000_000));

    assert_eq!(history[1].chain_id, SOLANA_CHAIN_ID);
    assert_eq!(history[1].amount, Amount::new(2_000_000));

    assert_eq!(history[2].chain_id, ETHEREUM_CHAIN_ID);
    assert_eq!(history[2].amount, Amount::new(500_000));

    // Nonces should be sequential
    assert_eq!(history[0].nonce, 0);
    assert_eq!(history[1].nonce, 1);
    assert_eq!(history[2].nonce, 2);
}

/// Test fee collection after partial withdrawal.
#[test]
fn test_fee_collection_after_withdrawal() {
    let mut env = TestEnvironment::new();

    // First collection cycle
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.create_fee_withdrawal(ETHEREUM_CHAIN_ID);

    // Collect new fees
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000u128);

    // Verify new fees are tracked independently
    assert_eq!(
        env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::new(500_000)
    );

    // Total collected should include both cycles
    assert_eq!(
        env.fee_collector.get_total_collected(USDC_ASSET_TYPE),
        Amount::new(1_500_000)
    );
}

/// Test sequencer address in exit receipts.
#[test]
fn test_sequencer_address_in_receipts() {
    let mut env = TestEnvironment::new();

    // Set a specific sequencer address
    let sequencer_addr = test_sequencer_address();
    env.fee_collector.set_sequencer_address(sequencer_addr);

    // Collect and withdraw fees
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    let result = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("Withdrawal should succeed");

    // Verify sequencer address is stored
    assert_eq!(
        env.fee_collector.sequencer_address(),
        &sequencer_addr
    );

    // Exit receipt aux field should contain address encoding
    let receipt = &result.exit_receipts[0];
    assert_ne!(receipt.aux, ark_bn254::Fr::from(0));
}

/// Test large fee amounts.
#[test]
fn test_large_fee_amounts() {
    let mut env = TestEnvironment::new();

    // Simulate high volume fee collection
    let large_fee = 1_000_000_000_000u128; // 1 million USDC in fees

    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, large_fee);

    assert_eq!(
        env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::new(large_fee)
    );

    // Withdrawal should handle large amounts
    let result = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("Large fee withdrawal should succeed");

    assert_eq!(
        result.exit_receipts[0].amount,
        Amount::new(large_fee)
    );
}

/// Test fee collection with has_fees check.
#[test]
fn test_has_fees_check() {
    let mut env = TestEnvironment::new();

    // Initially no fees
    assert!(!env.fee_collector.has_fees(ETHEREUM_CHAIN_ID));
    assert!(!env.fee_collector.has_fees(SOLANA_CHAIN_ID));

    // After collection
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    assert!(env.fee_collector.has_fees(ETHEREUM_CHAIN_ID));
    assert!(!env.fee_collector.has_fees(SOLANA_CHAIN_ID));

    // After withdrawal
    env.create_fee_withdrawal(ETHEREUM_CHAIN_ID);
    assert!(!env.fee_collector.has_fees(ETHEREUM_CHAIN_ID));
}

/// Test fee withdrawal integration with main protocol flow.
#[test]
fn test_fee_integration_with_protocol_flow() {
    let mut env = TestEnvironment::new();

    // ========================================
    // Full protocol flow with fees
    // ========================================

    // Seed Solana liquidity
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("Liquidity should succeed");

    // User deposits on Ethereum
    let deposit_amount = 100_000_000u128;
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, deposit_amount)
        .expect("Deposit should succeed");

    // Sequencer collects deposit fee (0.1%)
    let deposit_fee = deposit_amount / 1000;
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, deposit_fee);

    // User withdraws to Solana
    let withdrawal_amount = 50_000_000u128;
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, withdrawal_amount)
        .expect("Withdrawal should succeed");

    // Sequencer collects withdrawal fee (0.2%)
    let withdrawal_fee = withdrawal_amount * 2 / 1000;
    env.collect_fee(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, withdrawal_fee);

    // Finalize batch
    env.finalize_batch().expect("Batch should finalize");

    // ========================================
    // Sequencer withdraws collected fees
    // ========================================

    // Withdraw ETH fees
    let eth_fee_withdrawal = env
        .create_fee_withdrawal(ETHEREUM_CHAIN_ID)
        .expect("ETH fee withdrawal should succeed");
    assert_eq!(
        eth_fee_withdrawal.exit_receipts[0].amount,
        Amount::new(deposit_fee)
    );

    // Withdraw SOL fees
    let sol_fee_withdrawal = env
        .create_fee_withdrawal(SOLANA_CHAIN_ID)
        .expect("SOL fee withdrawal should succeed");
    assert_eq!(
        sol_fee_withdrawal.exit_receipts[0].amount,
        Amount::new(withdrawal_fee)
    );

    // ========================================
    // Verify protocol state
    // ========================================

    // Global supply = liquidity + deposit - withdrawal
    let liquidity_amount = 100_000_000u128;
    let expected_supply = liquidity_amount + deposit_amount - withdrawal_amount;
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(expected_supply)
    );

    // All invariants should hold
    env.verify_global_consistency()
        .expect("Protocol should be consistent");
}

/// Test clear all fees.
#[test]
fn test_clear_all_fees() {
    let mut env = TestEnvironment::new();

    // Collect various fees
    env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000u128);
    env.collect_fee(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 2_000_000u128);

    // Verify fees exist
    assert!(env.fee_collector.has_fees(ETHEREUM_CHAIN_ID));
    assert!(env.fee_collector.has_fees(SOLANA_CHAIN_ID));

    // Clear all
    env.fee_collector.clear_all_fees();

    // Verify all cleared
    assert!(!env.fee_collector.has_fees(ETHEREUM_CHAIN_ID));
    assert!(!env.fee_collector.has_fees(SOLANA_CHAIN_ID));
    assert_eq!(env.fee_collector.chains_with_fees().len(), 0);
}
