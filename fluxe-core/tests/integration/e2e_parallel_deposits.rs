//! Multi-chain parallel deposit tests for FLUXE.
//!
//! Tests parallel deposit processing:
//! 1. Deposit 50 on Ethereum + 50 on Solana simultaneously
//! 2. Verify both ingress receipts created
//! 3. Verify supply tracking is correct on both chains
//! 4. Verify global supply invariant holds

use super::test_utils::*;
use fluxe_core::bridge::events::DepositEvent;
use fluxe_core::data_structures::IngressReceipt;
use fluxe_core::types::*;
use std::thread;
use std::sync::{Arc, Mutex};

/// Test simultaneous deposits on Ethereum and Solana.
#[test]
fn test_parallel_deposits_eth_and_solana() {
    let mut env = TestEnvironment::new();

    let eth_amount = 50_000_000u128; // 50 USDC
    let sol_amount = 50_000_000u128; // 50 USDC

    // ========================================
    // Simulate simultaneous deposits
    // ========================================

    // In a real scenario, these would come from different chain monitors.
    // Here we process them in sequence but verify they're independent.

    let (eth_receipt, eth_commitment) = env
        .process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, eth_amount)
        .expect("ETH deposit should succeed");

    let (sol_receipt, sol_commitment) = env
        .process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_amount)
        .expect("SOL deposit should succeed");

    // ========================================
    // Verify both ingress receipts created correctly
    // ========================================

    assert_eq!(eth_receipt.source_chain, ETHEREUM_CHAIN_ID);
    assert_eq!(eth_receipt.amount, Amount::from(eth_amount));

    assert_eq!(sol_receipt.source_chain, SOLANA_CHAIN_ID);
    assert_eq!(sol_receipt.amount, Amount::from(sol_amount));

    // Receipts should have different nonces
    assert_ne!(eth_receipt.nonce, sol_receipt.nonce);

    // Commitments should be different
    assert_ne!(eth_commitment, sol_commitment);

    // ========================================
    // Verify per-chain supply tracking
    // ========================================

    let eth_deposited = env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE);
    let sol_deposited = env.get_chain_deposited(SOLANA_CHAIN_ID, USDC_ASSET_TYPE);

    assert_eq!(eth_deposited, Amount::from(eth_amount));
    assert_eq!(sol_deposited, Amount::from(sol_amount));

    // Withdrawals should be zero
    assert_eq!(
        env.get_chain_withdrawn(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::zero()
    );
    assert_eq!(
        env.get_chain_withdrawn(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::zero()
    );

    // ========================================
    // Verify global supply invariant holds
    // ========================================

    let global_supply = env.get_global_supply(USDC_ASSET_TYPE);
    assert_eq!(global_supply, Amount::from(eth_amount + sol_amount));

    // Invariant check: global = sum of deposits - sum of withdrawals
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));
    env.verify_global_consistency()
        .expect("Global consistency should hold");
}

/// Test many parallel deposits from multiple chains.
#[test]
fn test_high_volume_parallel_deposits() {
    let mut env = TestEnvironment::new()
        .with_chain(BASE_CHAIN_ID, ChainType::EVM);

    let deposits_per_chain = 20;
    let amount_per_deposit = 10_000_000u128; // 10 USDC each

    let chains = [ETHEREUM_CHAIN_ID, SOLANA_CHAIN_ID, BASE_CHAIN_ID];
    let mut tracker = ParallelDepositTracker::new();

    // ========================================
    // Process many deposits across chains
    // ========================================

    for round in 0..deposits_per_chain {
        for &chain_id in &chains {
            let (receipt, commitment) = env
                .process_deposit(chain_id, USDC_ASSET_TYPE, amount_per_deposit)
                .expect(&format!("Deposit {} on chain {} should succeed", round, chain_id));

            tracker.add(chain_id, receipt, commitment);
        }
    }

    // ========================================
    // Verify deposit counts per chain
    // ========================================

    for &chain_id in &chains {
        assert_eq!(
            tracker.count_by_chain(chain_id),
            deposits_per_chain,
            "Chain {} should have {} deposits",
            chain_id,
            deposits_per_chain
        );
    }

    // ========================================
    // Verify per-chain supply tracking
    // ========================================

    let expected_per_chain = amount_per_deposit * deposits_per_chain as u128;

    for &chain_id in &chains {
        let deposited = env.get_chain_deposited(chain_id, USDC_ASSET_TYPE);
        assert_eq!(
            deposited,
            Amount::from(expected_per_chain),
            "Chain {} should have {} deposited",
            chain_id,
            expected_per_chain
        );
    }

    // ========================================
    // Verify global supply
    // ========================================

    let expected_total = expected_per_chain * chains.len() as u128;
    let global_supply = env.get_global_supply(USDC_ASSET_TYPE);

    assert_eq!(global_supply, Amount::from(expected_total));

    // Also verify via tracker
    let tracked_total = tracker.total_amount(USDC_ASSET_TYPE);
    assert_eq!(tracked_total, Amount::from(expected_total));

    // ========================================
    // Verify invariant holds
    // ========================================

    env.verify_global_consistency()
        .expect("Global consistency should hold after high volume deposits");
}

/// Test parallel deposits with different asset types.
#[test]
fn test_parallel_multi_asset_deposits() {
    let mut env = TestEnvironment::new();

    const USDT: AssetType = 2;
    const DAI: AssetType = 3;

    // Deposit different assets on different chains simultaneously
    let deposits = vec![
        (ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128),
        (ETHEREUM_CHAIN_ID, USDT, 200_000_000u128),
        (SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 150_000_000u128),
        (SOLANA_CHAIN_ID, DAI, 300_000_000u128),
    ];

    // Process all deposits
    for (chain_id, asset_type, amount) in &deposits {
        env.process_deposit(*chain_id, *asset_type, *amount)
            .expect("Deposit should succeed");
    }

    // ========================================
    // Verify per-asset supplies
    // ========================================

    // USDC: 100 (ETH) + 150 (SOL) = 250
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(250_000_000u128)
    );

    // USDT: 200 (ETH only)
    assert_eq!(env.get_global_supply(USDT), Amount::from(200_000_000u128));

    // DAI: 300 (SOL only)
    assert_eq!(env.get_global_supply(DAI), Amount::from(300_000_000u128));

    // ========================================
    // Verify per-chain per-asset tracking
    // ========================================

    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(100_000_000u128)
    );
    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDT),
        Amount::from(200_000_000u128)
    );
    assert_eq!(
        env.get_chain_deposited(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(150_000_000u128)
    );
    assert_eq!(
        env.get_chain_deposited(SOLANA_CHAIN_ID, DAI),
        Amount::from(300_000_000u128)
    );

    // ========================================
    // Verify all invariants hold
    // ========================================

    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));
    assert!(env.check_supply_invariant(USDT));
    assert!(env.check_supply_invariant(DAI));

    env.verify_global_consistency()
        .expect("All invariants should hold");
}

/// Test that parallel deposits don't interfere with each other.
#[test]
fn test_deposit_isolation() {
    let mut env = TestEnvironment::new();

    // Track initial state
    let initial_supply = env.get_global_supply(USDC_ASSET_TYPE);
    assert_eq!(initial_supply, Amount::zero());

    // First deposit on Ethereum
    let (eth_receipt1, eth_cm1) = env
        .process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("First ETH deposit should succeed");

    let supply_after_first = env.get_global_supply(USDC_ASSET_TYPE);
    assert_eq!(supply_after_first, Amount::from(100_000_000u128));

    // Second deposit on Solana - should not affect ETH tracking
    let (sol_receipt, sol_cm) = env
        .process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("SOL deposit should succeed");

    // ETH tracking should be unchanged
    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(100_000_000u128)
    );

    // SOL tracking should be updated
    assert_eq!(
        env.get_chain_deposited(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(200_000_000u128)
    );

    // Third deposit on Ethereum - should add to ETH total
    let (eth_receipt2, eth_cm2) = env
        .process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 50_000_000u128)
        .expect("Second ETH deposit should succeed");

    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(150_000_000u128) // 100 + 50
    );

    // Global should be sum of all
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(350_000_000u128) // 100 + 200 + 50
    );

    // All commitments should be unique
    assert_ne!(eth_cm1, eth_cm2);
    assert_ne!(eth_cm1, sol_cm);
    assert_ne!(eth_cm2, sol_cm);
}

/// Test rapid sequential deposits (stress test).
#[test]
fn test_rapid_sequential_deposits() {
    let mut env = TestEnvironment::new();

    let num_deposits = 100;
    let amount_each = 1_000_000u128; // 1 USDC each

    let mut expected_eth_total = 0u128;
    let mut expected_sol_total = 0u128;

    for i in 0..num_deposits {
        let chain_id = if i % 2 == 0 {
            ETHEREUM_CHAIN_ID
        } else {
            SOLANA_CHAIN_ID
        };

        env.process_deposit(chain_id, USDC_ASSET_TYPE, amount_each)
            .expect(&format!("Deposit {} should succeed", i));

        if chain_id == ETHEREUM_CHAIN_ID {
            expected_eth_total += amount_each;
        } else {
            expected_sol_total += amount_each;
        }
    }

    // Verify final state
    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(expected_eth_total)
    );
    assert_eq!(
        env.get_chain_deposited(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(expected_sol_total)
    );
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(expected_eth_total + expected_sol_total)
    );

    // All invariants should hold
    env.verify_global_consistency()
        .expect("Invariants should hold after rapid deposits");
}

/// Test parallel deposits followed by parallel withdrawals.
///
/// Deposits on each chain create liquidity for withdrawals to that chain.
#[test]
fn test_parallel_deposits_then_withdrawals() {
    let mut env = TestEnvironment::new();

    // Phase 1: Parallel deposits (creates liquidity for each chain)
    let eth_deposit = 500_000_000u128;
    let sol_deposit = 300_000_000u128;

    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, eth_deposit)
        .expect("ETH deposit should succeed");
    env.process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_deposit)
        .expect("SOL deposit should succeed");

    let supply_after_deposits = env.get_global_supply(USDC_ASSET_TYPE);
    assert_eq!(supply_after_deposits, Amount::from(eth_deposit + sol_deposit));

    // Phase 2: Cross-chain withdrawals (each uses destination chain's liquidity)
    // Withdraw to Solana (uses SOL's 300 liquidity)
    let to_sol = 200_000_000u128;
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, to_sol)
        .expect("Withdrawal to SOL should succeed");

    // Withdraw to Ethereum (uses ETH's 500 liquidity)
    let to_eth = 150_000_000u128;
    env.process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, to_eth)
        .expect("Withdrawal to ETH should succeed");

    // Verify final supply
    let expected_final = eth_deposit + sol_deposit - to_sol - to_eth;
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(expected_final)
    );

    // Verify per-chain tracking
    // ETH: deposited 500, withdrawn 150 (as withdrawal destination)
    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(eth_deposit)
    );
    assert_eq!(
        env.get_chain_withdrawn(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(to_eth)
    );

    // SOL: deposited 300, withdrawn 200 (as withdrawal destination)
    assert_eq!(
        env.get_chain_deposited(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(sol_deposit)
    );
    assert_eq!(
        env.get_chain_withdrawn(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(to_sol)
    );

    // Finalize and verify
    env.finalize_batch().expect("Finalization should succeed");
    env.verify_global_consistency()
        .expect("All invariants should hold");
}

/// Test deposit event creation and processing.
#[test]
fn test_deposit_event_to_receipt() {
    let mut env = TestEnvironment::new();

    // Create deposit events as if coming from chain monitors
    let eth_event = env.create_deposit_event(
        ETHEREUM_CHAIN_ID,
        USDC_ASSET_TYPE,
        100_000_000u128,
        12345,
    );

    let sol_event = env.create_deposit_event(
        SOLANA_CHAIN_ID,
        USDC_ASSET_TYPE,
        200_000_000u128,
        98765,
    );

    // Verify event properties
    assert_eq!(eth_event.source_chain, ETHEREUM_CHAIN_ID);
    assert_eq!(eth_event.block_number, 12345);
    assert_eq!(sol_event.source_chain, SOLANA_CHAIN_ID);
    assert_eq!(sol_event.block_number, 98765);

    // Events should have unique IDs
    assert_ne!(eth_event.unique_id(), sol_event.unique_id());

    // Convert to ingress receipts and process
    // Note: In production, this would use DepositMonitor::process_deposit
    let eth_receipt = IngressReceipt::new(
        eth_event.source_chain,
        eth_event.asset_type,
        eth_event.amount,
        eth_event.beneficiary_cm,
        eth_event.block_number,
    );

    let sol_receipt = IngressReceipt::new(
        sol_event.source_chain,
        sol_event.asset_type,
        sol_event.amount,
        sol_event.beneficiary_cm,
        sol_event.block_number,
    );

    // Process via global state
    let eth_cm = env.random_field();
    env.global_state
        .process_mint(ETHEREUM_CHAIN_ID, &eth_receipt, &[eth_cm])
        .expect("ETH mint should succeed");

    let sol_cm = env.random_field();
    env.global_state
        .process_mint(SOLANA_CHAIN_ID, &sol_receipt, &[sol_cm])
        .expect("SOL mint should succeed");

    // Verify supply
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(300_000_000u128)
    );
}

/// Test parallel deposits with chain state snapshot.
#[test]
fn test_parallel_deposits_state_snapshot() {
    let mut env = TestEnvironment::new();

    // Take snapshot of initial state
    let initial_eth_ingress_size = env
        .global_state
        .get_chain_state(ETHEREUM_CHAIN_ID)
        .unwrap()
        .ingress_size();
    let initial_sol_ingress_size = env
        .global_state
        .get_chain_state(SOLANA_CHAIN_ID)
        .unwrap()
        .ingress_size();

    assert_eq!(initial_eth_ingress_size, 0);
    assert_eq!(initial_sol_ingress_size, 0);

    // Process deposits
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("ETH deposit should succeed");
    env.process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("SOL deposit should succeed");
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 150_000_000u128)
        .expect("Second ETH deposit should succeed");

    // Verify ingress tree sizes
    let final_eth_ingress_size = env
        .global_state
        .get_chain_state(ETHEREUM_CHAIN_ID)
        .unwrap()
        .ingress_size();
    let final_sol_ingress_size = env
        .global_state
        .get_chain_state(SOLANA_CHAIN_ID)
        .unwrap()
        .ingress_size();

    assert_eq!(final_eth_ingress_size, 2); // Two ETH deposits
    assert_eq!(final_sol_ingress_size, 1); // One SOL deposit

    // Verify ingress roots changed
    let eth_roots = env.global_state.get_chain_roots(ETHEREUM_CHAIN_ID).unwrap();
    let sol_roots = env.global_state.get_chain_roots(SOLANA_CHAIN_ID).unwrap();

    // Roots should be non-zero after deposits
    assert_ne!(eth_roots.ingress_root, ark_bn254::Fr::from(0));
    assert_ne!(sol_roots.ingress_root, ark_bn254::Fr::from(0));
}
