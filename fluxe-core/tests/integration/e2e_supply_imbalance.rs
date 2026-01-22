//! Supply imbalance detection tests for FLUXE.
//!
//! Tests imbalance detection and prevention:
//! 1. Deposit 1000 on Ethereum
//! 2. Withdraw 600 on Solana
//! 3. Verify imbalance detection works
//! 4. Verify withdrawal fails if pool has insufficient liquidity

use super::test_utils::*;
use fluxe_core::data_structures::ExitReceipt;
use fluxe_core::errors::StateError;
use fluxe_core::state_manager::ChainState;
use fluxe_core::types::*;

/// Test basic supply imbalance scenario.
///
/// In the liquidity pool model, a "cross-chain imbalance" occurs when one chain
/// has more withdrawals than deposits. This is allowed as long as global supply
/// invariant holds, but each chain must have sufficient liquidity for withdrawals.
#[test]
fn test_basic_supply_imbalance_detection() {
    let mut env = TestEnvironment::new();

    // ========================================
    // Step 1: Deposit 1000 USDC on Ethereum
    // ========================================
    let eth_deposit = 1_000_000_000u128; // 1000 USDC

    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, eth_deposit)
        .expect("ETH deposit should succeed");

    // Seed Solana liquidity for withdrawals
    let sol_liquidity = 1_000_000_000u128; // 1000 USDC
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_liquidity)
        .expect("SOL liquidity should succeed");

    // Verify initial state
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(eth_deposit + sol_liquidity)
    );
    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(eth_deposit)
    );

    // ========================================
    // Step 2: Withdraw 600 USDC on Solana
    // ========================================
    let sol_withdrawal = 600_000_000u128; // 600 USDC

    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_withdrawal)
        .expect("SOL withdrawal should succeed");

    // Verify state after withdrawal
    // Supply = eth_deposit + sol_liquidity - sol_withdrawal
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(eth_deposit + sol_liquidity - sol_withdrawal)
    );

    // ========================================
    // Step 3: Verify imbalance detection works
    // ========================================

    // Chain imbalance check:
    // ETH deposited: 1000, withdrawn: 0 -> net: 1000
    // SOL deposited: 1000 (liquidity), withdrawn: 600 -> net: 400

    // Global supply should still match deposited - withdrawn
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    // Check per-chain state
    let eth_deposited = env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE);
    let eth_withdrawn = env.get_chain_withdrawn(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE);
    let sol_deposited = env.get_chain_deposited(SOLANA_CHAIN_ID, USDC_ASSET_TYPE);
    let sol_withdrawn = env.get_chain_withdrawn(SOLANA_CHAIN_ID, USDC_ASSET_TYPE);

    assert_eq!(eth_deposited, Amount::from(eth_deposit));
    assert_eq!(eth_withdrawn, Amount::zero());
    assert_eq!(sol_deposited, Amount::from(sol_liquidity));
    assert_eq!(sol_withdrawn, Amount::from(sol_withdrawal));

    // ========================================
    // Step 4: Verify global consistency still holds
    // ========================================
    env.verify_global_consistency()
        .expect("Global consistency should hold");
}

/// Test withdrawal fails when insufficient chain liquidity.
///
/// In the liquidity pool model, withdrawals are limited by the destination
/// chain's liquidity, not just global supply.
#[test]
fn test_insufficient_global_supply_withdrawal() {
    let mut env = TestEnvironment::new();

    // Deposit 1000 on Ethereum
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Deposit should succeed");

    // Seed limited Solana liquidity
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("Liquidity should succeed");

    // Withdraw 400 to Solana (within liquidity)
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 400_000_000u128)
        .expect("First withdrawal should succeed");

    // Try to withdraw more than remaining Solana liquidity (200 > 100 remaining)
    let result = env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128);

    assert!(result.is_err(), "Withdrawal exceeding chain liquidity should fail");
}

/// Test withdrawal fails on specific chain with insufficient liquidity.
#[test]
fn test_chain_insufficient_liquidity() {
    let mut env = TestEnvironment::new();

    // Deposit on Ethereum only
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH deposit should succeed");

    // Now try to process an exit on Solana for more than available
    // This tests the per-chain supply check in ChainState::process_exit

    // Get direct access to Solana chain state to test the check
    let mut sol_chain = ChainState::new(SOLANA_CHAIN_ID, ChainType::SVM, TEST_TREE_DEPTH);

    // Try to process exit without any deposits
    let exit_receipt = ExitReceipt::new(
        SOLANA_CHAIN_ID,
        USDC_ASSET_TYPE,
        Amount::from(100_000_000u128),
        env.random_field(), // nullifier
        1,
    );

    let result = sol_chain.process_exit(&exit_receipt);

    assert!(
        matches!(result, Err(StateError::InsufficientSupply)),
        "Exit on chain with no deposits should fail with InsufficientSupply"
    );
}

/// Test supply invariant violation detection.
#[test]
fn test_supply_invariant_violation_detection() {
    let mut env = TestEnvironment::new();

    // Setup normal state
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Deposit should succeed");

    // Invariant should hold
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    // Manually corrupt state to test detection
    // (This simulates a bug that would be caught by invariant checks)
    {
        let chain_state = env
            .global_state
            .get_chain_state_mut(ETHEREUM_CHAIN_ID)
            .unwrap();

        // Artificially increase withdrawn amount to break invariant
        *chain_state.withdrawn.entry(USDC_ASSET_TYPE).or_insert(Amount::zero()) =
            Amount::from(2_000_000_000u128); // More than deposited!
    }

    // Per-chain invariant should now be violated
    let chain_state = env.global_state.get_chain_state(ETHEREUM_CHAIN_ID).unwrap();
    let chain_invariant_result = chain_state.check_supply_invariant(USDC_ASSET_TYPE);

    assert!(
        chain_invariant_result.is_err(),
        "Corrupted chain state should fail invariant check"
    );
}

/// Test maximum withdrawal equals chain liquidity.
#[test]
fn test_maximum_withdrawal_equals_deposits() {
    let mut env = TestEnvironment::new();

    let deposit_amount = 500_000_000u128;

    // Deposit on Ethereum
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, deposit_amount)
        .expect("Deposit should succeed");

    // Seed exact same amount on Solana as liquidity
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, deposit_amount)
        .expect("Liquidity should succeed");

    // Withdraw exact Solana liquidity amount
    let result = env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, deposit_amount);

    assert!(result.is_ok(), "Withdrawing exact liquidity amount should succeed");

    // Global supply should be ETH deposit (Solana liquidity is exhausted but ETH remains)
    assert_eq!(env.get_global_supply(USDC_ASSET_TYPE), Amount::from(deposit_amount));

    // Invariant should still hold
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));
}

/// Test multi-chain deposit and withdrawal scenario.
///
/// With deposits on all chains, each has liquidity for withdrawals to it.
#[test]
fn test_multi_chain_imbalance_scenario() {
    let mut env = TestEnvironment::new()
        .with_chain(BASE_CHAIN_ID, ChainType::EVM);

    // Deposits create liquidity for withdrawals
    // ETH: +1000
    // SOL: +600 (enough for 600 withdrawal)
    // BASE: +500 (enough for 400 withdrawal)
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH deposit should succeed");
    env.process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 600_000_000u128)
        .expect("SOL deposit should succeed");
    env.process_deposit(BASE_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("BASE deposit should succeed");

    // Total: 2100
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(2_100_000_000u128)
    );

    // Withdrawals (each uses destination chain's liquidity)
    // To ETH: -200 (uses ETH's 1000 liquidity)
    // To SOL: -500 (uses SOL's 600 liquidity, leaving 100)
    // To BASE: -300 (uses BASE's 500 liquidity, leaving 200)
    env.process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("ETH withdrawal should succeed");
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("SOL withdrawal should succeed");
    env.process_withdrawal(BASE_CHAIN_ID, USDC_ASSET_TYPE, 300_000_000u128)
        .expect("BASE withdrawal should succeed");

    // Final: 2100 - 1000 = 1100
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(1_100_000_000u128)
    );

    // Verify per-chain net supply:
    // ETH: 1000 - 200 = 800 net positive
    // SOL: 600 - 500 = 100 net positive
    // BASE: 500 - 300 = 200 net positive

    // Global consistency should still hold
    env.verify_global_consistency()
        .expect("Multi-chain should maintain global consistency");
}

/// Test withdrawal ordering affects availability.
#[test]
fn test_withdrawal_ordering() {
    let mut env = TestEnvironment::new();

    // Deposit on Ethereum
    let eth_deposit = 1_000_000_000u128;
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, eth_deposit)
        .expect("Deposit should succeed");

    // Seed Solana with exact liquidity for all withdrawals
    let sol_liquidity = 1_000_000_000u128;
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_liquidity)
        .expect("Liquidity should succeed");

    let initial_supply = eth_deposit + sol_liquidity;

    // Sequential withdrawals that sum to exactly Solana's liquidity
    let withdrawals = [300_000_000u128, 400_000_000u128, 300_000_000u128];
    let mut total_withdrawn = 0u128;

    for (i, &amount) in withdrawals.iter().enumerate() {
        let result = env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, amount);
        assert!(result.is_ok(), "Withdrawal {} should succeed", i);
        total_withdrawn += amount;

        // Check remaining supply
        let remaining = initial_supply - total_withdrawn;
        assert_eq!(env.get_global_supply(USDC_ASSET_TYPE), Amount::from(remaining));
    }

    // Final supply should be the ETH deposit (Solana liquidity exhausted)
    assert_eq!(env.get_global_supply(USDC_ASSET_TYPE), Amount::from(eth_deposit));

    // One more withdrawal to Solana should fail (no liquidity left)
    let result = env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1);
    assert!(result.is_err(), "Withdrawal from empty chain pool should fail");
}

/// Test withdrawal with multiple asset types using per-chain liquidity.
#[test]
fn test_multi_asset_imbalance() {
    let mut env = TestEnvironment::new();

    const USDT: AssetType = 2;

    // Deposit both assets on Ethereum
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("USDC deposit should succeed");
    env.process_deposit(ETHEREUM_CHAIN_ID, USDT, 2_000_000_000u128)
        .expect("USDT deposit should succeed");

    // Seed Solana with limited USDC liquidity but more USDT
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 900_000_000u128)
        .expect("USDC liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDT, 2_000_000_000u128)
        .expect("USDT liquidity should succeed");

    // Withdraw most of USDC to Solana (uses Solana's USDC liquidity)
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 800_000_000u128)
        .expect("USDC withdrawal should succeed");

    // Try to withdraw more USDC than Solana's remaining liquidity (200 > 100)
    let result = env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128);
    assert!(result.is_err(), "Excess USDC withdrawal should fail");

    // But USDT should still be available (Solana has 2000 USDT liquidity)
    env.process_withdrawal(SOLANA_CHAIN_ID, USDT, 1_500_000_000u128)
        .expect("USDT withdrawal should succeed");

    // Verify per-asset supplies
    // USDC: 1000 (ETH) + 900 (SOL) - 800 (withdrawal) = 1100
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(1_100_000_000u128)
    );
    // USDT: 2000 (ETH) + 2000 (SOL) - 1500 (withdrawal) = 2500
    assert_eq!(
        env.get_global_supply(USDT),
        Amount::from(2_500_000_000u128)
    );
}

/// Test zero withdrawal handling.
#[test]
fn test_zero_withdrawal() {
    let mut env = TestEnvironment::new();

    // Deposit some funds
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Deposit should succeed");

    // Try zero withdrawal - should succeed (no-op effectively)
    let result = env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 0);

    // Zero withdrawal should succeed (it's a valid no-op)
    assert!(result.is_ok(), "Zero withdrawal should be allowed");

    // Supply should be unchanged
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(1_000_000_000u128)
    );
}

/// Test concurrent deposits and withdrawals maintain invariant.
#[test]
fn test_concurrent_deposit_withdrawal_invariant() {
    let mut env = TestEnvironment::new();

    // Interleave deposits and withdrawals
    for i in 0..10 {
        // Deposit on alternating chains
        let deposit_chain = if i % 2 == 0 {
            ETHEREUM_CHAIN_ID
        } else {
            SOLANA_CHAIN_ID
        };
        let deposit_amount = ((i + 1) * 100_000_000) as u128;

        env.process_deposit(deposit_chain, USDC_ASSET_TYPE, deposit_amount)
            .expect("Deposit should succeed");

        // Withdraw smaller amount to the other chain
        if i > 0 {
            let withdrawal_chain = if i % 2 == 0 {
                SOLANA_CHAIN_ID
            } else {
                ETHEREUM_CHAIN_ID
            };
            let withdrawal_amount = ((i) * 50_000_000) as u128;

            // Check if we have enough supply first
            let current_supply = env.get_global_supply(USDC_ASSET_TYPE);
            if current_supply >= Amount::from(withdrawal_amount) {
                env.process_withdrawal(withdrawal_chain, USDC_ASSET_TYPE, withdrawal_amount)
                    .expect("Withdrawal should succeed");
            }
        }

        // Invariant should hold at every step
        assert!(
            env.check_supply_invariant(USDC_ASSET_TYPE),
            "Invariant should hold after operation {}",
            i
        );
    }

    // Final consistency check
    env.verify_global_consistency()
        .expect("Final state should be consistent");
}

/// Test liquidity rebalancing through additional deposits.
#[test]
fn test_imbalance_recovery() {
    let mut env = TestEnvironment::new();

    // Deposit on ETH
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH deposit should succeed");

    // Seed initial Solana liquidity
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("SOL liquidity should succeed");

    // Withdraw to Solana
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 800_000_000u128)
        .expect("SOL withdrawal should succeed");

    // State: SOL deposited 1000, SOL withdrawn 800 -> 200 remaining liquidity

    // "Rebalance" by depositing more on Solana
    env.process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 800_000_000u128)
        .expect("SOL rebalance deposit should succeed");

    // Now SOL has more liquidity: deposited 1800, withdrawn 800 -> 1000 remaining
    assert_eq!(
        env.get_chain_deposited(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(1_800_000_000u128) // 1000 initial + 800 rebalance
    );
    assert_eq!(
        env.get_chain_withdrawn(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(800_000_000u128)
    );

    // Global supply: 1000 (ETH) + 1000 (SOL initial) + 800 (SOL rebalance) - 800 (withdrawal) = 2000
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(2_000_000_000u128)
    );

    env.verify_global_consistency()
        .expect("Rebalanced state should be consistent");
}

/// Test large withdrawal scenario with sufficient liquidity.
#[test]
fn test_extreme_imbalance() {
    let mut env = TestEnvironment::new();

    // Large deposit on Ethereum
    let large_deposit = 10_000_000_000_000u128; // 10 million USDC
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, large_deposit)
        .expect("Large deposit should succeed");

    // Seed large Solana liquidity
    let sol_liquidity = 10_000_000_000_000u128; // 10 million USDC
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_liquidity)
        .expect("Large liquidity should succeed");

    // Withdraw 99% of Solana liquidity
    let large_withdrawal = sol_liquidity * 99 / 100;
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, large_withdrawal)
        .expect("Large withdrawal should succeed");

    // Supply = ETH + SOL - withdrawal
    let remaining = large_deposit + sol_liquidity - large_withdrawal;
    assert_eq!(env.get_global_supply(USDC_ASSET_TYPE), Amount::from(remaining));

    // Global invariant should still hold
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));
    env.verify_global_consistency()
        .expect("Large withdrawal should maintain consistency");
}
