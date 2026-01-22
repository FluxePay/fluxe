//! End-to-end cross-chain flow tests for FLUXE.
//!
//! Tests the complete flow:
//! 1. Deposit on Ethereum (chain_id=1)
//! 2. Create ingress receipt
//! 3. Mint note on FLUXE
//! 4. Burn note targeting Solana (chain_id=501)
//! 5. Generate exit receipt and Merkle proof
//! 6. Verify withdrawal on Solana

use super::test_utils::*;
use fluxe_core::bridge::{WithdrawalProof, WithdrawalStatus};
use fluxe_core::merkle::TreeParams;
use fluxe_core::types::*;
use ark_bn254::Fr as F;
use ark_serialize::CanonicalSerialize;

/// Test the complete cross-chain flow: Ethereum deposit -> Solana withdrawal.
///
/// Note: In the FLUXE liquidity pool model, each chain must have deposits to
/// enable withdrawals. This simulates liquidity providers seeding each chain.
#[test]
fn test_basic_eth_to_solana_flow() {
    let mut env = TestEnvironment::new();

    // ========================================
    // Step 0: Seed liquidity on Solana
    // In production, liquidity providers would deposit on each chain
    // ========================================
    let liquidity_amount = 500_000_000u128; // 500 USDC liquidity on Solana
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, liquidity_amount)
        .expect("Seeding Solana liquidity should succeed");

    // ========================================
    // Step 1: Deposit 100 USDC on Ethereum
    // ========================================
    let deposit_amount = 100_000_000u128; // 100 USDC (6 decimals)

    let (ingress_receipt, _note_commitment) = env
        .process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, deposit_amount)
        .expect("Deposit on Ethereum should succeed");

    // Verify ingress receipt fields
    assert_eq!(ingress_receipt.source_chain, ETHEREUM_CHAIN_ID);
    assert_eq!(ingress_receipt.asset_type, USDC_ASSET_TYPE);
    assert_eq!(ingress_receipt.amount, Amount::from(deposit_amount));

    // Verify global supply was updated (includes liquidity)
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(deposit_amount + liquidity_amount)
    );

    // Verify chain state was updated
    assert_eq!(
        env.get_chain_deposited(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(deposit_amount)
    );

    // ========================================
    // Step 2: Burn note targeting Solana
    // ========================================
    let withdrawal_amount = 60_000_000u128; // 60 USDC

    let (exit_receipt, nullifier) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, withdrawal_amount)
        .expect("Burn targeting Solana should succeed");

    // Verify exit receipt fields
    assert_eq!(exit_receipt.destination_chain, SOLANA_CHAIN_ID);
    assert_eq!(exit_receipt.asset_type, USDC_ASSET_TYPE);
    assert_eq!(exit_receipt.amount, Amount::from(withdrawal_amount));
    assert_eq!(exit_receipt.burned_nf, nullifier);

    // Verify global supply was decreased
    // Supply = liquidity + deposit - withdrawal
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(liquidity_amount + deposit_amount - withdrawal_amount)
    );

    // Verify nullifier is now spent
    assert!(env.global_state.nullifier_exists(nullifier));

    // Verify chain state was updated for Solana
    assert_eq!(
        env.get_chain_withdrawn(SOLANA_CHAIN_ID, USDC_ASSET_TYPE),
        Amount::from(withdrawal_amount)
    );

    // ========================================
    // Step 3: Finalize batch and generate proofs
    // ========================================
    let finalized_withdrawals = env
        .finalize_batch()
        .expect("Batch finalization should succeed");

    // Verify Solana withdrawal was processed
    assert!(finalized_withdrawals.contains_key(&SOLANA_CHAIN_ID));
    let sol_withdrawals = finalized_withdrawals.get(&SOLANA_CHAIN_ID).unwrap();
    assert_eq!(sol_withdrawals.len(), 1);

    // ========================================
    // Step 4: Verify withdrawal proof is ready
    // ========================================
    let exit_hash = &sol_withdrawals[0];
    let status = env
        .get_withdrawal_status(SOLANA_CHAIN_ID, exit_hash)
        .expect("Withdrawal should exist");

    assert_eq!(status, WithdrawalStatus::Ready);

    // Get the exit tree root for proof verification
    let exit_root = env
        .get_exit_tree_root(SOLANA_CHAIN_ID)
        .expect("Exit tree should exist");

    // Get the withdrawal proof
    let proof = env
        .withdrawal_processor
        .get_withdrawal_proof(SOLANA_CHAIN_ID, exit_hash, exit_root)
        .expect("Withdrawal proof should be available");

    // Verify the proof is valid
    let params = TreeParams::new(TEST_TREE_DEPTH);
    assert!(proof.verify(&params), "Withdrawal proof should be valid");

    // ========================================
    // Step 5: Claim withdrawal on Solana
    // ========================================
    env.claim_withdrawal(SOLANA_CHAIN_ID, exit_hash)
        .expect("Claiming withdrawal should succeed");

    let final_status = env
        .get_withdrawal_status(SOLANA_CHAIN_ID, exit_hash)
        .expect("Withdrawal should exist");

    assert_eq!(final_status, WithdrawalStatus::Claimed);

    // ========================================
    // Step 6: Verify final state consistency
    // ========================================
    env.verify_global_consistency()
        .expect("Global state should be consistent");
}

/// Test bi-directional cross-chain flow: ETH->SOL and SOL->ETH.
///
/// This test shows the bi-directional liquidity pool model where deposits
/// on each chain create liquidity that can be withdrawn to.
#[test]
fn test_bidirectional_cross_chain_flow() {
    let mut env = TestEnvironment::new();

    // ========================================
    // Deposit on both chains (this also creates liquidity)
    // ========================================
    let eth_deposit = 500_000_000u128; // 500 USDC
    let sol_deposit = 300_000_000u128; // 300 USDC

    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, eth_deposit)
        .expect("ETH deposit should succeed");

    env.process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_deposit)
        .expect("SOL deposit should succeed");

    // Verify combined supply
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(eth_deposit + sol_deposit)
    );

    // ========================================
    // Cross-chain withdrawals
    // Withdrawing to a chain uses that chain's deposited liquidity
    // ========================================

    // Withdraw to Solana (uses SOL chain's liquidity)
    let eth_to_sol = 200_000_000u128;
    let (_exit_eth_to_sol, _) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, eth_to_sol)
        .expect("ETH->SOL withdrawal should succeed");

    // Withdraw to Ethereum (uses ETH chain's liquidity)
    let sol_to_eth = 150_000_000u128;
    let (_exit_sol_to_eth, _) = env
        .process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, sol_to_eth)
        .expect("SOL->ETH withdrawal should succeed");

    // Verify supply after withdrawals
    let expected_supply = eth_deposit + sol_deposit - eth_to_sol - sol_to_eth;
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(expected_supply)
    );

    // ========================================
    // Finalize and verify proofs for both chains
    // ========================================
    let finalized = env.finalize_batch().expect("Finalization should succeed");

    // Both chains should have withdrawals
    assert!(finalized.contains_key(&SOLANA_CHAIN_ID));
    assert!(finalized.contains_key(&ETHEREUM_CHAIN_ID));

    // Verify proofs are ready
    let params = TreeParams::new(TEST_TREE_DEPTH);

    for chain_id in [SOLANA_CHAIN_ID, ETHEREUM_CHAIN_ID] {
        for exit_hash in finalized.get(&chain_id).unwrap() {
            let status = env.get_withdrawal_status(chain_id, exit_hash).unwrap();
            assert_eq!(status, WithdrawalStatus::Ready);

            // Verify proof validity
            let exit_root = env.get_exit_tree_root(chain_id).unwrap();
            let proof = env
                .withdrawal_processor
                .get_withdrawal_proof(chain_id, exit_hash, exit_root)
                .expect("Proof should be available");
            assert!(proof.verify(&params));
        }
    }

    // Global consistency check
    env.verify_global_consistency()
        .expect("Global state should be consistent");
}

/// Test multiple sequential cross-chain transactions.
///
/// This test demonstrates sequential withdrawals from a chain with sufficient liquidity.
#[test]
fn test_sequential_cross_chain_transactions() {
    let mut env = TestEnvironment::new();

    // Seed Solana with enough liquidity for all withdrawals
    let solana_liquidity = 10_000_000_000u128;
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, solana_liquidity)
        .expect("Seeding Solana liquidity should succeed");

    // Initial large deposit on Ethereum
    let eth_deposit = 10_000_000_000u128;
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, eth_deposit)
        .expect("Initial deposit should succeed");

    // Total initial supply
    let initial_supply = solana_liquidity + eth_deposit;

    // Perform 10 sequential cross-chain transactions
    let mut total_withdrawn = 0u128;

    for i in 0..10 {
        let amount = (i + 1) as u128 * 100_000_000; // 100, 200, ... 1000 USDC

        let (_, _) = env
            .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, amount)
            .expect(&format!("Withdrawal {} should succeed", i));

        total_withdrawn += amount;

        // Verify incremental supply decrease
        let expected = initial_supply - total_withdrawn;
        assert_eq!(
            env.get_global_supply(USDC_ASSET_TYPE),
            Amount::from(expected)
        );
    }

    // Total withdrawn should be sum of 100+200+...+1000 = 5500 USDC
    assert_eq!(total_withdrawn, 5_500_000_000u128);

    // Finalize all withdrawals
    let finalized = env.finalize_batch().expect("Finalization should succeed");

    // All 10 withdrawals should be ready
    assert_eq!(finalized.get(&SOLANA_CHAIN_ID).unwrap().len(), 10);
}

/// Test cross-chain with multiple asset types.
#[test]
fn test_multi_asset_cross_chain() {
    let mut env = TestEnvironment::new();

    // Asset types
    const USDT_ASSET_TYPE: AssetType = 2;
    const DAI_ASSET_TYPE: AssetType = 3;

    // Seed Solana with liquidity for each asset
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1000_000_000u128)
        .expect("USDC liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDT_ASSET_TYPE, 2000_000_000u128)
        .expect("USDT liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, DAI_ASSET_TYPE, 3000_000_000u128)
        .expect("DAI liquidity should succeed");

    // Deposit different assets on Ethereum
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1000_000_000u128)
        .expect("USDC deposit should succeed");
    env.process_deposit(ETHEREUM_CHAIN_ID, USDT_ASSET_TYPE, 2000_000_000u128)
        .expect("USDT deposit should succeed");
    env.process_deposit(ETHEREUM_CHAIN_ID, DAI_ASSET_TYPE, 3000_000_000u128)
        .expect("DAI deposit should succeed");

    // Withdraw each to Solana (uses Solana's liquidity)
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("USDC withdrawal should succeed");
    env.process_withdrawal(SOLANA_CHAIN_ID, USDT_ASSET_TYPE, 1000_000_000u128)
        .expect("USDT withdrawal should succeed");
    env.process_withdrawal(SOLANA_CHAIN_ID, DAI_ASSET_TYPE, 1500_000_000u128)
        .expect("DAI withdrawal should succeed");

    // Verify per-asset supplies (liquidity + deposit - withdrawal)
    // USDC: 1000 (SOL liq) + 1000 (ETH dep) - 500 (withdrawal) = 1500
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(1500_000_000u128)
    );
    // USDT: 2000 (SOL liq) + 2000 (ETH dep) - 1000 (withdrawal) = 3000
    assert_eq!(
        env.get_global_supply(USDT_ASSET_TYPE),
        Amount::from(3000_000_000u128)
    );
    // DAI: 3000 (SOL liq) + 3000 (ETH dep) - 1500 (withdrawal) = 4500
    assert_eq!(
        env.get_global_supply(DAI_ASSET_TYPE),
        Amount::from(4500_000_000u128)
    );

    // Finalize and verify all withdrawals are ready
    let finalized = env.finalize_batch().expect("Finalization should succeed");
    assert_eq!(finalized.get(&SOLANA_CHAIN_ID).unwrap().len(), 3);

    // Verify invariant holds for all assets
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));
    assert!(env.check_supply_invariant(USDT_ASSET_TYPE));
    assert!(env.check_supply_invariant(DAI_ASSET_TYPE));
}

/// Test that exit receipts have unique hashes even with same parameters.
#[test]
fn test_exit_receipt_uniqueness() {
    let mut env = TestEnvironment::new();

    // Seed Solana liquidity for withdrawals
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Seeding liquidity should succeed");

    // Deposit on Ethereum
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Deposit should succeed");

    // Create multiple identical withdrawals
    let amount = 100_000_000u128;
    let mut exit_hashes: Vec<F> = Vec::new();

    for _ in 0..5 {
        let (exit_receipt, _) = env
            .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, amount)
            .expect("Withdrawal should succeed");

        let hash = exit_receipt.hash();

        // Verify hash is unique
        assert!(!exit_hashes.contains(&hash), "Exit receipt hash should be unique");
        exit_hashes.push(hash);
    }
}

/// Test double-spend prevention across chains.
#[test]
fn test_double_spend_prevention() {
    let mut env = TestEnvironment::new();

    // Seed Solana liquidity
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("Seeding liquidity should succeed");

    // Deposit on Ethereum
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("Deposit should succeed");

    // First withdrawal succeeds
    let (_exit_receipt, nullifier) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("First withdrawal should succeed");

    // Nullifier should be recorded
    assert!(env.global_state.nullifier_exists(nullifier));

    // Attempting to use the same nullifier should fail
    // (In a real scenario, this would happen via a crafted transaction)
    // Here we verify the nullifier check mechanism works
    let random_commitment = env.random_field();
    let transfer_result = env.global_state.process_transfer(
        &[nullifier], // Reuse nullifier - should fail
        &[random_commitment],
    );

    assert!(transfer_result.is_err(), "Reusing nullifier should fail");
}

/// Test withdrawal proof serialization and verification.
#[test]
fn test_withdrawal_proof_serialization() {
    let mut env = TestEnvironment::new();

    // Seed Solana liquidity
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("Seeding liquidity should succeed");

    // Setup and create withdrawal
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("Deposit should succeed");

    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("Withdrawal should succeed");

    let finalized = env.finalize_batch().expect("Finalization should succeed");
    let exit_hash = &finalized.get(&SOLANA_CHAIN_ID).unwrap()[0];

    // Get proof
    let exit_root = env.get_exit_tree_root(SOLANA_CHAIN_ID).unwrap();
    let proof = env
        .withdrawal_processor
        .get_withdrawal_proof(SOLANA_CHAIN_ID, exit_hash, exit_root)
        .expect("Proof should be available");

    // Serialize proof
    let bytes = proof.to_bytes();

    // Verify non-empty serialization
    assert!(!bytes.is_empty(), "Proof serialization should not be empty");

    // Verify minimum expected size:
    // exit_hash(32) + batch_id(8) + exit_root(32) + leaf_index(8) + num_siblings(4) + siblings(32*depth)
    let min_expected_size = 32 + 8 + 32 + 8 + 4;
    assert!(
        bytes.len() >= min_expected_size,
        "Serialized proof should have minimum size"
    );
}

/// Test batch finalization with empty batch.
#[test]
fn test_empty_batch_finalization() {
    let mut env = TestEnvironment::new();

    // No deposits or withdrawals - finalize empty batch
    let finalized = env.finalize_batch().expect("Empty batch finalization should succeed");

    // Should return empty results (no withdrawals to process)
    assert!(finalized.is_empty() || finalized.values().all(|v| v.is_empty()));
}

/// Test cross-chain flow with three chains.
///
/// With deposits on all chains, each chain has liquidity for cross-chain withdrawals.
#[test]
fn test_three_chain_cross_flow() {
    let mut env = TestEnvironment::new()
        .with_chain(BASE_CHAIN_ID, ChainType::EVM);

    // Deposit on all three chains (creates liquidity for withdrawals to each)
    env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1000_000_000u128)
        .expect("ETH deposit should succeed");
    env.process_deposit(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 2000_000_000u128)
        .expect("SOL deposit should succeed");
    env.process_deposit(BASE_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("BASE deposit should succeed");

    // Total supply should be sum of all deposits
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(3500_000_000u128)
    );

    // Withdraw to each chain (uses that chain's deposited liquidity)
    // Withdraw to Solana (uses SOL's 2000 liquidity)
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 300_000_000u128)
        .expect("Withdraw to SOL should succeed");
    // Withdraw to Base (uses BASE's 500 liquidity)
    env.process_withdrawal(BASE_CHAIN_ID, USDC_ASSET_TYPE, 400_000_000u128)
        .expect("Withdraw to BASE should succeed");
    // Withdraw to Ethereum (uses ETH's 1000 liquidity)
    env.process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("Withdraw to ETH should succeed");

    // Verify final supply
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(2600_000_000u128)
    );

    // Finalize and verify all chains have withdrawals
    let finalized = env.finalize_batch().expect("Finalization should succeed");

    assert!(finalized.contains_key(&SOLANA_CHAIN_ID));
    assert!(finalized.contains_key(&BASE_CHAIN_ID));
    assert!(finalized.contains_key(&ETHEREUM_CHAIN_ID));

    // Verify consistency
    env.verify_global_consistency()
        .expect("State should be consistent");
}
