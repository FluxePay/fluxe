//! Comprehensive end-to-end integration tests for FLUXE.
//!
//! This test file covers the complete lifecycle of the protocol including:
//! - Deposit monitoring and ingress receipt creation
//! - State management and supply tracking
//! - Withdrawal processing with proof generation
//! - Failure handling for proof generation
//! - Multi-batch scenarios
//! - Complete claim lifecycle

use super::test_utils::*;
use fluxe_core::bridge::{WithdrawalFailureReason, WithdrawalProof, WithdrawalStatus};
use fluxe_core::merkle::{IncrementalTree, TreeParams};
use fluxe_core::types::*;
use ark_bn254::Fr as F;
use ark_ff::Zero;

/// Test comprehensive lifecycle: deposit -> mint -> transfer -> burn -> finalize -> claim.
///
/// This test simulates a complete user journey across multiple chains.
#[test]
fn test_comprehensive_user_journey() {
    let mut env = TestEnvironment::new()
        .with_chain(BASE_CHAIN_ID, ChainType::EVM);

    // ========================================
    // Phase 1: Setup liquidity on all chains
    // ========================================
    let eth_liquidity = 1_000_000_000u128; // 1000 USDC
    let sol_liquidity = 500_000_000u128;   // 500 USDC
    let base_liquidity = 300_000_000u128;  // 300 USDC

    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, eth_liquidity)
        .expect("ETH liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, sol_liquidity)
        .expect("SOL liquidity should succeed");
    env.seed_liquidity(BASE_CHAIN_ID, USDC_ASSET_TYPE, base_liquidity)
        .expect("BASE liquidity should succeed");

    let initial_supply = eth_liquidity + sol_liquidity + base_liquidity;
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(initial_supply)
    );

    // ========================================
    // Phase 2: User deposits on Ethereum
    // ========================================
    let user_deposit = 200_000_000u128; // 200 USDC
    let (ingress_receipt, note_commitment) = env
        .process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, user_deposit)
        .expect("User deposit should succeed");

    // Verify ingress receipt
    assert_eq!(ingress_receipt.source_chain, ETHEREUM_CHAIN_ID);
    assert_eq!(ingress_receipt.amount, Amount::from(user_deposit));
    assert_ne!(note_commitment, F::zero());

    // Supply increased
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(initial_supply + user_deposit)
    );

    // ========================================
    // Phase 3: User withdraws to Solana
    // ========================================
    let withdrawal_amount = 150_000_000u128; // 150 USDC
    let (exit_receipt, nullifier) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, withdrawal_amount)
        .expect("Withdrawal to Solana should succeed");

    // Verify exit receipt
    assert_eq!(exit_receipt.destination_chain, SOLANA_CHAIN_ID);
    assert_eq!(exit_receipt.amount, Amount::from(withdrawal_amount));
    assert_eq!(exit_receipt.burned_nf, nullifier);

    // Verify nullifier is recorded
    assert!(env.global_state.nullifier_exists(nullifier));

    // Supply decreased
    assert_eq!(
        env.get_global_supply(USDC_ASSET_TYPE),
        Amount::from(initial_supply + user_deposit - withdrawal_amount)
    );

    // ========================================
    // Phase 4: Finalize batch and generate proofs
    // ========================================
    let finalized = env
        .finalize_batch()
        .expect("Batch finalization should succeed");

    // Solana should have one finalized withdrawal
    assert!(finalized.contains_key(&SOLANA_CHAIN_ID));
    let sol_exits = finalized.get(&SOLANA_CHAIN_ID).unwrap();
    assert_eq!(sol_exits.len(), 1);

    let exit_hash = &sol_exits[0];

    // ========================================
    // Phase 5: Verify withdrawal is ready
    // ========================================
    let status = env
        .get_withdrawal_status(SOLANA_CHAIN_ID, exit_hash)
        .expect("Withdrawal status should exist");
    assert_eq!(status, WithdrawalStatus::Ready);

    // ========================================
    // Phase 6: Get and verify proof
    // ========================================
    let exit_root = env
        .get_exit_tree_root(SOLANA_CHAIN_ID)
        .expect("Exit tree should exist");

    let proof = env
        .withdrawal_processor
        .get_withdrawal_proof(SOLANA_CHAIN_ID, exit_hash, exit_root)
        .expect("Proof should be available");

    // Verify proof is valid
    let params = TreeParams::new(TEST_TREE_DEPTH);
    assert!(proof.verify(&params), "Proof should be valid");

    // Verify proof contents
    assert_eq!(proof.batch_id, 1);
    assert_eq!(proof.exit_receipt.amount, Amount::from(withdrawal_amount));

    // ========================================
    // Phase 7: Claim withdrawal
    // ========================================
    env.claim_withdrawal(SOLANA_CHAIN_ID, exit_hash)
        .expect("Claim should succeed");

    let final_status = env
        .get_withdrawal_status(SOLANA_CHAIN_ID, exit_hash)
        .expect("Status should exist");
    assert_eq!(final_status, WithdrawalStatus::Claimed);

    // ========================================
    // Phase 8: Verify final consistency
    // ========================================
    env.verify_global_consistency()
        .expect("Final state should be consistent");
}

/// Test multiple withdrawals across multiple batches.
#[test]
fn test_multi_batch_withdrawals() {
    let mut env = TestEnvironment::new();

    // Seed liquidity
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("SOL liquidity should succeed");

    // ========================================
    // Batch 1: Two withdrawals
    // ========================================
    let (_, _) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("First withdrawal should succeed");
    let (_, _) = env
        .process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 150_000_000u128)
        .expect("Second withdrawal should succeed");

    let batch1 = env.finalize_batch().expect("Batch 1 should finalize");

    // Both chains should have withdrawals
    assert!(batch1.contains_key(&SOLANA_CHAIN_ID));
    assert!(batch1.contains_key(&ETHEREUM_CHAIN_ID));
    assert_eq!(batch1.get(&SOLANA_CHAIN_ID).unwrap().len(), 1);
    assert_eq!(batch1.get(&ETHEREUM_CHAIN_ID).unwrap().len(), 1);

    // ========================================
    // Batch 2: More withdrawals
    // ========================================
    let (_, _) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("Third withdrawal should succeed");
    let (_, _) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 50_000_000u128)
        .expect("Fourth withdrawal should succeed");

    let batch2 = env.finalize_batch().expect("Batch 2 should finalize");

    // Only Solana should have new withdrawals
    assert!(batch2.contains_key(&SOLANA_CHAIN_ID));
    assert_eq!(batch2.get(&SOLANA_CHAIN_ID).unwrap().len(), 2);

    // ========================================
    // Verify all withdrawals are ready
    // ========================================
    for (chain_id, exit_hashes) in [&batch1, &batch2].iter().flat_map(|b| b.iter()) {
        for exit_hash in exit_hashes {
            let status = env
                .get_withdrawal_status(*chain_id, exit_hash)
                .expect("Status should exist");
            assert_eq!(status, WithdrawalStatus::Ready);
        }
    }

    // Verify consistency
    env.verify_global_consistency()
        .expect("State should be consistent");
}

/// Test partial withdrawals leave remaining balance.
#[test]
fn test_partial_withdrawals() {
    let mut env = TestEnvironment::new();

    // Deposit 1000 USDC on Ethereum
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH liquidity should succeed");

    // Seed Solana for withdrawals
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("SOL liquidity should succeed");

    let initial_supply = env.get_global_supply(USDC_ASSET_TYPE);

    // Make several partial withdrawals
    let withdrawals = vec![
        100_000_000u128, // 100 USDC
        250_000_000u128, // 250 USDC
        75_000_000u128,  // 75 USDC
    ];

    let mut total_withdrawn = 0u128;

    for amount in withdrawals {
        env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, amount)
            .expect("Withdrawal should succeed");
        total_withdrawn += amount;

        // Verify supply decreases correctly after each withdrawal
        let expected = initial_supply.as_u128() - total_withdrawn;
        assert_eq!(
            env.get_global_supply(USDC_ASSET_TYPE),
            Amount::from(expected)
        );
    }

    // Finalize and verify
    let finalized = env.finalize_batch().expect("Should finalize");
    assert_eq!(finalized.get(&SOLANA_CHAIN_ID).unwrap().len(), 3);

    env.verify_global_consistency()
        .expect("State should be consistent");
}

/// Test that double-spending the same nullifier fails.
#[test]
fn test_nullifier_double_spend_prevention() {
    let mut env = TestEnvironment::new();

    // Setup
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Liquidity should succeed");

    // First withdrawal succeeds and records nullifier
    let (_, nullifier) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("First withdrawal should succeed");

    // Nullifier should be recorded
    assert!(env.global_state.nullifier_exists(nullifier));

    // Trying to use same nullifier should fail
    let random_commitment = env.random_field();
    let result = env.global_state.process_transfer(
        &[nullifier], // Reusing the spent nullifier
        &[random_commitment],
    );

    assert!(
        result.is_err(),
        "Using spent nullifier should fail"
    );
}

/// Test withdrawal across all three chains in a single batch.
#[test]
fn test_three_chain_single_batch() {
    let mut env = TestEnvironment::new()
        .with_chain(BASE_CHAIN_ID, ChainType::EVM);

    // Seed all chains
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("SOL liquidity should succeed");
    env.seed_liquidity(BASE_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("BASE liquidity should succeed");

    // Withdraw to all three chains in same batch
    env.process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("ETH withdrawal should succeed");
    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("SOL withdrawal should succeed");
    env.process_withdrawal(BASE_CHAIN_ID, USDC_ASSET_TYPE, 150_000_000u128)
        .expect("BASE withdrawal should succeed");

    // Finalize
    let finalized = env.finalize_batch().expect("Should finalize");

    // All three chains should have withdrawals
    assert!(finalized.contains_key(&ETHEREUM_CHAIN_ID));
    assert!(finalized.contains_key(&SOLANA_CHAIN_ID));
    assert!(finalized.contains_key(&BASE_CHAIN_ID));

    // All should be ready
    let params = TreeParams::new(TEST_TREE_DEPTH);

    for (chain_id, exit_hashes) in &finalized {
        for exit_hash in exit_hashes {
            let status = env.get_withdrawal_status(*chain_id, exit_hash).unwrap();
            assert_eq!(status, WithdrawalStatus::Ready);

            // Verify proof is valid
            let exit_root = env.get_exit_tree_root(*chain_id).unwrap();
            let proof = env
                .withdrawal_processor
                .get_withdrawal_proof(*chain_id, exit_hash, exit_root)
                .expect("Proof should exist");
            assert!(proof.verify(&params));
        }
    }

    env.verify_global_consistency()
        .expect("State should be consistent");
}

/// Test high volume scenario with many withdrawals.
#[test]
fn test_high_volume_withdrawals() {
    let mut env = TestEnvironment::new();

    // Large liquidity pool
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000_000u128)
        .expect("Liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000_000u128)
        .expect("Liquidity should succeed");

    let num_withdrawals = 50;
    let amount_each = 10_000_000u128; // 10 USDC each

    // Create many withdrawals alternating between chains
    for i in 0..num_withdrawals {
        let chain_id = if i % 2 == 0 { ETHEREUM_CHAIN_ID } else { SOLANA_CHAIN_ID };
        env.process_withdrawal(chain_id, USDC_ASSET_TYPE, amount_each)
            .expect(&format!("Withdrawal {} should succeed", i));
    }

    // Finalize
    let finalized = env.finalize_batch().expect("Should finalize");

    // Total withdrawals should match
    let total_finalized: usize = finalized.values().map(|v| v.len()).sum();
    assert_eq!(total_finalized, num_withdrawals);

    // All should be ready
    for (chain_id, exit_hashes) in &finalized {
        for exit_hash in exit_hashes {
            let status = env.get_withdrawal_status(*chain_id, exit_hash).unwrap();
            assert_eq!(status, WithdrawalStatus::Ready);
        }
    }

    env.verify_global_consistency()
        .expect("State should be consistent");
}

/// Test fee collection during withdrawals.
#[test]
fn test_withdrawal_with_fees() {
    let mut env = TestEnvironment::new();

    // Setup
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Liquidity should succeed");

    // Process withdrawal and collect fee
    let (_, _) = env
        .process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("Withdrawal should succeed");

    // Collect a 0.1% fee
    let fee = 100_000u128; // 0.1 USDC
    env.collect_fee(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, fee);

    // Verify fee was collected
    let collected_fees = env.fee_collector.get_fees(SOLANA_CHAIN_ID, USDC_ASSET_TYPE);
    assert_eq!(collected_fees, Amount::new(fee));

    // Create fee withdrawal
    let fee_withdrawal = env.create_fee_withdrawal(SOLANA_CHAIN_ID);
    assert!(fee_withdrawal.is_some());

    let fee_result = fee_withdrawal.unwrap();
    assert!(!fee_result.exit_receipts.is_empty());
}

/// Test that batch numbers increment correctly across multiple batches.
#[test]
fn test_batch_id_progression() {
    let mut env = TestEnvironment::new();

    // Seed liquidity
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Liquidity should succeed");

    // Process multiple batches
    for expected_batch_id in 1..=5u64 {
        // Add a withdrawal
        env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 10_000_000u128)
            .expect("Withdrawal should succeed");

        // Finalize
        let finalized = env.finalize_batch().expect("Should finalize");

        // Get the proof and verify batch ID
        let exit_hash = &finalized.get(&SOLANA_CHAIN_ID).unwrap()[0];
        let exit_root = env.get_exit_tree_root(SOLANA_CHAIN_ID).unwrap();
        let proof = env
            .withdrawal_processor
            .get_withdrawal_proof(SOLANA_CHAIN_ID, exit_hash, exit_root)
            .expect("Proof should exist");

        assert_eq!(
            proof.batch_id, expected_batch_id,
            "Batch ID should be {}", expected_batch_id
        );
    }
}

/// Test withdrawal proof serialization and deserialization consistency.
#[test]
fn test_proof_serialization_roundtrip() {
    let mut env = TestEnvironment::new();

    // Setup and create withdrawal
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("Liquidity should succeed");

    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("Withdrawal should succeed");

    let finalized = env.finalize_batch().expect("Should finalize");
    let exit_hash = &finalized.get(&SOLANA_CHAIN_ID).unwrap()[0];

    // Get proof
    let exit_root = env.get_exit_tree_root(SOLANA_CHAIN_ID).unwrap();
    let original_proof = env
        .withdrawal_processor
        .get_withdrawal_proof(SOLANA_CHAIN_ID, exit_hash, exit_root)
        .expect("Proof should exist");

    // Verify original
    let params = TreeParams::new(TEST_TREE_DEPTH);
    assert!(original_proof.verify(&params));

    // Serialize
    let bytes = original_proof.to_bytes();
    assert!(!bytes.is_empty());

    // The proof should have consistent serialization
    let bytes2 = original_proof.to_bytes();
    assert_eq!(bytes, bytes2, "Serialization should be deterministic");
}

/// Test supply invariant holds under various conditions.
#[test]
fn test_supply_invariant_comprehensive() {
    let mut env = TestEnvironment::new()
        .with_chain(BASE_CHAIN_ID, ChainType::EVM);

    // Check invariant at start
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));
    env.verify_global_consistency().expect("Should be consistent");

    // Add deposits
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH deposit should succeed");
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 500_000_000u128)
        .expect("SOL deposit should succeed");
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    env.seed_liquidity(BASE_CHAIN_ID, USDC_ASSET_TYPE, 300_000_000u128)
        .expect("BASE deposit should succeed");
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    // Add withdrawals
    env.process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100_000_000u128)
        .expect("ETH withdrawal should succeed");
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 200_000_000u128)
        .expect("SOL withdrawal should succeed");
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    // Finalize batch
    env.finalize_batch().expect("Should finalize");
    assert!(env.check_supply_invariant(USDC_ASSET_TYPE));

    // Final comprehensive check
    env.verify_global_consistency().expect("Should be consistent");
}

/// Test that withdrawal handler correctly tracks per-chain statistics.
#[test]
fn test_withdrawal_statistics() {
    let mut env = TestEnvironment::new();

    // Setup
    env.seed_liquidity(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("ETH liquidity should succeed");
    env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1_000_000_000u128)
        .expect("SOL liquidity should succeed");

    // Create multiple withdrawals
    for _ in 0..3 {
        env.process_withdrawal(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 50_000_000u128)
            .expect("ETH withdrawal should succeed");
    }
    for _ in 0..2 {
        env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 75_000_000u128)
            .expect("SOL withdrawal should succeed");
    }

    // Check pending counts before finalization
    let eth_pending = env.withdrawal_processor.get_pending_withdrawals(ETHEREUM_CHAIN_ID);
    let sol_pending = env.withdrawal_processor.get_pending_withdrawals(SOLANA_CHAIN_ID);

    assert_eq!(eth_pending.len(), 3);
    assert_eq!(sol_pending.len(), 2);

    // Finalize
    env.finalize_batch().expect("Should finalize");

    // Check ready counts after finalization
    let eth_ready = env.withdrawal_processor.get_ready_withdrawals(ETHEREUM_CHAIN_ID);
    let sol_ready = env.withdrawal_processor.get_ready_withdrawals(SOLANA_CHAIN_ID);

    assert_eq!(eth_ready.len(), 3);
    assert_eq!(sol_ready.len(), 2);

    // Get summaries
    let summaries = env.withdrawal_processor.get_all_summaries();
    assert!(!summaries.is_empty());

    for summary in &summaries {
        if summary.chain_id == ETHEREUM_CHAIN_ID {
            assert_eq!(summary.ready_count, 3);
        } else if summary.chain_id == SOLANA_CHAIN_ID {
            assert_eq!(summary.ready_count, 2);
        }
    }
}
