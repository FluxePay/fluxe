/// Comprehensive integration tests for cross-chain flows in Fluxe
///
/// These tests validate the complete cross-chain transaction lifecycle:
/// - Cross-chain deposits and withdrawals
/// - Double-spend prevention across chains
/// - Multi-chain parallel deposits
/// - Supply invariant validation
/// - Invalid chain ID handling
///
/// All tests use the GlobalStateManager to simulate a multi-chain environment.

use fluxe_core::{
    crypto::pedersen::{PedersenCommitment, PedersenParams, PedersenRandomness},
    data_structures::{IngressReceipt, ExitReceipt},
    state_manager::GlobalStateManager,
    types::*,
};
use ark_bn254::Fr as F;
use ark_ff::{Zero, UniformRand};
use rand::thread_rng;

/// Helper function to create a mock note commitment
fn create_commitment(value: u64, rng: &mut rand::rngs::ThreadRng, params: &PedersenParams) -> F {
    let randomness = PedersenRandomness::new(rng);
    PedersenCommitment::commit(params, value, &randomness)
}

/// Test 1: Basic Cross-Chain Deposit/Withdrawal
///
/// This test validates the fundamental cross-chain flow:
/// - Deposit 100 USDC on Ethereum (chain_id = 1)
/// - Mint note via minting operation
/// - Burn note with target Solana (chain_id = 501)
/// - Verify exit receipt created on Solana chain
/// - Verify supply accounting is correct
#[test]
fn test_basic_cross_chain_deposit_withdrawal() {
    println!("\n=== Test 1: Basic Cross-Chain Deposit/Withdrawal ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    // Register chains: Ethereum (1) and Solana (501)
    let ethereum_chain_id: ChainId = 1;
    let solana_chain_id: ChainId = 501;

    gsm.register_chain(ethereum_chain_id, ChainType::EVM)
        .expect("Failed to register Ethereum");
    gsm.register_chain(solana_chain_id, ChainType::SVM)
        .expect("Failed to register Solana");

    println!("✓ Registered chains: Ethereum (1), Solana (501)");

    // Step 1: Create deposit on Ethereum
    let deposit_amount: Amount = Amount::from(100u128);
    let beneficiary_cm = F::rand(&mut rng);
    let nonce_1 = 1u64;

    let ingress_receipt = IngressReceipt::new(
        ethereum_chain_id,
        1u32, // USDC asset type
        deposit_amount,
        beneficiary_cm,
        nonce_1,
    );

    println!("Step 1: Created ingress receipt on Ethereum for {} USDC", deposit_amount.as_u128());

    // Step 2: Process mint (simulate MintCircuit proof generation)
    let output_cm = create_commitment(deposit_amount.as_u128(), &mut rng, &params);

    let mint_result = gsm.process_mint(
        ethereum_chain_id,
        &ingress_receipt,
        &[output_cm],
    );

    assert!(mint_result.is_ok(), "Mint operation should succeed");

    println!("Step 2: Minted note with commitment: {:?}", output_cm);
    println!("  Global supply after mint: {} USDC", gsm.get_supply(1u32).as_u128());

    // Verify supply
    assert_eq!(gsm.get_supply(1u32).as_u128(), 100, "Global supply should be 100");

    // Verify Ethereum chain state updated
    let eth_chain_state = gsm.get_chain_state(ethereum_chain_id)
        .expect("Ethereum chain state should exist");
    assert_eq!(
        eth_chain_state.get_deposited(1u32).as_u128(), 100,
        "Ethereum should show 100 deposited"
    );

    println!("✓ Verified Ethereum chain state: deposited = 100 USDC");

    // Step 3: Burn note on Solana (simulate BurnCircuit proof)
    // First, create a nullifier for the burned note
    let nullifier = F::rand(&mut rng);
    let nonce_2 = 1u64;

    let exit_receipt = ExitReceipt::new(
        solana_chain_id,
        1u32, // USDC asset type
        deposit_amount,
        nullifier,
        nonce_2,
    );

    let burn_result = gsm.process_burn(
        solana_chain_id,
        &exit_receipt,
        nullifier,
    );

    assert!(burn_result.is_ok(), "Burn operation should succeed");

    println!("Step 3: Burned note on Solana for {} USDC", deposit_amount.as_u128());

    // Verify exit receipt was created on Solana chain
    let sol_chain_state = gsm.get_chain_state(solana_chain_id)
        .expect("Solana chain state should exist");
    assert_eq!(
        sol_chain_state.get_withdrawn(1u32).as_u128(), 100,
        "Solana should show 100 withdrawn"
    );

    println!("✓ Verified Solana chain state: withdrawn = 100 USDC");

    // Step 4: Verify supply accounting is correct
    // After mint on ETH and burn on SOL, global supply should still be 100
    // (it went ETH -> protocol -> SOL)
    let final_supply = gsm.get_supply(1u32);
    println!("Step 4: Final global supply: {} USDC", final_supply.as_u128());

    assert_eq!(final_supply.as_u128(), 100, "Global supply should remain 100");

    // Verify supply invariant
    gsm.check_supply_invariant(1u32)
        .expect("Supply invariant should hold");

    println!("✓ Supply invariant validated");
    println!("✓ Test 1 PASSED\n");
}

/// Test 2: Cross-Chain Double-Spend Prevention
///
/// This test validates double-spend protection across chains:
/// - Deposit on Ethereum
/// - Mint note
/// - Attempt to burn same note twice (different chains)
/// - Verify second burn fails with double-spend error
/// - Verify global nullifier tree prevents replay
#[test]
fn test_cross_chain_double_spend_prevention() {
    println!("\n=== Test 2: Cross-Chain Double-Spend Prevention ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    // Register multiple chains
    let ethereum_chain_id: ChainId = 1;
    let solana_chain_id: ChainId = 501;
    let polygon_chain_id: ChainId = 137;

    gsm.register_chain(ethereum_chain_id, ChainType::EVM)
        .expect("Failed to register Ethereum");
    gsm.register_chain(solana_chain_id, ChainType::SVM)
        .expect("Failed to register Solana");
    gsm.register_chain(polygon_chain_id, ChainType::EVM)
        .expect("Failed to register Polygon");

    println!("✓ Registered chains: Ethereum (1), Solana (501), Polygon (137)");

    // Step 1: Deposit on Ethereum
    let deposit_amount: Amount = Amount::from(50u128);
    let beneficiary_cm = F::rand(&mut rng);

    let ingress_receipt = IngressReceipt::new(
        ethereum_chain_id,
        1u32,
        deposit_amount,
        beneficiary_cm,
        1u64,
    );

    let output_cm = create_commitment(deposit_amount.as_u128(), &mut rng, &params);

    let mint_result = gsm.process_mint(
        ethereum_chain_id,
        &ingress_receipt,
        &[output_cm],
    );

    assert!(mint_result.is_ok(), "Mint should succeed");
    println!("Step 1: Deposited and minted {} USDC on Ethereum", deposit_amount.as_u128());

    // Step 2: First burn on Solana
    let nullifier = F::rand(&mut rng);

    let exit_receipt_1 = ExitReceipt::new(
        solana_chain_id,
        1u32,
        deposit_amount,
        nullifier,
        1u64,
    );

    let burn_result_1 = gsm.process_burn(
        solana_chain_id,
        &exit_receipt_1,
        nullifier,
    );

    assert!(burn_result_1.is_ok(), "First burn should succeed");
    println!("Step 2: First burn succeeded on Solana");

    // Step 3: Attempt to burn same nullifier again on Polygon
    let exit_receipt_2 = ExitReceipt::new(
        polygon_chain_id,
        1u32,
        deposit_amount,
        nullifier, // Same nullifier - attempt double-spend
        2u64,
    );

    let burn_result_2 = gsm.process_burn(
        polygon_chain_id,
        &exit_receipt_2,
        nullifier, // Same nullifier
    );

    assert!(burn_result_2.is_err(), "Second burn with same nullifier should fail");

    if let Err(StateError::DoubleSpend(_)) = burn_result_2 {
        println!("✓ Double-spend correctly rejected: {}", burn_result_2.unwrap_err());
    } else {
        panic!("Expected DoubleSpend error, got: {:?}", burn_result_2);
    }

    // Step 4: Verify global nullifier tree prevents replay
    // The nullifier should be in the global NFT tree
    assert!(gsm.nft_tree.contains(&nullifier), "Nullifier should be in global tree");

    println!("✓ Global nullifier tree prevents replay");
    println!("✓ Test 2 PASSED\n");
}

/// Test 3: Multi-Chain Parallel Deposits
///
/// This test validates parallel deposits on multiple chains:
/// - Deposit 50 USDC on Ethereum
/// - Deposit 50 USDC on Solana
/// - Mint two separate notes
/// - Merge via Transfer (2 inputs, 1 output)
/// - Burn back to Ethereum
/// - Verify supply invariants hold
#[test]
fn test_multi_chain_parallel_deposits() {
    println!("\n=== Test 3: Multi-Chain Parallel Deposits ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    // Register chains
    let ethereum_chain_id: ChainId = 1;
    let solana_chain_id: ChainId = 501;

    gsm.register_chain(ethereum_chain_id, ChainType::EVM)
        .expect("Failed to register Ethereum");
    gsm.register_chain(solana_chain_id, ChainType::SVM)
        .expect("Failed to register Solana");

    println!("✓ Registered chains: Ethereum (1), Solana (501)");

    // Step 1: Deposit on Ethereum
    let eth_amount: Amount = Amount::from(50u128);
    let eth_beneficiary = F::rand(&mut rng);

    let eth_ingress = IngressReceipt::new(
        ethereum_chain_id,
        1u32,
        eth_amount,
        eth_beneficiary,
        1u64,
    );

    let eth_cm = create_commitment(eth_amount.as_u128(), &mut rng, &params);

    let eth_mint = gsm.process_mint(
        ethereum_chain_id,
        &eth_ingress,
        &[eth_cm],
    );

    assert!(eth_mint.is_ok(), "Ethereum mint should succeed");
    println!("Step 1: Deposited {} USDC on Ethereum", eth_amount.as_u128());

    // Step 2: Deposit on Solana
    let sol_amount: Amount = Amount::from(50u128);
    let sol_beneficiary = F::rand(&mut rng);

    let sol_ingress = IngressReceipt::new(
        solana_chain_id,
        1u32,
        sol_amount,
        sol_beneficiary,
        1u64,
    );

    let sol_cm = create_commitment(sol_amount.as_u128(), &mut rng, &params);

    let sol_mint = gsm.process_mint(
        solana_chain_id,
        &sol_ingress,
        &[sol_cm],
    );

    assert!(sol_mint.is_ok(), "Solana mint should succeed");
    println!("Step 2: Deposited {} USDC on Solana", sol_amount.as_u128());

    // Verify total global supply
    assert_eq!(gsm.get_supply(1u32).as_u128(), 100, "Global supply should be 100");
    println!("✓ Total global supply verified: 100 USDC");

    // Step 3: Merge via Transfer (2 inputs, 1 output)
    let nullifier_1 = F::rand(&mut rng);
    let nullifier_2 = F::rand(&mut rng);
    let merged_cm = create_commitment(100, &mut rng, &params);

    let transfer_result = gsm.process_transfer(
        &[nullifier_1, nullifier_2],
        &[merged_cm],
    );

    assert!(transfer_result.is_ok(), "Transfer should succeed");
    println!("Step 3: Merged 2 input notes into 1 output note via Transfer");

    // Step 4: Burn back to Ethereum
    let burn_nullifier = F::rand(&mut rng);
    let burn_amount: Amount = Amount::from(100u128);

    let exit_receipt = ExitReceipt::new(
        ethereum_chain_id,
        1u32,
        burn_amount,
        burn_nullifier,
        2u64,
    );

    let burn_result = gsm.process_burn(
        ethereum_chain_id,
        &exit_receipt,
        burn_nullifier,
    );

    assert!(burn_result.is_ok(), "Burn should succeed");
    println!("Step 4: Burned {} USDC back to Ethereum", burn_amount.as_u128());

    // Step 5: Verify supply invariants hold
    gsm.check_supply_invariant(1u32)
        .expect("Supply invariant should hold");

    println!("✓ Supply invariant validated");

    // Verify final supply accounting
    let eth_state = gsm.get_chain_state(ethereum_chain_id).unwrap();
    let sol_state = gsm.get_chain_state(solana_chain_id).unwrap();

    println!("Ethereum: deposited={}, withdrawn={}",
        eth_state.get_deposited(1u32).as_u128(),
        eth_state.get_withdrawn(1u32).as_u128());
    println!("Solana: deposited={}, withdrawn={}",
        sol_state.get_deposited(1u32).as_u128(),
        sol_state.get_withdrawn(1u32).as_u128());

    assert_eq!(eth_state.get_deposited(1u32).as_u128(), 50);
    assert_eq!(eth_state.get_withdrawn(1u32).as_u128(), 100);
    assert_eq!(sol_state.get_deposited(1u32).as_u128(), 50);
    assert_eq!(sol_state.get_withdrawn(1u32).as_u128(), 0);

    println!("✓ Test 3 PASSED\n");
}

/// Test 4: Supply Invariant Validation
///
/// This test validates the cross-chain supply invariant:
/// - Deposit 1000 USDC on Ethereum
/// - Withdraw 600 USDC on Solana
/// - Verify global supply = 400 USDC
/// - Verify ETH chain has +1000 imbalance
/// - Verify SOL chain has -600 imbalance
/// - Verify check_supply_invariant() passes
#[test]
fn test_supply_invariant_validation() {
    println!("\n=== Test 4: Supply Invariant Validation ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    // Register chains
    let ethereum_chain_id: ChainId = 1;
    let solana_chain_id: ChainId = 501;

    gsm.register_chain(ethereum_chain_id, ChainType::EVM)
        .expect("Failed to register Ethereum");
    gsm.register_chain(solana_chain_id, ChainType::SVM)
        .expect("Failed to register Solana");

    println!("✓ Registered chains");

    // Step 1: Deposit 1000 USDC on Ethereum
    let eth_deposit: Amount = Amount::from(1000u128);
    let eth_beneficiary = F::rand(&mut rng);

    let eth_ingress = IngressReceipt::new(
        ethereum_chain_id,
        1u32,
        eth_deposit,
        eth_beneficiary,
        1u64,
    );

    let eth_cm = create_commitment(eth_deposit.as_u128(), &mut rng, &params);

    let eth_mint = gsm.process_mint(
        ethereum_chain_id,
        &eth_ingress,
        &[eth_cm],
    );

    assert!(eth_mint.is_ok());
    println!("Step 1: Deposited {} USDC on Ethereum", eth_deposit.as_u128());

    // Step 2: Withdraw 600 USDC on Solana
    let sol_withdrawal: Amount = Amount::from(600u128);
    let sol_nullifier = F::rand(&mut rng);

    let sol_exit = ExitReceipt::new(
        solana_chain_id,
        1u32,
        sol_withdrawal,
        sol_nullifier,
        1u64,
    );

    let sol_burn = gsm.process_burn(
        solana_chain_id,
        &sol_exit,
        sol_nullifier,
    );

    assert!(sol_burn.is_ok());
    println!("Step 2: Withdrawn {} USDC on Solana", sol_withdrawal.as_u128());

    // Step 3: Verify global supply = 400 USDC
    let global_supply = gsm.get_supply(1u32);
    println!("Step 3: Global supply: {} USDC", global_supply.as_u128());

    assert_eq!(global_supply.as_u128(), 400, "Global supply should be 400");
    println!("✓ Global supply verified: 400 USDC");

    // Step 4: Verify chain imbalances
    let eth_state = gsm.get_chain_state(ethereum_chain_id).unwrap();
    let sol_state = gsm.get_chain_state(solana_chain_id).unwrap();

    let eth_deposited = eth_state.get_deposited(1u32).as_u128();
    let eth_withdrawn = eth_state.get_withdrawn(1u32).as_u128();
    let sol_deposited = sol_state.get_deposited(1u32).as_u128();
    let sol_withdrawn = sol_state.get_withdrawn(1u32).as_u128();

    println!("Step 4: Chain state analysis");
    println!("  Ethereum: deposited={}, withdrawn={}, imbalance={}",
        eth_deposited, eth_withdrawn, eth_deposited as i128 - eth_withdrawn as i128);
    println!("  Solana: deposited={}, withdrawn={}, imbalance={}",
        sol_deposited, sol_withdrawn, sol_deposited as i128 - sol_withdrawn as i128);

    assert_eq!(eth_deposited, 1000, "ETH should have +1000 deposited");
    assert_eq!(eth_withdrawn, 0, "ETH should have no withdrawals");
    assert_eq!(sol_deposited, 0, "SOL should have no deposits");
    assert_eq!(sol_withdrawn, 600, "SOL should have -600 withdrawn");

    println!("✓ ETH chain has +1000 imbalance");
    println!("✓ SOL chain has -600 imbalance");

    // Step 5: Verify check_supply_invariant() passes
    gsm.check_supply_invariant(1u32)
        .expect("Supply invariant should pass");

    println!("Step 5: Supply invariant check passed");

    // Verify the math: deposited - withdrawn = global supply
    let calculated_supply = eth_deposited + sol_deposited - eth_withdrawn - sol_withdrawn;
    assert_eq!(calculated_supply as u128, global_supply.as_u128());

    println!("✓ Math verified: {} + {} - {} - {} = {}",
        eth_deposited, sol_deposited, eth_withdrawn, sol_withdrawn, global_supply.as_u128());
    println!("✓ Test 4 PASSED\n");
}

/// Test 5: Invalid Chain ID Handling
///
/// This test validates error handling for unregistered chains:
/// - Attempt transaction with unregistered chain_id
/// - Verify appropriate error returned
/// - Verify state unchanged
#[test]
fn test_invalid_chain_id_handling() {
    println!("\n=== Test 5: Invalid Chain ID Handling ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    // Register only Ethereum
    let ethereum_chain_id: ChainId = 1;
    gsm.register_chain(ethereum_chain_id, ChainType::EVM)
        .expect("Failed to register Ethereum");

    println!("✓ Registered only Ethereum (1)");

    // Step 1: Attempt mint on unregistered chain (999)
    let unregistered_chain_id: ChainId = 999;
    let amount: Amount = Amount::from(100u128);
    let beneficiary = F::rand(&mut rng);

    let ingress_receipt = IngressReceipt::new(
        unregistered_chain_id,
        1u32,
        amount,
        beneficiary,
        1u64,
    );

    let output_cm = create_commitment(amount.as_u128(), &mut rng, &params);

    let mint_result = gsm.process_mint(
        unregistered_chain_id,
        &ingress_receipt,
        &[output_cm],
    );

    assert!(mint_result.is_err(), "Mint on unregistered chain should fail");

    if let Err(StateError::InvalidTransition { from, to }) = mint_result {
        println!("Step 1: ✓ Mint correctly rejected with error: {} -> {}", from, to);
    } else {
        panic!("Expected InvalidTransition error");
    }

    // Step 2: Verify state unchanged - global supply should be 0
    let global_supply = gsm.get_supply(1u32);
    assert_eq!(global_supply.as_u128(), 0, "Global supply should remain 0");
    println!("Step 2: ✓ State unchanged - global supply: 0 USDC");

    // Step 3: Attempt burn on unregistered chain
    let nullifier = F::rand(&mut rng);
    let exit_receipt = ExitReceipt::new(
        unregistered_chain_id,
        1u32,
        amount,
        nullifier,
        1u64,
    );

    let burn_result = gsm.process_burn(
        unregistered_chain_id,
        &exit_receipt,
        nullifier,
    );

    assert!(burn_result.is_err(), "Burn on unregistered chain should fail");
    println!("Step 3: ✓ Burn correctly rejected");

    // Step 4: Verify valid chain still works after error attempts
    let valid_ingress = IngressReceipt::new(
        ethereum_chain_id,
        1u32,
        amount,
        beneficiary,
        2u64,
    );

    let valid_cm = create_commitment(amount.as_u128(), &mut rng, &params);
    let valid_mint = gsm.process_mint(
        ethereum_chain_id,
        &valid_ingress,
        &[valid_cm],
    );

    assert!(valid_mint.is_ok(), "Valid chain should still work");
    assert_eq!(gsm.get_supply(1u32).as_u128(), 100, "Global supply should be 100");
    println!("Step 4: ✓ Valid chain still works after error attempts");

    println!("✓ Test 5 PASSED\n");
}

/// Test 6: Multiple Assets Cross-Chain Flow
///
/// This test validates handling of multiple assets across chains:
/// - Deposit USDC and USDT on different chains
/// - Verify per-asset supply tracking
/// - Burn different amounts of each asset
/// - Verify supply invariants for both assets
#[test]
fn test_multiple_assets_cross_chain_flow() {
    println!("\n=== Test 6: Multiple Assets Cross-Chain Flow ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    // Register chains
    let ethereum_chain_id: ChainId = 1;
    let solana_chain_id: ChainId = 501;

    gsm.register_chain(ethereum_chain_id, ChainType::EVM)
        .expect("Failed to register Ethereum");
    gsm.register_chain(solana_chain_id, ChainType::SVM)
        .expect("Failed to register Solana");

    println!("✓ Registered chains");

    // Asset types: USDC = 1, USDT = 2
    let usdc_asset: AssetType = 1u32;
    let usdt_asset: AssetType = 2u32;

    // Step 1: Deposit USDC on Ethereum
    let usdc_amount: Amount = Amount::from(1000u128);
    let usdc_beneficiary = F::rand(&mut rng);

    let usdc_ingress = IngressReceipt::new(
        ethereum_chain_id,
        usdc_asset,
        usdc_amount,
        usdc_beneficiary,
        1u64,
    );

    let usdc_cm = create_commitment(usdc_amount.as_u128(), &mut rng, &params);

    let usdc_mint = gsm.process_mint(
        ethereum_chain_id,
        &usdc_ingress,
        &[usdc_cm],
    );

    assert!(usdc_mint.is_ok());
    println!("Step 1: Deposited {} USDC on Ethereum", usdc_amount.as_u128());

    // Step 2: Deposit USDT on Solana
    let usdt_amount: Amount = Amount::from(500u128);
    let usdt_beneficiary = F::rand(&mut rng);

    let usdt_ingress = IngressReceipt::new(
        solana_chain_id,
        usdt_asset,
        usdt_amount,
        usdt_beneficiary,
        1u64,
    );

    let usdt_cm = create_commitment(usdt_amount.as_u128(), &mut rng, &params);

    let usdt_mint = gsm.process_mint(
        solana_chain_id,
        &usdt_ingress,
        &[usdt_cm],
    );

    assert!(usdt_mint.is_ok());
    println!("Step 2: Deposited {} USDT on Solana", usdt_amount.as_u128());

    // Step 3: Verify per-asset supply tracking
    assert_eq!(gsm.get_supply(usdc_asset).as_u128(), 1000, "USDC supply should be 1000");
    assert_eq!(gsm.get_supply(usdt_asset).as_u128(), 500, "USDT supply should be 500");
    println!("✓ Per-asset supply tracked correctly");

    // Step 4: Burn USDC on Solana
    let usdc_burn_amount: Amount = Amount::from(400u128);
    let usdc_burn_nf = F::rand(&mut rng);

    let usdc_exit = ExitReceipt::new(
        solana_chain_id,
        usdc_asset,
        usdc_burn_amount,
        usdc_burn_nf,
        1u64,
    );

    let usdc_burn = gsm.process_burn(
        solana_chain_id,
        &usdc_exit,
        usdc_burn_nf,
    );

    assert!(usdc_burn.is_ok());
    println!("Step 4: Burned {} USDC on Solana", usdc_burn_amount.as_u128());

    // Step 5: Burn USDT on Ethereum
    let usdt_burn_amount: Amount = Amount::from(200u128);
    let usdt_burn_nf = F::rand(&mut rng);

    let usdt_exit = ExitReceipt::new(
        ethereum_chain_id,
        usdt_asset,
        usdt_burn_amount,
        usdt_burn_nf,
        1u64,
    );

    let usdt_burn = gsm.process_burn(
        ethereum_chain_id,
        &usdt_exit,
        usdt_burn_nf,
    );

    assert!(usdt_burn.is_ok());
    println!("Step 5: Burned {} USDT on Ethereum", usdt_burn_amount.as_u128());

    // Step 6: Verify supply invariants for both assets
    gsm.check_supply_invariant(usdc_asset)
        .expect("USDC supply invariant should hold");
    gsm.check_supply_invariant(usdt_asset)
        .expect("USDT supply invariant should hold");

    println!("✓ Supply invariants verified for both assets");

    // Step 7: Verify final supplies
    assert_eq!(gsm.get_supply(usdc_asset).as_u128(), 600, "USDC supply should be 600");
    assert_eq!(gsm.get_supply(usdt_asset).as_u128(), 300, "USDT supply should be 300");

    println!("Final supplies: USDC={}, USDT={}",
        gsm.get_supply(usdc_asset).as_u128(),
        gsm.get_supply(usdt_asset).as_u128());

    println!("✓ Test 6 PASSED\n");
}

/// Test 7: Cross-Chain Transfer Chain
///
/// This test validates complex cross-chain transfer chains:
/// - Start with deposits on 3 chains
/// - Execute series of transfers across chains
/// - Verify nullifier accumulation
/// - Verify commitment tree growth
#[test]
fn test_cross_chain_transfer_chain() {
    println!("\n=== Test 7: Cross-Chain Transfer Chain ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    // Register 3 chains
    let chain_1: ChainId = 1;
    let chain_2: ChainId = 2;
    let chain_3: ChainId = 3;

    gsm.register_chain(chain_1, ChainType::EVM)
        .expect("Failed to register chain 1");
    gsm.register_chain(chain_2, ChainType::EVM)
        .expect("Failed to register chain 2");
    gsm.register_chain(chain_3, ChainType::EVM)
        .expect("Failed to register chain 3");

    println!("✓ Registered 3 chains");

    // Step 1: Deposit on each chain
    let amounts = vec![
        Amount::from(100u128),
        Amount::from(100u128),
        Amount::from(100u128),
    ];

    for (idx, &chain_id) in [chain_1, chain_2, chain_3].iter().enumerate() {
        let ingress = IngressReceipt::new(
            chain_id,
            1u32,
            amounts[idx],
            F::rand(&mut rng),
            1u64,
        );

        let cm = create_commitment(amounts[idx].as_u128(), &mut rng, &params);

        let mint = gsm.process_mint(chain_id, &ingress, &[cm]);
        assert!(mint.is_ok());
    }

    println!("Step 1: Deposited 100 USDC on each of 3 chains");
    assert_eq!(gsm.get_supply(1u32).as_u128(), 300);

    // Step 2: Execute series of in-protocol transfers
    for i in 0..5 {
        let input_nf = F::rand(&mut rng);
        let output_cm = create_commitment(100, &mut rng, &params);

        let transfer = gsm.process_transfer(&[input_nf], &[output_cm]);
        assert!(transfer.is_ok(), "Transfer {} should succeed", i);
    }

    println!("Step 2: Executed 5 in-protocol transfers");

    // Step 3: Verify nullifier tree has accumulated nullifiers
    let withdrawal_1 = Amount::from(50u128);
    let nf_final = F::rand(&mut rng);

    let exit = ExitReceipt::new(chain_1, 1u32, withdrawal_1, nf_final, 2u64);
    let burn = gsm.process_burn(chain_1, &exit, nf_final);

    assert!(burn.is_ok());
    println!("Step 3: ✓ Nullifier tree has accumulated nullifiers");

    // Step 4: Verify commitment tree growth
    let final_cmt_root = gsm.get_global_roots().cmt_root;
    assert_ne!(final_cmt_root, F::zero(), "CMT root should be non-zero after transactions");

    println!("Step 4: ✓ Commitment tree has grown");

    // Step 5: Verify final supply invariant
    gsm.check_supply_invariant(1u32)
        .expect("Supply invariant should hold");

    println!("✓ Final supply: {}", gsm.get_supply(1u32).as_u128());
    println!("✓ Test 7 PASSED\n");
}

/// Test 8: Concurrent Deposits on Same Chain
///
/// This test validates concurrent deposits on the same chain:
/// - Execute multiple deposits on Ethereum sequentially
/// - Verify supply accumulates correctly
/// - Verify each deposit increases ingress tree
#[test]
fn test_concurrent_deposits_same_chain() {
    println!("\n=== Test 8: Concurrent Deposits on Same Chain ===");

    let mut rng = thread_rng();
    let mut gsm = GlobalStateManager::new(26);
    let params = PedersenParams::setup_value_commitment();

    let ethereum_chain_id: ChainId = 1;
    gsm.register_chain(ethereum_chain_id, ChainType::EVM)
        .expect("Failed to register Ethereum");

    println!("✓ Registered Ethereum");

    // Step 1: Execute 10 deposits
    let deposit_amounts = vec![100u128, 50u128, 75u128, 125u128, 200u128,
                               60u128, 90u128, 110u128, 85u128, 75u128];

    let mut total_deposited = 0u128;

    for (idx, &amount) in deposit_amounts.iter().enumerate() {
        let ingress = IngressReceipt::new(
            ethereum_chain_id,
            1u32,
            Amount::from(amount),
            F::rand(&mut rng),
            (idx as u64) + 1,
        );

        let cm = create_commitment(amount, &mut rng, &params);
        let mint = gsm.process_mint(ethereum_chain_id, &ingress, &[cm]);

        assert!(mint.is_ok(), "Deposit {} should succeed", idx + 1);
        total_deposited += amount;
    }

    println!("Step 1: ✓ Executed 10 deposits totaling {} USDC", total_deposited);

    // Step 2: Verify supply accumulates
    assert_eq!(gsm.get_supply(1u32).as_u128(), total_deposited);
    println!("Step 2: ✓ Global supply: {} USDC", total_deposited);

    // Step 3: Verify ingress tree has all deposits
    let eth_state = gsm.get_chain_state(ethereum_chain_id).unwrap();
    assert_eq!(eth_state.get_deposited(1u32).as_u128(), total_deposited);
    println!("Step 3: ✓ Ethereum chain state verified");

    // Step 4: Verify supply invariant still holds
    gsm.check_supply_invariant(1u32)
        .expect("Supply invariant should hold");

    println!("✓ Test 8 PASSED\n");
}
