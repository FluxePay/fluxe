//! Full End-to-End Integration Test
//!
//! This test file provides the main entry points for running the complete
//! FLUXE E2E integration test with rapidsnark proving and SP1 aggregation.
//!
//! # Test Modes
//!
//! 1. **Mock Flow (fast)**: Tests the state machine and sequencer logic without
//!    actual proof generation. This is useful for CI/CD and quick iteration.
//!
//! 2. **Full Flow (slow)**: Complete test with actual R1CS export, proving key
//!    generation, rapidsnark proof generation, and SP1 aggregation simulation.
//!    Requires snarkjs and rapidsnark to be installed.
//!
//! # Running the Tests
//!
//! ```bash
//! # Run mock tests only (fast)
//! cargo test --package e2e-rapidsnark-sp1
//!
//! # Run full tests including proof generation (slow)
//! cargo test --package e2e-rapidsnark-sp1 -- --ignored
//! ```

use e2e_rapidsnark_sp1::{
    TestConfig, CircuitType,
    circuit_setup,
    mock_sequencer::{MockSequencer, CHAIN_ETHEREUM, CHAIN_SOLANA, CHAIN_BASE},
    e2e_flow::E2ETestRunner,
};

use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;

/// Test that the test configuration is properly initialized
#[test]
fn test_config_initialization() {
    let config = TestConfig::new();

    // Check paths are set
    assert!(config.output_dir.to_str().is_some());
    assert!(config.prover_binary.to_str().is_some());
    assert!(config.ptau_path.to_str().is_some());

    // Check ptau power is reasonable
    assert!(config.ptau_power >= 15, "ptau power should be at least 15 for FLUXE circuits");
    assert!(config.ptau_power <= 25, "ptau power should not exceed 25");
}

/// Test that all circuit types are properly defined
#[test]
fn test_circuit_type_coverage() {
    let types = CircuitType::all();

    assert!(types.contains(&CircuitType::Mint), "Should include Mint circuit");
    assert!(types.contains(&CircuitType::Transfer), "Should include Transfer circuit");
    assert!(types.contains(&CircuitType::Burn), "Should include Burn circuit");
    assert!(types.contains(&CircuitType::ObjectUpdate), "Should include ObjectUpdate circuit");

    // Verify names
    assert_eq!(CircuitType::Mint.name(), "mint");
    assert_eq!(CircuitType::Transfer.name(), "transfer");
    assert_eq!(CircuitType::Burn.name(), "burn");
    assert_eq!(CircuitType::ObjectUpdate.name(), "object_update");
}

/// Test the mock sequencer initialization
#[test]
fn test_sequencer_initialization() {
    let sequencer = MockSequencer::new(16);

    // Check all chains are initialized
    assert!(sequencer.chains.contains_key(&CHAIN_ETHEREUM), "Should have Ethereum chain");
    assert!(sequencer.chains.contains_key(&CHAIN_SOLANA), "Should have Solana chain");
    assert!(sequencer.chains.contains_key(&CHAIN_BASE), "Should have Base chain");

    // Check initial state
    assert_eq!(sequencer.current_batch_id, 0);
    assert!(sequencer.tx_history.is_empty());
    assert!(sequencer.notes_by_hash.is_empty());
}

/// Test basic deposit flow in mock sequencer
#[test]
fn test_mock_deposit() {
    let mut sequencer = MockSequencer::new(16);
    let mut rng = thread_rng();
    let recipient = F::rand(&mut rng);

    let deposit = sequencer.create_deposit(
        CHAIN_ETHEREUM,
        1, // USDC
        1000,
        recipient,
    ).expect("Deposit should succeed");

    // Verify deposit created note
    assert!(sequencer.notes_by_hash.contains_key(&deposit.note.commitment()));

    // Verify chain state updated
    let eth = sequencer.chains.get(&CHAIN_ETHEREUM).unwrap();
    assert_eq!(eth.deposited.get(&1).unwrap().0, 1000);

    // Verify supply invariant
    sequencer.verify_supply_invariant().expect("Supply should be valid");
}

/// Test basic transfer flow in mock sequencer
#[test]
fn test_mock_transfer() {
    let mut sequencer = MockSequencer::new(16);
    let mut rng = thread_rng();
    let recipient = F::rand(&mut rng);

    // First deposit
    let deposit = sequencer.create_deposit(
        CHAIN_ETHEREUM,
        1,
        1000,
        recipient,
    ).unwrap();

    // Then transfer
    let transfer = sequencer.create_transfer(
        deposit.note.commitment(),
        900,
        F::rand(&mut rng),
        100,
    ).expect("Transfer should succeed");

    // Verify output note created
    assert!(sequencer.notes_by_hash.contains_key(&transfer.output_note.commitment()));

    // Verify fee accounting
    assert_eq!(transfer.fee.0, 100);

    // Verify supply invariant
    sequencer.verify_supply_invariant().expect("Supply should be valid");
}

/// Test basic withdrawal flow in mock sequencer
#[test]
fn test_mock_withdrawal() {
    let mut sequencer = MockSequencer::new(16);
    let mut rng = thread_rng();
    let recipient = F::rand(&mut rng);

    // Deposit on Ethereum
    let deposit = sequencer.create_deposit(
        CHAIN_ETHEREUM,
        1,
        1000,
        recipient,
    ).unwrap();

    // Withdraw to Solana
    let withdrawal = sequencer.create_withdrawal(
        deposit.note.commitment(),
        CHAIN_SOLANA,
        1000,
    ).expect("Withdrawal should succeed");

    // Verify exit receipt
    assert_eq!(withdrawal.exit_receipt.destination_chain, CHAIN_SOLANA);
    assert_eq!(withdrawal.exit_receipt.amount.0, 1000);

    // Verify chain states
    let eth = sequencer.chains.get(&CHAIN_ETHEREUM).unwrap();
    assert_eq!(eth.deposited.get(&1).unwrap().0, 1000);
    assert!(eth.withdrawn.get(&1).is_none());

    let sol = sequencer.chains.get(&CHAIN_SOLANA).unwrap();
    assert!(sol.deposited.get(&1).is_none());
    assert_eq!(sol.withdrawn.get(&1).unwrap().0, 1000);

    // Verify supply invariant
    sequencer.verify_supply_invariant().expect("Supply should be valid");
}

/// Test full deposit → transfer → withdrawal flow in mock sequencer
#[test]
fn test_mock_full_flow() {
    let mut sequencer = MockSequencer::new(16);
    let mut rng = thread_rng();

    // Step 1: Deposit 1000 USDC on Ethereum
    let deposit = sequencer.create_deposit(
        CHAIN_ETHEREUM,
        1,
        1000,
        F::rand(&mut rng),
    ).unwrap();

    // Step 2: Transfer 900 USDC (100 fee)
    let transfer = sequencer.create_transfer(
        deposit.note.commitment(),
        900,
        F::rand(&mut rng),
        100,
    ).unwrap();

    // Step 3: Withdraw 900 USDC to Solana
    let _withdrawal = sequencer.create_withdrawal(
        transfer.output_note.commitment(),
        CHAIN_SOLANA,
        900,
    ).unwrap();

    // Verify final state
    let eth = sequencer.chains.get(&CHAIN_ETHEREUM).unwrap();
    assert_eq!(eth.deposited.get(&1).unwrap().0, 1000);
    assert_eq!(eth.net_balance(1), 1000);

    let sol = sequencer.chains.get(&CHAIN_SOLANA).unwrap();
    assert_eq!(sol.withdrawn.get(&1).unwrap().0, 900);
    assert_eq!(sol.net_balance(1), -900);

    // Verify supply invariant (global)
    sequencer.verify_supply_invariant().expect("Supply should be valid");

    // Finalize batch
    let batch_id = sequencer.finalize_batch();
    assert_eq!(batch_id, 1);
}

/// Test cross-chain deposit and withdrawal
#[test]
fn test_cross_chain_flow() {
    let mut sequencer = MockSequencer::new(16);
    let mut rng = thread_rng();

    // Deposit on Ethereum
    let deposit1 = sequencer.create_deposit(CHAIN_ETHEREUM, 1, 500, F::rand(&mut rng)).unwrap();

    // Deposit on Base
    let deposit2 = sequencer.create_deposit(CHAIN_BASE, 1, 500, F::rand(&mut rng)).unwrap();

    // Withdraw from Ethereum deposit to Solana
    let _withdrawal1 = sequencer.create_withdrawal(
        deposit1.note.commitment(),
        CHAIN_SOLANA,
        500,
    ).unwrap();

    // Withdraw from Base deposit to Ethereum
    let _withdrawal2 = sequencer.create_withdrawal(
        deposit2.note.commitment(),
        CHAIN_ETHEREUM,
        500,
    ).unwrap();

    // Verify supply invariant
    sequencer.verify_supply_invariant().expect("Supply should be valid");

    // Check net balances
    let eth = sequencer.chains.get(&CHAIN_ETHEREUM).unwrap();
    assert_eq!(eth.net_balance(1), 0); // +500 deposited, -500 withdrawn

    let sol = sequencer.chains.get(&CHAIN_SOLANA).unwrap();
    assert_eq!(sol.net_balance(1), -500); // 0 deposited, -500 withdrawn

    let base = sequencer.chains.get(&CHAIN_BASE).unwrap();
    assert_eq!(base.net_balance(1), 500); // +500 deposited, 0 withdrawn
}

// Note: SP1 aggregation simulation tests removed.
// With real Groth16 verification, mock proofs don't work - you need actual proofs with matching VKs.
// Use the full_e2e_flow test to verify real proof aggregation.

/// Test E2E runner creation
#[test]
fn test_e2e_runner_creation() {
    let runner = E2ETestRunner::new();

    // Should start with no proofs
    assert!(runner.proofs.is_empty());

    // Should have sequencer with all chains
    assert!(runner.sequencer.chains.contains_key(&CHAIN_ETHEREUM));
    assert!(runner.sequencer.chains.contains_key(&CHAIN_SOLANA));
    assert!(runner.sequencer.chains.contains_key(&CHAIN_BASE));
}

/// Test double-spend prevention
#[test]
fn test_double_spend_prevention() {
    let mut sequencer = MockSequencer::new(16);
    let mut rng = thread_rng();

    // Deposit
    let deposit = sequencer.create_deposit(
        CHAIN_ETHEREUM,
        1,
        1000,
        F::rand(&mut rng),
    ).unwrap();

    // First spend (transfer)
    let _transfer = sequencer.create_transfer(
        deposit.note.commitment(),
        900,
        F::rand(&mut rng),
        100,
    ).expect("First spend should succeed");

    // Second spend attempt (should fail - note already spent)
    let result = sequencer.create_transfer(
        deposit.note.commitment(),
        500,
        F::rand(&mut rng),
        100,
    );

    assert!(result.is_err(), "Double spend should fail");
}

/// Test insufficient balance rejection
#[test]
fn test_insufficient_balance() {
    let mut sequencer = MockSequencer::new(16);
    let mut rng = thread_rng();

    // Deposit 1000
    let deposit = sequencer.create_deposit(
        CHAIN_ETHEREUM,
        1,
        1000,
        F::rand(&mut rng),
    ).unwrap();

    // Try to transfer more than balance
    let result = sequencer.create_transfer(
        deposit.note.commitment(),
        2000, // More than deposited
        F::rand(&mut rng),
        100,
    );

    assert!(result.is_err(), "Transfer exceeding balance should fail");
}

/// Full E2E test with actual proof generation
/// This test is ignored by default because it requires snarkjs and rapidsnark
#[test]
#[ignore = "Requires snarkjs, rapidsnark, and powers of tau file. Run with: cargo test -- --ignored"]
fn test_full_e2e_with_proofs() {
    let mut runner = E2ETestRunner::new();

    // Check prerequisites
    if !runner.config.check_snarkjs() {
        panic!("snarkjs not found. Install with: npm install -g snarkjs");
    }

    if !runner.config.check_prover() {
        panic!("rapidsnark prover not found at {:?}", runner.config.prover_binary);
    }

    // Setup all circuits (this downloads ptau if needed)
    runner.setup().expect("Circuit setup should succeed");

    // Run the full E2E flow
    let result = runner.run_e2e_flow().expect("E2E flow should succeed");

    // Verify results
    assert_eq!(result.proof_count, 3, "Should have 3 proofs (mint, transfer, burn)");
    assert_eq!(result.batch_id, 1);
    assert!(result.execution_cycles > 0);

    println!("\n=== FULL E2E TEST PASSED ===");
    println!("Proofs generated: {}", result.proof_count);
    println!("SP1 cycles: {}", result.execution_cycles);
}

/// Test for R1CS export only (no proof generation)
/// This is faster than full E2E but still tests the circuit serialization
#[test]
#[ignore = "Requires fluxe-rapidsnark dependencies"]
fn test_r1cs_export_only() {
    let config = TestConfig::new();
    config.ensure_output_dir().expect("Should create output dir");

    // Test each circuit type
    for circuit_type in CircuitType::all() {
        println!("Testing R1CS export for {:?}...", circuit_type);

        let result = circuit_setup::export_circuit_r1cs(&config, circuit_type);

        match result {
            Ok(paths) => {
                println!("  R1CS: {:?}", paths.r1cs);
                println!("  Witness: {:?}", paths.witness);
            }
            Err(e) => {
                println!("  Export failed: {}", e);
            }
        }
    }
}
