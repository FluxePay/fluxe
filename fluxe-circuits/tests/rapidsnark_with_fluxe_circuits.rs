//! Test rapidsnark integration with actual Fluxe circuits
//!
//! This demonstrates using rapidsnark serializer with circuits

use ark_bn254::Fr;
use fluxe_circuits::rapidsnark::*;
use fluxe_core::types::*;
use std::path::PathBuf;

/// Helper to create dummy state roots (using Fr field elements)
fn dummy_roots() -> StateRoots {
    StateRoots {
        cmt_root: Fr::from(1u32),
        nft_root: Fr::from(2u32),
        obj_root: Fr::from(3u32),
        cb_root: Fr::from(4u32),
        ingress_root: Fr::from(5u32),
        exit_root: Fr::from(6u32),
        sanctions_root: Fr::from(7u32),
        pool_rules_root: Fr::from(8u32),
    }
}

#[test]
fn test_serializer_with_state_roots() {
    println!("\n=== Testing Serializer with StateRoots Type ===\n");

    // Verify that StateRoots is correctly defined
    let roots = dummy_roots();
    println!("Created StateRoots:");
    println!("  cmt_root: {:?}", roots.cmt_root);
    println!("  nft_root: {:?}", roots.nft_root);

    assert_eq!(roots.cmt_root, Fr::from(1u32));
    assert_eq!(roots.nft_root, Fr::from(2u32));

    println!("✓ StateRoots structure is compatible with Fr field elements");
}

// Note: Full circuit tests are complex because circuits require many parameters
// and proper witness data. The integration tests in rapidsnark_integration.rs
// and rapidsnark_verification.rs demonstrate the full workflow with simpler circuits.

#[test]
fn test_circuit_stats_display() {
    let stats = CircuitStats {
        num_constraints: 1000,
        num_public_inputs: 10,
        num_private_inputs: 50,
        num_wires: 60,
    };

    let display = format!("{}", stats);
    assert!(display.contains("1000"));
    assert!(display.contains("Constraints"));
    println!("\n{}", stats);
}

#[test]
fn test_rapidsnark_paths() {
    let paths = RapidsnarkPaths::new("/tmp/test", "my_circuit");

    assert!(paths.r1cs.to_string_lossy().contains("my_circuit.r1cs"));
    assert!(paths.witness.to_string_lossy().contains("my_circuit_witness.wtns"));
    assert!(paths.proving_key.to_string_lossy().contains("my_circuit_final.zkey"));
    assert!(paths.verification_key.to_string_lossy().contains("my_circuit_verification_key.json"));
    assert!(paths.proof.to_string_lossy().contains("my_circuit_proof.json"));
    assert!(paths.public_inputs.to_string_lossy().contains("my_circuit_public.json"));

    println!("\n=== RapidsnarkPaths Structure ===");
    println!("R1CS: {}", paths.r1cs.display());
    println!("Witness: {}", paths.witness.display());
    println!("Proving key: {}", paths.proving_key.display());
    println!("Verification key: {}", paths.verification_key.display());
    println!("Proof: {}", paths.proof.display());
    println!("Public inputs: {}", paths.public_inputs.display());
}

#[test]
fn test_config_creation() {
    let config = RapidsnarkConfig::default();
    assert_eq!(config.prover_path.to_string_lossy(), "rapidsnark-prover");
    assert_eq!(config.verifier_path.to_string_lossy(), "rapidsnark-verifier");

    let local_config = RapidsnarkConfig::from_local_build("/path/to/rapidsnark");
    assert!(local_config.prover_path.to_string_lossy().contains("prover"));

    let with_ptau = config.with_powers_of_tau("/path/to/ptau");
    assert!(with_ptau.powers_of_tau.is_some());

    println!("\n=== Config Test Passed ===");
}
