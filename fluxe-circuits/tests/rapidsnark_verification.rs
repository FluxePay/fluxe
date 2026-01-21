//! End-to-end verification test for rapidsnark integration
//!
//! This test verifies that the complete workflow works:
//! 1. Circuit synthesis
//! 2. Export to Circom format
//! 3. Trusted setup
//! 4. Proof generation with rapidsnark
//! 5. Verification with both rapidsnark and snarkjs

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use fluxe_circuits::rapidsnark::*;
use std::path::PathBuf;

#[derive(Clone)]
struct SquareCircuit {
    x: Fr,
    x_squared: Fr,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_var = FpVar::new_witness(cs.clone(), || Ok(self.x))?;
        let x_squared_var = FpVar::new_input(cs, || Ok(self.x_squared))?;

        let computed = &x_var * &x_var;
        computed.enforce_equal(&x_squared_var)?;

        Ok(())
    }
}

#[test]
#[ignore] // Requires rapidsnark and snarkjs to be installed
fn test_end_to_end_workflow() {
    println!("\n=== End-to-End Rapidsnark Verification Test ===\n");

    // Setup
    let base_dir = PathBuf::from("outputs/test_e2e");
    std::fs::create_dir_all(&base_dir).unwrap();
    let paths = RapidsnarkPaths::new(&base_dir, "square");
    paths.ensure_base_dir().unwrap();

    let rapidsnark_dir = PathBuf::from("../rapidsnark");
    let config = RapidsnarkConfig::from_local_build(&rapidsnark_dir);

    // Test case: x = 7, x^2 = 49
    let x = Fr::from(7u32);
    let x_squared = Fr::from(49u32);

    println!("Step 1: Creating circuit (x={}, x^2={})", 7, 49);
    let circuit = SquareCircuit { x, x_squared };

    // Export to Circom format
    println!("\nStep 2: Exporting to Circom format...");
    let stats = export_to_circom_files(
        circuit.clone(),
        &paths.r1cs,
        &paths.witness,
    ).unwrap();

    println!("  Constraints: {}", stats.num_constraints);
    println!("  Public inputs: {}", stats.num_public_inputs);
    println!("  Private inputs: {}", stats.num_private_inputs);
    println!("  R1CS: {}", paths.r1cs.display());
    println!("  Witness: {}", paths.witness.display());

    assert!(paths.r1cs.exists(), "R1CS file not created");
    assert!(paths.witness.exists(), "Witness file not created");

    // Perform trusted setup
    println!("\nStep 3: Performing trusted setup...");
    let power = 8; // 2^8 = 256 constraints
    complete_setup(
        &config,
        &paths.r1cs,
        &paths.proving_key,
        &paths.verification_key,
        power,
    ).unwrap();

    assert!(paths.proving_key.exists(), "Proving key not created");
    assert!(paths.verification_key.exists(), "Verification key not created");
    println!("  Proving key: {}", paths.proving_key.display());
    println!("  Verification key: {}", paths.verification_key.display());

    // Generate proof with rapidsnark
    println!("\nStep 4: Generating proof with rapidsnark...");
    let proof_result = rapidsnark_prove(
        &config,
        &paths.proving_key,
        &paths.witness,
        &paths.proof,
        &paths.public_inputs,
    ).unwrap();

    println!("  Proof generated in {} ms", proof_result.proving_time_ms);
    println!("  Proof: {}", paths.proof.display());
    println!("  Public inputs: {}", paths.public_inputs.display());

    assert!(paths.proof.exists(), "Proof file not created");
    assert!(paths.public_inputs.exists(), "Public inputs file not created");

    // Verify with rapidsnark
    println!("\nStep 5: Verifying with rapidsnark...");
    let verification_result = rapidsnark_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    ).unwrap();

    println!("  Valid: {}", verification_result.is_valid);
    println!("  Verification took {} ms", verification_result.verification_time_ms);
    assert!(verification_result.is_valid, "Rapidsnark verification failed!");

    // Cross-verify with snarkjs
    println!("\nStep 6: Cross-verifying with snarkjs...");
    let snarkjs_valid = snarkjs_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    ).unwrap();

    println!("  Valid: {}", snarkjs_valid);
    assert!(snarkjs_valid, "Snarkjs verification failed!");

    // Test with different input
    println!("\n--- Testing with different input ---");
    let x2 = Fr::from(12u32);
    let x2_squared = Fr::from(144u32);
    println!("New test: x={}, x^2={}", 12, 144);

    let circuit2 = SquareCircuit { x: x2, x_squared: x2_squared };

    println!("Exporting new witness...");
    export_to_circom_files(
        circuit2,
        &paths.r1cs,
        &paths.witness,
    ).unwrap();

    println!("Generating new proof...");
    let proof_result2 = rapidsnark_prove(
        &config,
        &paths.proving_key,
        &paths.witness,
        &paths.proof,
        &paths.public_inputs,
    ).unwrap();

    println!("  Proof generated in {} ms", proof_result2.proving_time_ms);

    println!("Verifying new proof...");
    let verification_result2 = rapidsnark_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    ).unwrap();

    println!("  Valid: {}", verification_result2.is_valid);
    assert!(verification_result2.is_valid, "Second proof verification failed!");

    println!("\n✓ All tests passed! Rapidsnark integration is working correctly.");
    println!("\nPerformance Summary:");
    println!("  First proof:  {} ms", proof_result.proving_time_ms);
    println!("  Second proof: {} ms", proof_result2.proving_time_ms);
    println!("  Verification: {} ms", verification_result.verification_time_ms);
}

#[test]
fn test_witness_generation_only() {
    // This test can run without rapidsnark/snarkjs
    let temp_dir = std::env::temp_dir();
    let r1cs_path = temp_dir.join("test_square.r1cs");
    let wtns_path = temp_dir.join("test_square.wtns");

    let x = Fr::from(10u32);
    let x_squared = Fr::from(100u32);
    let circuit = SquareCircuit { x, x_squared };

    let stats = export_to_circom_files(
        circuit,
        &r1cs_path,
        &wtns_path,
    ).unwrap();

    assert!(r1cs_path.exists());
    assert!(wtns_path.exists());
    assert!(stats.num_constraints > 0);
    println!("Circuit stats: {} constraints, {} wires",
             stats.num_constraints, stats.num_wires);

    // Cleanup
    let _ = std::fs::remove_file(r1cs_path);
    let _ = std::fs::remove_file(wtns_path);
}
