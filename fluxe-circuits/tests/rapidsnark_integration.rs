//! Integration test for rapidsnark proving
//!
//! This test verifies that the arkworks to rapidsnark pipeline works correctly.

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use fluxe_circuits::rapidsnark::*;
use std::path::PathBuf;

/// Simple test circuit: proves knowledge of a and b such that a * b = c
#[derive(Clone)]
struct MultiplyCircuit {
    a: Fr,
    b: Fr,
    c: Fr,
}

impl ConstraintSynthesizer<Fr> for MultiplyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
        let c_var = FpVar::new_input(cs, || Ok(self.c))?;

        let product = a_var * b_var;
        product.enforce_equal(&c_var)?;

        Ok(())
    }
}

#[test]
#[ignore] // Requires rapidsnark and snarkjs to be installed
fn test_rapidsnark_full_pipeline() {
    // Create output directory
    let base_dir = PathBuf::from("outputs/test_rapidsnark");
    std::fs::create_dir_all(&base_dir).unwrap();

    let paths = RapidsnarkPaths::new(&base_dir, "multiply");
    paths.ensure_base_dir().unwrap();

    // Configure rapidsnark
    let rapidsnark_dir = PathBuf::from("../../rapidsnark");
    let config = RapidsnarkConfig::from_local_build(&rapidsnark_dir);

    // Create circuit: 3 * 5 = 15
    let circuit = MultiplyCircuit {
        a: Fr::from(3u32),
        b: Fr::from(5u32),
        c: Fr::from(15u32),
    };

    // Export to Circom formats
    println!("Exporting circuit...");
    let stats = export_to_circom_files(
        circuit.clone(),
        &paths.r1cs,
        &paths.witness,
    ).unwrap();

    println!("{}", stats);
    assert!(stats.num_constraints > 0);
    assert!(paths.r1cs.exists());
    assert!(paths.witness.exists());

    // Perform setup
    println!("Performing setup...");
    let power = 8; // 2^8 = 256 constraints, enough for this simple circuit
    complete_setup(
        &config,
        &paths.r1cs,
        &paths.proving_key,
        &paths.verification_key,
        power,
    ).unwrap();

    assert!(paths.proving_key.exists());
    assert!(paths.verification_key.exists());

    // Generate proof
    println!("Generating proof with rapidsnark...");
    let proof_result = rapidsnark_prove(
        &config,
        &paths.proving_key,
        &paths.witness,
        &paths.proof,
        &paths.public_inputs,
    ).unwrap();

    println!("Proof generated in {} ms", proof_result.proving_time_ms);
    assert!(paths.proof.exists());
    assert!(paths.public_inputs.exists());

    // Verify with rapidsnark
    println!("Verifying with rapidsnark...");
    let verification_result = rapidsnark_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    ).unwrap();

    assert!(verification_result.is_valid, "Rapidsnark verification failed");
    println!("Verification took {} ms", verification_result.verification_time_ms);

    // Cross-verify with snarkjs
    println!("Cross-verifying with snarkjs...");
    let snarkjs_valid = snarkjs_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    ).unwrap();

    assert!(snarkjs_valid, "Snarkjs verification failed");

    println!("✓ All tests passed!");
}

#[test]
fn test_circuit_export_only() {
    // This test doesn't require rapidsnark/snarkjs to be installed
    let temp_dir = std::env::temp_dir();
    let r1cs_path = temp_dir.join("test_multiply.r1cs");
    let wtns_path = temp_dir.join("test_multiply.wtns");

    let circuit = MultiplyCircuit {
        a: Fr::from(7u32),
        b: Fr::from(8u32),
        c: Fr::from(56u32),
    };

    let stats = export_to_circom_files(
        circuit,
        &r1cs_path,
        &wtns_path,
    ).unwrap();

    assert!(r1cs_path.exists());
    assert!(wtns_path.exists());
    assert!(stats.num_constraints > 0);
    assert_eq!(stats.num_public_inputs, 2); // constant 1 + output c

    // Cleanup
    let _ = std::fs::remove_file(r1cs_path);
    let _ = std::fs::remove_file(wtns_path);
}
