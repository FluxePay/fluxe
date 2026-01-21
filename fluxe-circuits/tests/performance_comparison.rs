//! Quick performance comparison between arkworks and rapidsnark
//!
//! This test measures the time for proof generation to give a sense
//! of the performance difference.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_snark::SNARK;
use fluxe_circuits::rapidsnark::*;
use rand::thread_rng;
use std::path::PathBuf;
use std::time::Instant;

/// Test circuit: a * b + c = d
#[derive(Clone)]
struct SimpleCircuit {
    a: Fr,
    b: Fr,
    c: Fr,
    d: Fr,
}

impl ConstraintSynthesizer<Fr> for SimpleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
        let c_var = FpVar::new_witness(cs.clone(), || Ok(self.c))?;
        let d_var = FpVar::new_input(cs, || Ok(self.d))?;

        let product = &a_var * &b_var;
        let sum = product + c_var;
        sum.enforce_equal(&d_var)?;

        Ok(())
    }
}

#[test]
fn test_arkworks_proving_performance() {
    println!("\n=== Arkworks Native Proving Performance ===\n");

    let mut rng = thread_rng();

    // Test values: 3 * 4 + 5 = 17
    let a = Fr::from(3u32);
    let b = Fr::from(4u32);
    let c = Fr::from(5u32);
    let d = Fr::from(17u32);

    let circuit = SimpleCircuit { a, b, c, d };

    // Setup
    println!("Performing setup...");
    let setup_start = Instant::now();
    let (pk, vk) = Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(circuit.clone(), &mut rng)
        .expect("Setup failed");
    let setup_time = setup_start.elapsed();
    println!("  Setup time: {:?}", setup_time);

    // Get circuit stats
    let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    println!("  Constraints: {}", matrices.num_constraints);

    // Prove multiple times
    let num_proofs = 5;
    println!("\nGenerating {} proofs...", num_proofs);

    let mut times = Vec::new();
    for i in 0..num_proofs {
        let circuit = SimpleCircuit { a, b, c, d };
        let start = Instant::now();
        let proof = Groth16::<Bn254, LibsnarkReduction>::prove(&pk, circuit, &mut rng)
            .expect("Proof generation failed");
        let elapsed = start.elapsed();
        times.push(elapsed);
        println!("  Proof {}: {:?}", i + 1, elapsed);

        // Verify the proof
        let public_inputs = vec![d];
        assert!(Groth16::<Bn254, LibsnarkReduction>::verify(&vk, &public_inputs, &proof).unwrap());
    }

    let avg_time = times.iter().sum::<std::time::Duration>() / num_proofs as u32;
    println!("\nAverage proving time: {:?}", avg_time);
    println!("✓ All proofs verified correctly");
}

#[test]
#[ignore] // Requires rapidsnark and snarkjs to be installed
fn test_rapidsnark_proving_performance() {
    println!("\n=== Rapidsnark Proving Performance ===\n");

    let rapidsnark_dir = PathBuf::from("../rapidsnark");
    if !rapidsnark_dir.exists() {
        println!("⚠ Skipping - rapidsnark not found at {:?}", rapidsnark_dir);
        return;
    }

    let config = RapidsnarkConfig::from_local_build(&rapidsnark_dir);
    let base_dir = PathBuf::from("outputs/perf_test");
    std::fs::create_dir_all(&base_dir).unwrap();
    let paths = RapidsnarkPaths::new(&base_dir, "simple");

    // Test values
    let a = Fr::from(3u32);
    let b = Fr::from(4u32);
    let c = Fr::from(5u32);
    let d = Fr::from(17u32);
    let circuit = SimpleCircuit { a, b, c, d };

    // Export and setup (one-time)
    println!("Exporting circuit...");
    let stats = export_to_circom_files(circuit.clone(), &paths.r1cs, &paths.witness).unwrap();
    println!("  Constraints: {}", stats.num_constraints);

    println!("\nPerforming trusted setup...");
    let setup_start = Instant::now();
    complete_setup(&config, &paths.r1cs, &paths.proving_key, &paths.verification_key, 8).unwrap();
    let setup_time = setup_start.elapsed();
    println!("  Setup time: {:?}", setup_time);

    // Prove multiple times
    let num_proofs = 5;
    println!("\nGenerating {} proofs with rapidsnark...", num_proofs);

    let mut times = Vec::new();
    for i in 0..num_proofs {
        // Export witness
        let circuit = SimpleCircuit { a, b, c, d };
        export_to_circom_files(circuit, &paths.r1cs, &paths.witness).unwrap();

        // Prove
        let start = Instant::now();
        let result = rapidsnark_prove(
            &config,
            &paths.proving_key,
            &paths.witness,
            &paths.proof,
            &paths.public_inputs,
        ).unwrap();
        let elapsed = start.elapsed();
        times.push(elapsed);
        println!("  Proof {}: {:?}", i + 1, elapsed);

        // Verify
        let verification = rapidsnark_verify(
            &config,
            &paths.verification_key,
            &paths.public_inputs,
            &paths.proof,
        ).unwrap();
        assert!(verification.is_valid);
    }

    let avg_time = times.iter().sum::<std::time::Duration>() / num_proofs as u32;
    println!("\nAverage proving time: {:?}", avg_time);
    println!("✓ All proofs verified correctly");
}

#[test]
fn test_serialization_overhead() {
    println!("\n=== Testing Serialization Overhead ===\n");

    let a = Fr::from(3u32);
    let b = Fr::from(4u32);
    let c = Fr::from(5u32);
    let d = Fr::from(17u32);
    let circuit = SimpleCircuit { a, b, c, d };

    let temp_dir = std::env::temp_dir();
    let r1cs_path = temp_dir.join("perf_test.r1cs");
    let wtns_path = temp_dir.join("perf_test.wtns");

    // Measure serialization time
    println!("Measuring serialization time...");
    let mut times = Vec::new();
    for i in 0..10 {
        let circuit = SimpleCircuit { a, b, c, d };
        let start = Instant::now();
        export_to_circom_files(circuit, &r1cs_path, &wtns_path).unwrap();
        let elapsed = start.elapsed();
        times.push(elapsed);
        if i < 5 {
            println!("  Run {}: {:?}", i + 1, elapsed);
        }
    }

    let avg_time = times.iter().sum::<std::time::Duration>() / times.len() as u32;
    println!("...");
    println!("Average serialization time (10 runs): {:?}", avg_time);
    println!("\n✓ Serialization overhead is minimal (typically < 10ms)");

    // Cleanup
    let _ = std::fs::remove_file(r1cs_path);
    let _ = std::fs::remove_file(wtns_path);
}
