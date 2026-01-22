/// Simple example demonstrating basic circuit export to rapidsnark format
///
/// This example shows how to:
/// 1. Define a simple circuit
/// 2. Export it to R1CS and WTNS files
/// 3. Use the files with rapidsnark for proving

use ark_bn254::Fr;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use fluxe_rapidsnark::{export_to_circom_files, CircuitStats};

/// Simple demonstration circuit: proves a * b = c
#[derive(Clone)]
struct SimpleMultiplyCircuit {
    /// Private input
    pub a: Fr,
    /// Private input
    pub b: Fr,
    /// Public output: a * b
    pub c: Fr,
}

impl ConstraintSynthesizer<Fr> for SimpleMultiplyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_witness(cs.clone(), || Ok(self.b))?;

        // Allocate public output
        let c_var = FpVar::new_input(cs, || Ok(self.c))?;

        // Enforce constraint: a * b = c
        let ab = &a_var * &b_var;
        ab.enforce_equal(&c_var)?;

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Fluxe Rapidsnark Simple Circuit Example ===\n");

    // Create a simple circuit instance
    let circuit = SimpleMultiplyCircuit {
        a: Fr::from(7u64),
        b: Fr::from(13u64),
        c: Fr::from(91u64), // 7 * 13 = 91
    };

    println!("Circuit values:");
    println!("  a = 7 (private)");
    println!("  b = 13 (private)");
    println!("  c = 91 (public, should equal a * b)");
    println!();

    // Export to Circom-compatible files
    let output_dir = "fluxe-rapidsnark/outputs";
    std::fs::create_dir_all(output_dir)?;

    let r1cs_path = format!("{}/simple.r1cs", output_dir);
    let wtns_path = format!("{}/simple_witness.wtns", output_dir);

    println!("Exporting circuit to rapidsnark format...");
    let stats = export_to_circom_files(circuit, &r1cs_path, &wtns_path)?;

    println!();
    stats.print();

    println!();
    println!("=== Next Steps ===");
    println!("1. Run trusted setup:");
    println!("   cd fluxe-rapidsnark && ./scripts/setup.sh simple");
    println!();
    println!("2. Generate proof with rapidsnark:");
    println!("   cd fluxe-rapidsnark && ./scripts/prove.sh simple");
    println!();
    println!("3. Verify the proof:");
    println!("   cd fluxe-rapidsnark && ./scripts/verify.sh simple");

    Ok(())
}
