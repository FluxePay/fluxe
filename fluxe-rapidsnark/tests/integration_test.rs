/// Integration tests for fluxe-rapidsnark
///
/// These tests verify that the serialization and export functionality works correctly

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use fluxe_rapidsnark::export_to_circom_files;
use std::path::PathBuf;

#[derive(Clone)]
struct TestCircuit {
    a: Fr,
    b: Fr,
    c: Fr,
}

impl ConstraintSynthesizer<Fr> for TestCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
        let c_var = FpVar::new_input(cs, || Ok(self.c))?;

        let ab = &a_var * &b_var;
        ab.enforce_equal(&c_var)?;

        Ok(())
    }
}

#[test]
fn test_export_basic_circuit() {
    let circuit = TestCircuit {
        a: Fr::from(3u64),
        b: Fr::from(5u64),
        c: Fr::from(15u64),
    };

    let temp_dir = std::env::temp_dir();
    let r1cs_path = temp_dir.join("test_circuit.r1cs");
    let wtns_path = temp_dir.join("test_witness.wtns");

    let result = export_to_circom_files(circuit, &r1cs_path, &wtns_path);
    assert!(result.is_ok(), "Export should succeed");

    let stats = result.unwrap();
    assert!(stats.num_constraints > 0, "Should have constraints");
    assert!(stats.num_public_inputs >= 1, "Should have at least constant 1");
    assert!(stats.num_private_inputs >= 2, "Should have at least a and b");

    // Verify files were created
    assert!(r1cs_path.exists(), "R1CS file should exist");
    assert!(wtns_path.exists(), "WTNS file should exist");

    // Cleanup
    let _ = std::fs::remove_file(r1cs_path);
    let _ = std::fs::remove_file(wtns_path);
}

#[test]
fn test_circuit_stats() {
    let circuit = TestCircuit {
        a: Fr::from(10u64),
        b: Fr::from(20u64),
        c: Fr::from(200u64),
    };

    let temp_dir = std::env::temp_dir();
    let r1cs_path = temp_dir.join("stats_test.r1cs");
    let wtns_path = temp_dir.join("stats_test.wtns");

    let stats = export_to_circom_files(circuit, &r1cs_path, &wtns_path)
        .expect("Export failed");

    // Verify stats are reasonable
    assert_eq!(
        stats.total_wires,
        stats.num_public_inputs + stats.num_private_inputs,
        "Total wires should equal public + private"
    );

    // Cleanup
    let _ = std::fs::remove_file(r1cs_path);
    let _ = std::fs::remove_file(wtns_path);
}

#[test]
fn test_multiple_exports() {
    // Test that we can export multiple circuits without issues
    let circuits = vec![
        TestCircuit {
            a: Fr::from(1u64),
            b: Fr::from(2u64),
            c: Fr::from(2u64),
        },
        TestCircuit {
            a: Fr::from(5u64),
            b: Fr::from(7u64),
            c: Fr::from(35u64),
        },
        TestCircuit {
            a: Fr::from(11u64),
            b: Fr::from(13u64),
            c: Fr::from(143u64),
        },
    ];

    let temp_dir = std::env::temp_dir();

    for (i, circuit) in circuits.iter().enumerate() {
        let r1cs_path = temp_dir.join(format!("multi_test_{}.r1cs", i));
        let wtns_path = temp_dir.join(format!("multi_test_{}.wtns", i));

        let result = export_to_circom_files(circuit.clone(), &r1cs_path, &wtns_path);
        assert!(result.is_ok(), "Export {} should succeed", i);

        // Cleanup
        let _ = std::fs::remove_file(r1cs_path);
        let _ = std::fs::remove_file(wtns_path);
    }
}
