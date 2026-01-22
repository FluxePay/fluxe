use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use r1cs_file::{FieldElement as R1csFE, Header, Constraint as R1csConstraint, Constraints, R1csFile, WireMap};
use wtns_file::{WtnsFile, FieldElement as WtnsFE};
use std::fs::File;
use std::path::Path;
use crate::errors::{RapidsnarkError, Result};

const FIELD_SIZE: usize = 32; // BN254 Fr elements are 32 bytes

/// Export an arkworks circuit (BN254) to Circom-compatible R1CS and WTNS files
///
/// This function takes a constraint synthesizer circuit and exports it to the format
/// used by Circom/SnarkJS, allowing proof generation with rapidsnark.
///
/// # Arguments
/// * `circuit` - The arkworks circuit to export
/// * `r1cs_path` - Path where the R1CS file will be written
/// * `wtns_path` - Path where the witness file will be written
///
/// # Returns
/// * `Result<CircuitStats>` - Statistics about the exported circuit
pub fn export_to_circom_files<C, P1, P2>(
    circuit: C,
    r1cs_path: P1,
    wtns_path: P2,
) -> Result<CircuitStats>
where
    C: ConstraintSynthesizer<Fr>,
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    // 1) Build constraint system and synthesize
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone())
        .map_err(|e| RapidsnarkError::Circuit(format!("Failed to generate constraints: {}", e)))?;
    cs.finalize();

    // 2) Get matrices and dimensions
    let matrices = cs.to_matrices()
        .ok_or_else(|| RapidsnarkError::Circuit("Failed to get matrices".to_string()))?;

    let num_constraints = matrices.num_constraints;
    let num_instance = matrices.num_instance_variables; // public vars (includes constant 1)
    let num_witness = matrices.num_witness_variables;   // private vars

    println!("Circuit statistics:");
    println!("  Constraints: {}", num_constraints);
    println!("  Public inputs (including constant 1): {}", num_instance);
    println!("  Private inputs: {}", num_witness);

    // 3) Create R1CS header
    // Get BLS12-381 Fr prime field modulus as little-endian bytes
    let prime_bytes = <Fr as PrimeField>::MODULUS.to_bytes_le();
    let mut prime_le_32 = [0u8; FIELD_SIZE];
    prime_le_32[..prime_bytes.len().min(FIELD_SIZE)].copy_from_slice(&prime_bytes[..prime_bytes.len().min(FIELD_SIZE)]);
    let prime = R1csFE::<FIELD_SIZE>::from(prime_le_32);

    // Total wires = instance + witness
    let n_wires = num_instance + num_witness;
    let header = Header::<FIELD_SIZE> {
        prime,
        n_wires: n_wires as u32,
        n_pub_out: 0,                      // arkworks doesn't distinguish outputs
        n_pub_in: num_instance as u32,     // all public vars are inputs
        n_prvt_in: num_witness as u32,     // all private vars
        n_labels: n_wires as u64,
        n_constraints: num_constraints as u32,
    };

    // 4) Convert arkworks matrices to Circom format
    // Helper to convert sparse row to Circom terms (coefficient, wire_index) pairs
    let to_terms = |row: &Vec<(Fr, usize)>| -> Vec<(R1csFE<FIELD_SIZE>, u32)> {
        row.iter()
            .map(|(coeff, col_idx)| {
                // Convert coefficient to little-endian bytes
                let coeff_bytes = coeff.into_bigint().to_bytes_le();
                let mut le32 = [0u8; FIELD_SIZE];
                le32[..coeff_bytes.len().min(FIELD_SIZE)].copy_from_slice(&coeff_bytes[..coeff_bytes.len().min(FIELD_SIZE)]);
                (R1csFE::<FIELD_SIZE>::from(le32), *col_idx as u32)
            })
            .collect()
    };

    // Convert all constraints (A, B, C matrices)
    let mut constraints = Vec::with_capacity(num_constraints);
    for i in 0..num_constraints {
        let a_terms = to_terms(&matrices.a[i]);
        let b_terms = to_terms(&matrices.b[i]);
        let c_terms = to_terms(&matrices.c[i]);
        constraints.push(R1csConstraint::<FIELD_SIZE>(a_terms, b_terms, c_terms));
    }

    // 5) Write R1CS file
    let mut r1cs_file = File::create(r1cs_path.as_ref())?;
    R1csFile::<FIELD_SIZE> {
        header,
        constraints: Constraints(constraints),
        map: WireMap::default(),
    }.write(&mut r1cs_file)
        .map_err(|e| RapidsnarkError::Serialization(format!("Failed to write R1CS: {}", e)))?;

    println!("Written R1CS to: {}", r1cs_path.as_ref().display());

    // 6) Build witness vector in Circom order
    // IMPORTANT: Arkworks includes the constant 1 as the first element in instance_assignment
    // Order: [1, public_inputs...] in instance_values, [private_inputs...] in witness_values
    let cs_borrow = cs.borrow()
        .ok_or_else(|| RapidsnarkError::Circuit("Failed to borrow constraint system".to_string()))?;

    let instance_values = cs_borrow.instance_assignment.clone();
    let witness_values = cs_borrow.witness_assignment.clone();

    let mut witness_vector = Vec::with_capacity(n_wires);

    // Instance values (already include the constant 1 as first element)
    for val in instance_values {
        let val_bytes = val.into_bigint().to_bytes_le();
        let mut le32 = [0u8; FIELD_SIZE];
        le32[..val_bytes.len().min(FIELD_SIZE)].copy_from_slice(&val_bytes[..val_bytes.len().min(FIELD_SIZE)]);
        witness_vector.push(WtnsFE::<FIELD_SIZE>::from(le32));
    }

    // Private inputs
    for val in witness_values {
        let val_bytes = val.into_bigint().to_bytes_le();
        let mut le32 = [0u8; FIELD_SIZE];
        le32[..val_bytes.len().min(FIELD_SIZE)].copy_from_slice(&val_bytes[..val_bytes.len().min(FIELD_SIZE)]);
        witness_vector.push(WtnsFE::<FIELD_SIZE>::from(le32));
    }

    // 7) Write WTNS file
    let mut wtns_file = File::create(wtns_path.as_ref())?;
    // Create WTNS prime from same bytes (little-endian)
    let prime_bytes_wtns = <Fr as PrimeField>::MODULUS.to_bytes_le();
    let mut prime_le_32_wtns = [0u8; FIELD_SIZE];
    prime_le_32_wtns[..prime_bytes_wtns.len().min(FIELD_SIZE)].copy_from_slice(&prime_bytes_wtns[..prime_bytes_wtns.len().min(FIELD_SIZE)]);
    let prime_wtns = WtnsFE::<FIELD_SIZE>::from(prime_le_32_wtns);

    WtnsFile::<FIELD_SIZE>::from_vec(witness_vector, prime_wtns)
        .write(&mut wtns_file)
        .map_err(|e| RapidsnarkError::Serialization(format!("Failed to write WTNS: {}", e)))?;

    println!("Written witness to: {}", wtns_path.as_ref().display());

    Ok(CircuitStats {
        num_constraints,
        num_public_inputs: num_instance,
        num_private_inputs: num_witness,
        total_wires: n_wires,
    })
}

/// Statistics about an exported circuit
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub num_constraints: usize,
    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
    pub total_wires: usize,
}

impl CircuitStats {
    pub fn print(&self) {
        println!("=== Circuit Statistics ===");
        println!("Constraints:       {}", self.num_constraints);
        println!("Public inputs:     {}", self.num_public_inputs);
        println!("Private inputs:    {}", self.num_private_inputs);
        println!("Total wires:       {}", self.total_wires);
        println!("=========================");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::prelude::*;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

    #[derive(Clone)]
    struct TestCircuit {
        a: Fr,
        b: Fr,
        c: Fr,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> std::result::Result<(), SynthesisError> {
            let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
            let b_var = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
            let c_var = FpVar::new_input(cs, || Ok(self.c))?;

            let ab = &a_var * &b_var;
            ab.enforce_equal(&c_var)?;

            Ok(())
        }
    }

    #[test]
    fn test_export_simple_circuit() {
        use ark_ff::Field;

        let circuit = TestCircuit {
            a: Fr::from(3u64),
            b: Fr::from(5u64),
            c: Fr::from(15u64),
        };

        let stats = export_to_circom_files(
            circuit,
            "/tmp/test_circuit.r1cs",
            "/tmp/test_witness.wtns",
        ).expect("Export failed");

        stats.print();

        assert!(stats.num_constraints > 0);
        assert!(stats.num_public_inputs >= 1); // at least constant 1
        assert!(stats.num_private_inputs >= 2); // a and b
    }
}
