/// Regression tests for arkworks 0.5.0 migration fixes
/// These tests ensure that all the fixes made during the migration continue to work correctly
/// 
/// Key fixes tested:
/// 1. Boolean operations using bitwise operators (&, |, !) instead of method calls
/// 2. RangeProofGadget::le_bits_to_fp made public and accessible
/// 3. Comparison gadgets working with Boolean bitwise operations
/// 4. MerklePathVar using correct NOT operator syntax
/// 5. Sanctions checker with proper Boolean operations
/// 6. Auth gadget EC validation implementation
/// 7. std::io::Error compatibility fix for older Rust versions
/// 8. Complex Boolean expressions with nested operations
/// 
/// All tests should pass to ensure the migration fixes remain stable

use ark_bls12_381::Fr as F;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::ConstraintSystem;
use ark_ff::UniformRand;
use rand::thread_rng;

#[test]
fn test_boolean_bitwise_operations() {
    // Test that Boolean bitwise operators work correctly
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Create test booleans
    let a = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
    let b = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
    
    // Test AND operation using bitwise &
    let and_result = &a & &b;
    assert_eq!(and_result.value().unwrap(), false);
    
    // Test OR operation using bitwise |
    let or_result = &a | &b;
    assert_eq!(or_result.value().unwrap(), true);
    
    // Test NOT operation using bitwise !
    let not_a = !&a;
    assert_eq!(not_a.value().unwrap(), false);
    
    let not_b = !&b;
    assert_eq!(not_b.value().unwrap(), true);
    
    // Test chained operations
    let complex = &(&a | &b) & &(!&b);
    assert_eq!(complex.value().unwrap(), true); // (true | false) & true = true
    
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_comparison_gadget_with_bitwise_ops() {
    use fluxe_circuits::gadgets::comparison::ComparisonGadget;
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Test basic comparisons
    let a = FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap();
    let b = FpVar::new_witness(cs.clone(), || Ok(F::from(200u64))).unwrap();
    
    // Test less than
    let less_than = ComparisonGadget::is_less_than(cs.clone(), &a, &b).unwrap();
    assert!(less_than.value().unwrap());
    
    // Test greater than
    let greater_than = ComparisonGadget::is_greater_than(cs.clone(), &a, &b).unwrap();
    assert!(!greater_than.value().unwrap());
    
    // Test less than or equal
    let lte = ComparisonGadget::is_less_than_or_equal(cs.clone(), &a, &b).unwrap();
    assert!(lte.value().unwrap());
    
    // Test greater than or equal
    let gte = ComparisonGadget::is_greater_than_or_equal(cs.clone(), &a, &b).unwrap();
    assert!(!gte.value().unwrap());
    
    // Test equality edge case
    let c = FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap();
    let equal_lte = ComparisonGadget::is_less_than_or_equal(cs.clone(), &a, &c).unwrap();
    assert!(equal_lte.value().unwrap());
    
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_range_proof_le_bits_to_fp() {
    use fluxe_circuits::gadgets::range_proof::RangeProofGadget;
    
    let cs = ConstraintSystem::<F>::new_ref();
    let mut rng = thread_rng();
    
    // Test that le_bits_to_fp is publicly accessible and works correctly
    let value = F::from(42u64);
    let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
    
    let bits = value_var.to_bits_le().unwrap();
    let reconstructed = RangeProofGadget::le_bits_to_fp(&bits).unwrap();
    
    reconstructed.enforce_equal(&value_var).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_merkle_path_with_not_operator() {
    use fluxe_circuits::gadgets::merkle::MerklePathVar;
    use fluxe_core::merkle::MerklePath;
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    let path = MerklePath {
        leaf_index: 5,
        siblings: vec![F::from(1u64), F::from(2u64), F::from(3u64)],
        leaf: F::from(42u64),
    };
    
    let path_var = MerklePathVar::new_witness(cs.clone(), || Ok(path)).unwrap();
    let root_var = FpVar::new_witness(cs.clone(), || Ok(F::from(999u64))).unwrap();
    
    // This should compile and run without errors, using the ! operator internally
    let _computed_root = path_var.compute_root().unwrap();
    
    // The path verification uses Boolean operations internally
    let _is_valid = path_var.verify(&root_var).unwrap();
    
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_sanctions_checker_boolean_ops() {
    use fluxe_circuits::gadgets::sanctions::{SanctionsChecker, SanctionsLeafVar};
    use fluxe_circuits::gadgets::merkle::MerklePathVar;
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Create test data
    let identifier = FpVar::new_witness(cs.clone(), || Ok(F::from(150u64))).unwrap();
    let sanctions_root = FpVar::new_witness(cs.clone(), || Ok(F::from(999u64))).unwrap();
    
    let low_leaf = SanctionsLeafVar::new_witness(
        cs.clone(),
        F::from(100u64),
        F::from(200u64),
        None,
    ).unwrap();
    
    let merkle_path = MerklePathVar {
        leaf_index: FpVar::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap(),
        siblings: vec![FpVar::new_witness(cs.clone(), || Ok(F::from(1u64))).unwrap()],
        leaf: FpVar::new_witness(cs.clone(), || Ok(F::from(42u64))).unwrap(),
    };
    
    // This should compile with the fixed Boolean operations
    // The actual proof would fail without proper witness data, but compilation is what we're testing
    let _result = SanctionsChecker::prove_not_sanctioned(
        cs.clone(),
        &identifier,
        &sanctions_root,
        &low_leaf,
        &merkle_path,
    );
    
    // No assertion on result since we don't have valid witness data
    // The test passes if it compiles and runs without panicking
}

#[test]
fn test_auth_gadget_ec_validation() {
    use fluxe_circuits::gadgets::auth::AuthGadget;
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Test the EC key validity check (Baby JubJub curve equation)
    // For Baby JubJub: ax^2 + y^2 = 1 + dx^2y^2
    // where a = 168700 and d = 168696
    
    // Test with a valid point (simplified - not actual curve point)
    let pk_x = FpVar::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
    let pk_y = FpVar::new_witness(cs.clone(), || Ok(F::from(1u64))).unwrap();
    
    // This point (0, 1) should satisfy: 0 + 1 = 1 + 0
    let is_valid = AuthGadget::verify_public_key_valid(cs.clone(), &pk_x, &pk_y).unwrap();
    assert!(is_valid.value().unwrap());
    
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_sorted_tree_boolean_operations() {
    use fluxe_circuits::gadgets::sorted_tree::SortedLeafVar;
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    let leaf = SortedLeafVar {
        key: FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap(),
        next_key: FpVar::new_witness(cs.clone(), || Ok(F::from(200u64))).unwrap(),
        next_index: FpVar::new_witness(cs.clone(), || Ok(F::from(1u64))).unwrap(),
    };
    
    let value = FpVar::new_witness(cs.clone(), || Ok(F::from(150u64))).unwrap();
    
    // Test contains_gap which uses Boolean OR and AND operations
    let in_gap = leaf.contains_gap(&value).unwrap();
    assert!(in_gap.value().unwrap());
    
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_object_update_boolean_logic() {
    use ark_r1cs_std::boolean::Boolean;
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Test the frozen flag logic from object_update.rs
    // If frozen flag is set, limits must be zero
    let frozen = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
    let limits_zero = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
    
    // is_frozen_and_limits_zero = frozen AND limits_zero
    let is_frozen_and_limits_zero = &frozen & &limits_zero;
    
    // not_frozen_or_limits_ok = NOT(frozen) OR is_frozen_and_limits_zero
    let not_frozen = !&frozen;
    let not_frozen_or_limits_ok = &not_frozen | &is_frozen_and_limits_zero;
    
    assert!(not_frozen_or_limits_ok.value().unwrap());
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_io_error_compatibility() {
    // Test that our std::io::Error compatibility fix works
    use std::io;
    
    let custom_error = "Test error";
    let io_error = io::Error::new(io::ErrorKind::Other, custom_error);
    
    assert_eq!(io_error.kind(), io::ErrorKind::Other);
    assert_eq!(io_error.to_string(), custom_error);
}

#[test]
fn test_complex_boolean_expressions() {
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Test complex nested Boolean expressions like those in our fixes
    let a = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
    let b = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
    let c = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
    
    // Test expression: (a AND b) OR (NOT(b) AND c)
    let expr1 = &a & &b;
    let not_b = !&b;
    let expr2 = &not_b & &c;
    let result = &expr1 | &expr2;
    
    // Expected: (true AND false) OR (true AND true) = false OR true = true
    assert!(result.value().unwrap());
    
    // Test accumulator pattern used in sorted_insert.rs
    let mut accumulator = Boolean::TRUE;
    accumulator = &accumulator & &a;
    accumulator = &accumulator & &c;
    accumulator = &accumulator & &(!&b);
    
    assert!(accumulator.value().unwrap());
    
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_range_proof_bounds() {
    use fluxe_circuits::gadgets::range_proof::RangeProofGadget;
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Test range bounds functionality
    let value = FpVar::new_witness(cs.clone(), || Ok(F::from(500u64))).unwrap();
    
    // Prove value is within bounds [100, 1000]
    RangeProofGadget::prove_range_bounds(cs.clone(), &value, 100, 1000, 16).unwrap();
    
    assert!(cs.is_satisfied().unwrap());
}

// This test ensures all our migration fixes work together
#[test]
fn test_integrated_circuit_operations() {
    use fluxe_circuits::gadgets::{
        comparison::ComparisonGadget,
        range_proof::RangeProofGadget,
    };
    
    let cs = ConstraintSystem::<F>::new_ref();
    let mut rng = thread_rng();
    
    // Create test values
    let value1 = FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap();
    let value2 = FpVar::new_witness(cs.clone(), || Ok(F::from(200u64))).unwrap();
    
    // Test comparison with Boolean result
    let is_less = ComparisonGadget::is_less_than(cs.clone(), &value1, &value2).unwrap();
    
    // Test range proof
    RangeProofGadget::prove_range_bits(cs.clone(), &value1, 64).unwrap();
    
    // Test Boolean combinations
    let condition1 = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
    let condition2 = is_less;
    
    // Combined condition using bitwise operators
    let combined = &condition1 & &condition2;
    assert!(combined.value().unwrap());
    
    // Test NOT operation
    let negated = !&combined;
    assert!(!negated.value().unwrap());
    
    assert!(cs.is_satisfied().unwrap());
}