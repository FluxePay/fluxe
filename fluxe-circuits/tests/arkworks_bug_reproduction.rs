// Test to reproduce arkworks 0.5.0 is_cmp bug
// Run with: cargo test --test arkworks_bug_reproduction

use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, SynthesisError};

#[test]
#[should_panic(expected = "assertion `left != right` failed")]
fn test_is_cmp_bug_panics() {
    let cs = ConstraintSystem::<F>::new_ref();
    
    // This specific combination triggers the bug:
    // - Witness variable with small value (2)
    // - Constant with value 2^n - 1 (15 = 2^4 - 1)
    // - Using is_cmp with allow_equal=true
    let witness_value = FpVar::new_witness(cs.clone(), || Ok(F::from(2u64))).unwrap();
    let constant_value = FpVar::constant(F::from(15u64));
    
    // Will panic with assertion failure in FpVar::sum()
    let _result = witness_value.is_cmp(
        &constant_value,
        std::cmp::Ordering::Less,
        true, // allow_equal=true is critical to trigger the bug
    ).unwrap();
}

#[test]
fn test_workaround_using_is_cmp_unchecked() -> Result<(), SynthesisError> {
    let cs = ConstraintSystem::<F>::new_ref();
    
    let witness_value = FpVar::new_witness(cs.clone(), || Ok(F::from(2u64)))?;
    let constant_value = FpVar::constant(F::from(15u64));
    
    // Using is_cmp_unchecked avoids the bug
    let result = witness_value.is_cmp_unchecked(
        &constant_value,
        std::cmp::Ordering::Less,
        true,
    )?;
    
    // Should be true since 2 <= 15
    assert!(result.value().unwrap());
    assert!(cs.is_satisfied().unwrap());
    
    Ok(())
}

#[test]
#[should_panic]
fn test_bug_pattern_2_lte_15() {
    let cs = ConstraintSystem::<F>::new_ref();
    let witness = FpVar::new_witness(cs.clone(), || Ok(F::from(2u64))).unwrap();
    let constant = FpVar::constant(F::from(15u64));
    
    // This will panic
    let _result = witness.is_cmp(
        &constant,
        std::cmp::Ordering::Less,
        true,
    ).unwrap();
}

#[test]
#[should_panic]
fn test_bug_pattern_3_lte_31() {
    let cs = ConstraintSystem::<F>::new_ref();
    let witness = FpVar::new_witness(cs.clone(), || Ok(F::from(3u64))).unwrap();
    let constant = FpVar::constant(F::from(31u64));
    
    // This will panic
    let _result = witness.is_cmp(
        &constant,
        std::cmp::Ordering::Less,
        true,
    ).unwrap();
}