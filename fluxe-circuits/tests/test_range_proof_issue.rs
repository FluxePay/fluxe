use ark_bls12_381::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::range_proof::RangeProofGadget;

#[test]
fn test_range_proof_for_output() {
    println!("\n=== Testing range proof constraints ===\n");
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Create a value that should pass range proof
    let value = 990u64;
    let value_var = FpVar::new_witness(cs.clone(), || Ok(F::from(value))).unwrap();
    
    println!("Initial constraints: {}", cs.num_constraints());
    
    // Apply 64-bit range proof
    RangeProofGadget::prove_range_bits(cs.clone(), &value_var, 64).unwrap();
    
    println!("After range proof: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ Range proof satisfied!");
    }
    
    // Now test what happens at the constraint count we see failing
    println!("\n=== Checking constraint count alignment ===");
    
    // In the full circuit:
    // - Public inputs: ~10
    // - Note witnessing: ~512
    // - EC auth for 2 inputs: ~6693
    // - Value conservation: a few constraints
    // - Asset type checks: a few constraints
    // So we should be at around 7200-7300 before range proofs
    
    // Range proof adds how many?
    let cs2 = ConstraintSystem::<F>::new_ref();
    let value2_var = FpVar::new_witness(cs2.clone(), || Ok(F::from(value))).unwrap();
    let before = cs2.num_constraints();
    RangeProofGadget::prove_range_bits(cs2.clone(), &value2_var, 64).unwrap();
    let after = cs2.num_constraints();
    
    println!("Range proof adds {} constraints", after - before);
    
    // So if we're at ~7200 and add range proof, we'd be at ~7200 + (after - before)
    let estimated_after_range = 7200 + (after - before);
    println!("Estimated constraints after first range proof: {}", estimated_after_range);
    
    if estimated_after_range > 7995 {
        println!("⚠️ Range proof would push us past constraint 7995!");
        println!("The failure is likely IN the range proof for the output value");
    }
}

#[test] 
fn test_value_conservation_exact() {
    println!("\n=== Testing value conservation ===\n");
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Create input values
    let value1 = F::from(500u64);
    let value2 = F::from(500u64);
    
    let value1_var = FpVar::new_witness(cs.clone(), || Ok(value1)).unwrap();
    let value2_var = FpVar::new_witness(cs.clone(), || Ok(value2)).unwrap();
    
    // Sum inputs
    let sum_in = &value1_var + &value2_var;
    
    // Create output value and fee
    let value_out = F::from(990u64);
    let fee = F::from(10u64);
    
    let value_out_var = FpVar::new_witness(cs.clone(), || Ok(value_out)).unwrap();
    let fee_var = FpVar::new_witness(cs.clone(), || Ok(fee)).unwrap();
    
    // Sum outputs
    let sum_out = &value_out_var + &fee_var;
    
    println!("Constraints before equality: {}", cs.num_constraints());
    
    // Enforce conservation
    sum_in.enforce_equal(&sum_out).unwrap();
    
    println!("Constraints after equality: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ Value conservation satisfied!");
    }
}