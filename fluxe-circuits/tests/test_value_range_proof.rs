use ark_bls12_381::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;

use fluxe_circuits::gadgets::range_proof::RangeProofGadget;

#[test]
fn test_value_range_proof_direct() {
    println!("\n=== Testing Value Range Proofs Directly ===\n");
    
    // Test various values
    let test_values = vec![
        (0u64, "zero"),
        (1u64, "one"),
        (10u64, "ten"),
        (990u64, "nine-ninety"),
        (1000u64, "thousand"),
        (u32::MAX as u64, "u32_max"),
        ((1u64 << 63) - 1, "max_63_bit"),
        (u64::MAX, "u64_max"),
    ];
    
    for (value, name) in test_values {
        println!("Testing value: {} ({})", value, name);
        
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Create value as field element
        let value_field = F::from(value);
        let value_var = FpVar::new_witness(cs.clone(), || Ok(value_field)).unwrap();
        
        println!("  Field representation: {:?}", value_field);
        println!("  Constraints before: {}", cs.num_constraints());
        
        // Apply 64-bit range proof
        let result = RangeProofGadget::prove_range_bits(cs.clone(), &value_var, 64);
        
        println!("  Constraints after: {}", cs.num_constraints());
        
        if let Err(e) = result {
            println!("  ❌ Range proof failed: {:?}", e);
            continue;
        }
        
        if !cs.is_satisfied().unwrap() {
            if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                println!("  ❌ Constraint {} unsatisfied", unsat);
            }
        } else {
            println!("  ✅ All constraints satisfied");
        }
        
        println!();
    }
}

#[test]
fn test_value_conversion_consistency() {
    println!("\n=== Testing Value Field Conversion ===\n");
    
    let values = vec![990u64, 1000u64, 10u64];
    
    for value in values {
        let field = F::from(value);
        
        // Get the bits representation
        let cs = ConstraintSystem::<F>::new_ref();
        let value_var = FpVar::new_witness(cs.clone(), || Ok(field)).unwrap();
        let bits = value_var.to_bits_le().unwrap();
        
        // Reconstruct value from first 64 bits
        let mut reconstructed = 0u64;
        for (i, bit) in bits.iter().take(64).enumerate() {
            if bit.value().unwrap() {
                reconstructed |= 1u64 << i;
            }
        }
        
        println!("Original: {}", value);
        println!("Field: {:?}", field);
        println!("Bits (first 8): {:?}", bits.iter().take(8).map(|b| b.value().unwrap()).collect::<Vec<_>>());
        println!("Reconstructed: {}", reconstructed);
        println!("Match: {}", value == reconstructed);
        println!();
    }
}