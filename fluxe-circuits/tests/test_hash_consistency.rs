use ark_bls12_381::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_tree::SortedLeafVar;
use fluxe_core::merkle::SortedLeaf;
use fluxe_core::crypto::poseidon_hash;

#[test]
fn test_hash_consistency() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Hash Consistency ===\n");
    
    // Create a sorted leaf
    let leaf = SortedLeaf {
        key: F::from(0u64),
        next_key: F::from(0u64),
        next_index: 0,
    };
    
    // Compute hash outside circuit
    let hash_outside = poseidon_hash(&[leaf.key,
        leaf.next_key,
        F::from(leaf.next_index as u64)]);
    
    println!("Hash computed outside circuit: {:?}", hash_outside);
    
    // Now compute hash inside circuit
    let cs = ConstraintSystem::<F>::new_ref();
    
    let leaf_var = SortedLeafVar::new_witness(cs.clone(), || Ok(leaf.clone()))?;
    let hash_var = leaf_var.hash()?;
    
    // Get the value
    let hash_inside = hash_var.value()?;
    
    println!("Hash computed inside circuit: {:?}", hash_inside);
    println!("Match: {}", hash_outside == hash_inside);
    
    if hash_outside != hash_inside {
        panic!("❌ HASH MISMATCH!");
    }
    
    // Now test with non-zero values
    let leaf2 = SortedLeaf {
        key: F::from(12345u64),
        next_key: F::from(67890u64),
        next_index: 42,
    };
    
    let hash2_outside = poseidon_hash(&[leaf2.key,
        leaf2.next_key,
        F::from(leaf2.next_index as u64)]);
    
    let leaf2_var = SortedLeafVar::new_witness(cs.clone(), || Ok(leaf2.clone()))?;
    let hash2_var = leaf2_var.hash()?;
    let hash2_inside = hash2_var.value()?;
    
    println!("\nSecond test (non-zero values):");
    println!("Hash outside: {:?}", hash2_outside);
    println!("Hash inside: {:?}", hash2_inside);
    println!("Match: {}", hash2_outside == hash2_inside);
    
    if hash2_outside != hash2_inside {
        panic!("❌ HASH MISMATCH for non-zero values!");
    }
    
    // Now test if the constraint is satisfied
    hash_var.enforce_equal(&FpVar::new_witness(cs.clone(), || Ok(hash_outside))?)?;
    hash2_var.enforce_equal(&FpVar::new_witness(cs.clone(), || Ok(hash2_outside))?)?;
    
    println!("\nConstraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            panic!("❌ Unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ All hash constraints satisfied!");
    }
    
    Ok(())
}