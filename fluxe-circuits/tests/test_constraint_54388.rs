use ark_bls12_381::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_insert::{SortedInsertWitness, SimtInsertVar};
use fluxe_circuits::gadgets::sorted_tree::{RangePathVar, SortedLeafVar};
use fluxe_circuits::gadgets::MerklePathVar;
use fluxe_core::merkle::{SortedTree, TreeParams};
use fluxe_core::crypto::poseidon_hash;

#[test]
fn test_constraint_54388_debug() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Debugging Constraint 54388 ===\n");
    
    // Create a simple sorted tree
    let mut nft_tree = SortedTree::new(16);
    
    // Insert a nullifier
    let nf = F::from(12345u64);
    
    // Get witnesses
    let nft_root_old = nft_tree.root();
    let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    
    println!("NFT root old: {:?}", nft_root_old);
    println!("NFT root new: {:?}", nft_root_new);
    
    // Debug the witness paths
    println!("\n--- Witness Analysis ---");
    
    // Check pred_update_path
    let original_pred_hash = poseidon_hash(&[insert_witness_core.range_proof.low_leaf.key,
        insert_witness_core.range_proof.low_leaf.next_key,
        F::from(insert_witness_core.range_proof.low_leaf.next_index as u64)]);
    
    println!("\nOriginal predecessor leaf:");
    println!("  key: {:?}", insert_witness_core.range_proof.low_leaf.key);
    println!("  next_key: {:?}", insert_witness_core.range_proof.low_leaf.next_key);
    println!("  next_index: {}", insert_witness_core.range_proof.low_leaf.next_index);
    println!("  computed hash: {:?}", original_pred_hash);
    
    println!("\npred_update_path:");
    println!("  leaf field: {:?}", insert_witness_core.pred_update_path.leaf);
    println!("  leaf_index: {}", insert_witness_core.pred_update_path.leaf_index);
    println!("  Match: {}", original_pred_hash == insert_witness_core.pred_update_path.leaf);
    
    // Create the insert witness for gadget
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof.clone(),
        new_leaf: insert_witness_core.new_leaf.clone(),
        updated_pred_leaf: insert_witness_core.updated_pred_leaf.clone(),
        new_leaf_path: insert_witness_core.new_leaf_path.clone(),
        pred_update_path: insert_witness_core.pred_update_path.clone(),
        height: insert_witness_core.height,
    };
    
    // Create constraint system
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Create the gadget with the computed new root
    let tree_params = TreeParams::new(insert_witness_core.height);
    let computed_new_root = insert_witness_core.compute_new_root(&tree_params);
    
    println!("\n--- Creating Gadget ---");
    println!("Using computed new root: {:?}", computed_new_root);
    println!("Actual new root: {:?}", nft_root_new);
    
    let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(nft_root_old))?;
    let nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(nft_root_new))?;
    
    // Create the insert gadget
    let insert_gadget = SimtInsertVar {
        old_root: nft_root_old_var.clone(),
        new_root: FpVar::new_witness(cs.clone(), || Ok(computed_new_root))?,
        target: FpVar::new_witness(cs.clone(), || Ok(insert_witness.target))?,
        range_proof: RangePathVar::new_witness(
            cs.clone(), 
            || Ok(insert_witness.range_proof.clone())
        )?,
        new_leaf: SortedLeafVar::new_witness(
            cs.clone(), 
            || Ok(insert_witness.new_leaf.clone())
        )?,
        updated_pred_leaf: SortedLeafVar::new_witness(
            cs.clone(), 
            || Ok(insert_witness.updated_pred_leaf.clone())
        )?,
        new_leaf_path: MerklePathVar::new_witness(
            cs.clone(), 
            || Ok(insert_witness.new_leaf_path.clone())
        )?,
        pred_update_path: MerklePathVar::new_witness(
            cs.clone(), 
            || Ok(insert_witness.pred_update_path.clone())
        )?,
        height: insert_witness.height,
    };
    
    println!("\n--- Verifying Individual Components ---");
    
    // Test just the structural update verification
    let cs2 = ConstraintSystem::<F>::new_ref();
    
    // Recreate just the relevant variables
    let old_root_var = FpVar::new_input(cs2.clone(), || Ok(nft_root_old))?;
    let new_root_var = FpVar::new_witness(cs2.clone(), || Ok(computed_new_root))?;
    
    let range_proof_var = RangePathVar::new_witness(
        cs2.clone(), 
        || Ok(insert_witness_core.range_proof.clone())
    )?;
    
    let new_leaf_var = SortedLeafVar::new_witness(
        cs2.clone(), 
        || Ok(insert_witness_core.new_leaf.clone())
    )?;
    
    let new_leaf_path_var = MerklePathVar::new_witness(
        cs2.clone(), 
        || Ok(insert_witness_core.new_leaf_path.clone())
    )?;
    
    let pred_update_path_var = MerklePathVar::new_witness(
        cs2.clone(), 
        || Ok(insert_witness_core.pred_update_path.clone())
    )?;
    
    // Manually test the problematic constraint
    println!("\nTesting pred_path_leaf_matches constraint:");
    let pred_leaf_hash_var = range_proof_var.low_leaf.hash()?;
    let pred_path_leaf_matches = pred_update_path_var.leaf.is_eq(&pred_leaf_hash_var)?;
    pred_path_leaf_matches.enforce_equal(&Boolean::TRUE)?;
    
    if cs2.is_satisfied().unwrap() {
        println!("✅ Constraint satisfied when tested in isolation!");
    } else if let Ok(Some(unsat)) = cs2.which_is_unsatisfied() {
        println!("❌ Constraint {} unsatisfied even in isolation!", unsat);
        
        // Debug: check the actual values
        println!("\nDebug values:");
        if let Ok(pred_hash_value) = pred_leaf_hash_var.value() {
            println!("  pred_leaf_hash_var value: {:?}", pred_hash_value);
        }
        if let Ok(path_leaf_value) = pred_update_path_var.leaf.value() {
            println!("  pred_update_path.leaf value: {:?}", path_leaf_value);
        }
    }
    
    // Now test the full gadget
    println!("\n--- Testing Full Gadget ---");
    insert_gadget.enforce()?;
    
    println!("\nTotal constraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ Constraint {} unsatisfied!", unsat);
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
    
    Ok(())
}