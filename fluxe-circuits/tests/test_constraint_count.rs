use ark_bn254::Fr as F;
use ark_relations::r1cs::{ConstraintSystem};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_insert::{SortedInsertWitness, SimtInsertVar};
use fluxe_circuits::gadgets::sorted_tree::{RangePathVar, SortedLeafVar};
use fluxe_circuits::gadgets::MerklePathVar;
use fluxe_core::merkle::{SortedTree, TreeParams};

#[test]
fn test_constraint_count() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Counting Constraints ===\n");
    
    // Create a simple sorted tree
    let mut nft_tree = SortedTree::new(16);
    
    // Insert a nullifier
    let nf = F::from(12345u64);
    
    // Get witnesses
    let nft_root_old = nft_tree.root();
    let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    
    // Convert witness
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    // Create constraint system
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Track constraint counts
    let count0 = cs.num_constraints();
    println!("Initial constraints: {}", count0);
    
    // Create root variables
    let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(nft_root_old))?;
    let count1 = cs.num_constraints();
    println!("After old root input: {} (+{})", count1, count1 - count0);
    
    let _nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(nft_root_new))?;
    let count2 = cs.num_constraints();
    println!("After new root input: {} (+{})", count2, count2 - count1);
    
    // Create the gadget
    let tree_params = TreeParams::new(insert_witness.height);
    let new_root_computed = insert_witness.compute_new_root(&tree_params);
    
    let insert_gadget = SimtInsertVar {
        old_root: nft_root_old_var.clone(),
        new_root: FpVar::new_witness(cs.clone(), || Ok(new_root_computed))?,
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
    
    let count3 = cs.num_constraints();
    println!("After creating gadget witnesses: {} (+{})", count3, count3 - count2);
    
    // Now enforce
    insert_gadget.enforce()?;
    
    let count4 = cs.num_constraints();
    println!("After enforce: {} (+{})", count4, count4 - count3);
    
    println!("\nTotal constraints: {}", count4);
    
    // Check which constraint would be 54388
    let target_constraint = 54388;
    if count4 >= target_constraint {
        let percentage = (target_constraint as f64 / count4 as f64) * 100.0;
        println!("Constraint {} would be at {:.1}% through", target_constraint, percentage);
        
        // In a 1-1 transfer with ~70k constraints, 54388 is at ~77%
        // In our test with ~29k constraints, that would be around constraint 22330
        let equivalent = (0.77 * count4 as f64) as usize;
        println!("Equivalent position in this test: constraint {}", equivalent);
    }
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("\n❌ Unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("\n✅ All constraints satisfied!");
    }
    
    Ok(())
}