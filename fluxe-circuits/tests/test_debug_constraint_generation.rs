use ark_bn254::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_insert::{SortedInsertWitness, SimtInsertVar};
use fluxe_circuits::gadgets::sorted_tree::{RangePathVar, SortedLeafVar};
use fluxe_circuits::gadgets::MerklePathVar;
use fluxe_core::merkle::{SortedTree, TreeParams};

#[test]
fn test_debug_constraint_generation() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Debug Constraint Generation ===\n");
    
    // Create a sorted tree
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
    
    // Add many dummy constraints to push our constraint number higher
    println!("Adding dummy constraints to reach constraint 54000...");
    
    // We need to add about 54000 constraints before our test
    // Each Boolean::TRUE enforcement adds 1 constraint
    for i in 0..54000 {
        if i % 10000 == 0 {
            println!("  Added {} constraints", i);
        }
        let dummy = Boolean::new_witness(cs.clone(), || Ok(true))?;
        dummy.enforce_equal(&Boolean::TRUE)?;
    }
    
    println!("Current constraints: {}", cs.num_constraints());
    
    // Now create our gadget - this should push us past constraint 54388
    println!("\nCreating sorted insert gadget...");
    
    let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(nft_root_old))?;
    
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
    
    println!("Constraints before enforce: {}", cs.num_constraints());
    
    // Track constraints as we add them
    let mut last_count = cs.num_constraints();
    
    // Manually call verify to see where constraints are added
    let is_valid = insert_gadget.verify()?;
    
    let new_count = cs.num_constraints();
    println!("After verify(): {} constraints added (total: {})", new_count - last_count, new_count);
    
    // Check if we're near constraint 54388
    if new_count >= 54388 && last_count < 54388 {
        println!("⚠️  Constraint 54388 was added during verify()!");
    }
    
    last_count = new_count;
    
    // Now enforce
    is_valid.enforce_equal(&Boolean::TRUE)?;
    
    let final_count = cs.num_constraints();
    println!("After enforce_equal: {} constraints added (total: {})", final_count - last_count, final_count);
    
    // Check if we're near constraint 54388
    if final_count >= 54388 && last_count < 54388 {
        println!("⚠️  Constraint 54388 was added during enforce_equal!");
    }
    
    println!("\nTotal constraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ Unsatisfied constraint: {}", unsat);
            
            if unsat == "54388" {
                println!("Found it! Constraint 54388 is unsatisfied!");
            }
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
    
    Ok(())
}