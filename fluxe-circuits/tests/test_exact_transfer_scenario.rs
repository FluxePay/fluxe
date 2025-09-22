use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_insert::{SortedInsertWitness, SimtInsertVar};
use fluxe_circuits::gadgets::sorted_tree::{RangePathVar, SortedLeafVar};
use fluxe_circuits::gadgets::MerklePathVar;
use fluxe_core::merkle::{SortedTree, TreeParams};

#[test]
fn test_exact_transfer_scenario() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Exact Transfer Scenario ===\n");
    
    // Create a simple sorted tree - exactly like transfer circuit would
    let mut nft_tree = SortedTree::new(16);
    
    // Insert a nullifier
    let nf = F::from(12345u64);
    
    // Get witnesses
    let nft_root_old = nft_tree.root();
    let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    
    // Convert to fluxe_circuits version (like test_simple_working does)
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
    
    // Create variables exactly like the transfer circuit does
    let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(nft_root_old))?;
    let _nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(nft_root_new))?;
    
    // This mimics the transfer circuit flow
    let mut current_nft = nft_root_old_var.clone();
    
    // Create the gadget EXACTLY as the transfer circuit does
    let tree_params = TreeParams::new(insert_witness.height);
    let new_root_computed = insert_witness.compute_new_root(&tree_params);
    
    println!("Computed new root: {:?}", new_root_computed);
    println!("Actual new root: {:?}", nft_root_new);
    println!("Match: {}", new_root_computed == nft_root_new);
    
    let insert_gadget = SimtInsertVar {
        old_root: current_nft.clone(),
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
    
    // Verify the insertion
    insert_gadget.enforce()?;
    
    // Update current_nft like the transfer circuit would
    current_nft = insert_gadget.new_root.clone();
    
    println!("\nConstraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ Unsatisfied constraint: {}", unsat);
            
            // Debug the specific constraint
            if unsat == "54388" {
                println!("\n=== Debugging Constraint 54388 ===");
                
                // Try to understand what values are being compared
                let cs2 = ConstraintSystem::<F>::new_ref();
                
                // Recreate just the problematic part
                let range_proof_var = RangePathVar::new_witness(
                    cs2.clone(), 
                    || Ok(insert_witness.range_proof.clone())
                )?;
                
                let pred_update_path_var = MerklePathVar::new_witness(
                    cs2.clone(), 
                    || Ok(insert_witness.pred_update_path.clone())
                )?;
                
                let pred_leaf_hash = range_proof_var.low_leaf.hash()?;
                
                println!("Checking values:");
                if let Ok(hash_val) = pred_leaf_hash.value() {
                    println!("  Computed hash: {:?}", hash_val);
                }
                if let Ok(path_val) = pred_update_path_var.leaf.value() {
                    println!("  Path leaf: {:?}", path_val);
                }
                
                let matches = pred_update_path_var.leaf.is_eq(&pred_leaf_hash)?;
                matches.enforce_equal(&Boolean::TRUE)?;
                
                if cs2.is_satisfied().unwrap() {
                    println!("✅ Constraint satisfied in isolation!");
                } else {
                    println!("❌ Constraint fails even in isolation!");
                }
            }
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
    
    Ok(())
}