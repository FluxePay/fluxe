use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_insert::{SortedInsertWitness, SimtInsertVar};
use fluxe_circuits::gadgets::sorted_tree::{RangePathVar, SortedLeafVar};
use fluxe_circuits::gadgets::MerklePathVar;
use fluxe_core::merkle::SortedTree;

#[test]
fn test_manual_insert_gadget() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Manual Insert Gadget Test ===\n");
    
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
    
    // Compute what the new root should be
    let tree_params = fluxe_core::merkle::TreeParams::new(insert_witness_core.height);
    let computed_new_root = insert_witness_core.compute_new_root(&tree_params);
    println!("Computed new root: {:?}", computed_new_root);
    println!("Match: {}", computed_new_root == nft_root_new);
    
    // Create the insert witness
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
    
    // Create the gadget exactly as the transfer circuit does
    let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(nft_root_old))?;
    let nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(nft_root_new))?;
    
    // This mimics what happens in the transfer circuit
    let current_nft = nft_root_old_var.clone();
    
    let insert_gadget = SimtInsertVar {
        old_root: current_nft.clone(),
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
    
    // Verify the insertion
    insert_gadget.enforce()?;
    
    // Check if the new root matches what we expect
    let current_nft_new = insert_gadget.new_root.clone();
    current_nft_new.enforce_equal(&nft_root_new_var)?;
    
    println!("\nConstraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ Unsatisfied constraint: {}", unsat);
            
            // Debug: Try to understand what's failing
            // Let's check individual components
            println!("\n--- Checking components separately ---");
            
            // Test just the enforce without the final equality check
            let cs2 = ConstraintSystem::<F>::new_ref();
            let nft_root_old_var2 = FpVar::new_input(cs2.clone(), || Ok(nft_root_old))?;
            
            let insert_gadget2 = SimtInsertVar {
                old_root: nft_root_old_var2.clone(),
                new_root: FpVar::new_witness(cs2.clone(), || Ok(nft_root_new))?, // Use actual new root
                target: FpVar::new_witness(cs2.clone(), || Ok(insert_witness.target))?,
                range_proof: RangePathVar::new_witness(
                    cs2.clone(), 
                    || Ok(insert_witness.range_proof.clone())
                )?,
                new_leaf: SortedLeafVar::new_witness(
                    cs2.clone(), 
                    || Ok(insert_witness.new_leaf.clone())
                )?,
                updated_pred_leaf: SortedLeafVar::new_witness(
                    cs2.clone(), 
                    || Ok(insert_witness.updated_pred_leaf.clone())
                )?,
                new_leaf_path: MerklePathVar::new_witness(
                    cs2.clone(), 
                    || Ok(insert_witness.new_leaf_path.clone())
                )?,
                pred_update_path: MerklePathVar::new_witness(
                    cs2.clone(), 
                    || Ok(insert_witness.pred_update_path.clone())
                )?,
                height: insert_witness.height,
            };
            
            insert_gadget2.enforce()?;
            
            println!("Constraints with actual new root: {}", cs2.num_constraints());
            if cs2.is_satisfied().unwrap() {
                println!("✅ Works when using actual new root directly!");
                println!("The issue is that computed_new_root != actual new_root");
            } else {
                if let Ok(Some(unsat2)) = cs2.which_is_unsatisfied() {
                    println!("❌ Still fails with actual root: {}", unsat2);
                }
            }
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
    
    Ok(())
}