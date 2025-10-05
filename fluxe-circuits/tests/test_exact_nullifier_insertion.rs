use ark_bn254::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_insert::{SortedInsertWitness, SimtInsertVar};
use fluxe_circuits::gadgets::sorted_tree::{RangePathVar, SortedLeafVar};
use fluxe_circuits::gadgets::MerklePathVar;
use fluxe_circuits::utils::ec_helpers::compute_owner_address_circuit_compatible;
use fluxe_core::{
    Note,
    merkle::{SortedTree, TreeParams},
    crypto::{PedersenParams, PedersenCommitment, PedersenRandomness},
};

#[test]
fn test_exact_nullifier_insertion() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Exact Nullifier Insertion ===\n");
    
    // Create a sorted tree and insert sentinel
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    
    // Generate the exact same nullifier as test_simple_working
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let nk = F::from(456u64);
    
    // Create the same note
    let params = PedersenParams::setup_value_commitment();
    let value_in = 100u64;
    let randomness_in = F::from(42u64);
    let v_comm_in = PedersenCommitment::commit(&params, value_in, &PedersenRandomness { r: randomness_in });
    
    let psi_bytes = [7u8; 32];
    let mut note_in = Note::new(1, v_comm_in, owner_addr, psi_bytes, 1);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.lineage_hash = F::from(1u64);
    note_in.memo_hash = F::from(0u64);
    
    let nf = note_in.nullifier(&nk);
    
    println!("Nullifier: {:?}", nf);
    
    // Get the tree state before insertion
    let nft_root_old = nft_tree.root();
    println!("Old root: {:?}", nft_root_old);
    
    // Get the witness for insertion
    let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    println!("New root: {:?}", nft_root_new);
    
    // Convert to circuit witness
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    // Compute what the new root should be according to the witness
    let tree_params = TreeParams::new(insert_witness.height);
    let computed_new_root = insert_witness.compute_new_root(&tree_params);
    println!("Computed new root from witness: {:?}", computed_new_root);
    
    // Verify they match
    assert_eq!(nft_root_new, computed_new_root, "New root mismatch!");
    
    // Debug the witness details
    println!("\nWitness details:");
    println!("  new_leaf_path.leaf_index: {}", insert_witness.new_leaf_path.leaf_index);
    println!("  new_leaf_path.leaf: {:?}", insert_witness.new_leaf_path.leaf);
    println!("  new_leaf.hash(): {:?}", insert_witness.new_leaf.hash());
    println!("  pred_update_path.leaf_index: {}", insert_witness.pred_update_path.leaf_index);
    println!("  pred_update_path.leaf: {:?}", insert_witness.pred_update_path.leaf);
    println!("  range_proof.low_leaf.hash(): {:?}", insert_witness.range_proof.low_leaf.hash());
    
    // Now create the circuit
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("\nCreating circuit gadget...");
    
    // Create the gadget
    let insert_gadget = SimtInsertVar {
        old_root: FpVar::new_input(cs.clone(), || Ok(nft_root_old))?,
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
    
    println!("Initial constraints: {}", cs.num_constraints());
    
    // Verify the gadget
    let is_valid = insert_gadget.verify()?;
    println!("After verify: {} constraints", cs.num_constraints());
    
    // Enforce it
    is_valid.enforce_equal(&Boolean::TRUE)?;
    
    println!("After enforce: {} constraints", cs.num_constraints());
    println!("Total constraints: {}", cs.num_constraints());
    
    // Check satisfaction
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ Unsatisfied constraint: {}", unsat);
            
            // Debug: Try to understand what values are in the gadget
            println!("\nDebug values from gadget:");
            println!("  old_root: {:?}", insert_gadget.old_root.value().unwrap());
            println!("  new_root: {:?}", insert_gadget.new_root.value().unwrap());
            
            // Check path computation
            let computed_old = insert_gadget.pred_update_path.compute_root().unwrap();
            println!("  pred_update_path.compute_root(): {:?}", computed_old.value().unwrap());
            
            let computed_new = insert_gadget.new_leaf_path.compute_root().unwrap();
            println!("  new_leaf_path.compute_root(): {:?}", computed_new.value().unwrap());
            
            // Check the leaf values
            println!("\nLeaf checks:");
            println!("  pred_update_path.leaf: {:?}", insert_gadget.pred_update_path.leaf.value().unwrap());
            println!("  range_proof.low_leaf.hash(): {:?}", insert_gadget.range_proof.low_leaf.hash().unwrap().value().unwrap());
            println!("  new_leaf_path.leaf: {:?}", insert_gadget.new_leaf_path.leaf.value().unwrap());
            println!("  new_leaf.hash(): {:?}", insert_gadget.new_leaf.hash().unwrap().value().unwrap());
            
            // Check path heights and indices
            println!("\nPath details:");
            println!("  height: {}", insert_gadget.height);
            println!("  pred_update_path.leaf_index: {:?}", insert_gadget.pred_update_path.leaf_index.value().unwrap());
            println!("  pred_update_path.siblings.len(): {}", insert_gadget.pred_update_path.siblings.len());
            println!("  new_leaf_path.leaf_index: {:?}", insert_gadget.new_leaf_path.leaf_index.value().unwrap());
            println!("  new_leaf_path.siblings.len(): {}", insert_gadget.new_leaf_path.siblings.len());
            
            // Check first sibling
            println!("\nFirst siblings (should be each other):");
            println!("  pred_update_path.siblings[0]: {:?}", insert_gadget.pred_update_path.siblings[0].value().unwrap());
            println!("  new_leaf_path.siblings[0]: {:?}", insert_gadget.new_leaf_path.siblings[0].value().unwrap());
            
            // Check comparison values
            println!("\nComparison values:");
            println!("  target: {:?}", insert_gadget.target.value().unwrap());
            println!("  range_proof.low_leaf.key: {:?}", insert_gadget.range_proof.low_leaf.key.value().unwrap());
            
            panic!("Test failed at constraint {}", unsat);
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
    
    Ok(())
}