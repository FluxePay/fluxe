use ark_bls12_381::Fr as F;
use fluxe_core::{
    merkle::SortedTree,
    crypto::poseidon_hash,
};

#[test]
fn test_debug_path_leaf_field() {
    println!("\n=== Debugging Path Leaf Field ===\n");
    
    // Create a simple sorted tree
    let mut nft_tree = SortedTree::new(16);
    
    // Insert a nullifier
    let nf = F::from(12345u64);
    
    // Get non-membership proof BEFORE insertion
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    
    // Check the predecessor leaf
    println!("Predecessor leaf from range proof:");
    println!("  key: {:?}", nm_proof.low_leaf.key);
    println!("  next_key: {:?}", nm_proof.low_leaf.next_key);
    println!("  next_index: {}", nm_proof.low_leaf.next_index);
    
    // Compute the hash of the predecessor leaf
    let pred_leaf_hash = poseidon_hash(&vec![
        nm_proof.low_leaf.key,
        nm_proof.low_leaf.next_key,
        F::from(nm_proof.low_leaf.next_index as u64),
    ]);
    println!("\nComputed predecessor leaf hash: {:?}", pred_leaf_hash);
    
    // Check the path
    println!("\nPredecessor path (low_path):");
    println!("  leaf field: {:?}", nm_proof.low_path.leaf);
    println!("  leaf_index: {}", nm_proof.low_path.leaf_index);
    println!("  siblings count: {}", nm_proof.low_path.siblings.len());
    
    // Verify they match
    if nm_proof.low_path.leaf == pred_leaf_hash {
        println!("\n✅ Path leaf field matches computed hash");
    } else {
        println!("\n❌ Path leaf field does NOT match computed hash");
    }
    
    // Now get insert witness
    let insert_witness = nft_tree.insert_with_witness(nf).unwrap();
    
    println!("\n--- Insert Witness Paths ---");
    
    // Check pred_update_path
    println!("\nPredecessor update path:");
    println!("  leaf field: {:?}", insert_witness.pred_update_path.leaf);
    println!("  leaf_index: {}", insert_witness.pred_update_path.leaf_index);
    
    // The pred_update_path.leaf should be the hash of the ORIGINAL predecessor
    let original_pred_hash = poseidon_hash(&vec![
        insert_witness.range_proof.low_leaf.key,
        insert_witness.range_proof.low_leaf.next_key,
        F::from(insert_witness.range_proof.low_leaf.next_index as u64),
    ]);
    println!("\nOriginal predecessor hash: {:?}", original_pred_hash);
    
    if insert_witness.pred_update_path.leaf == original_pred_hash {
        println!("✅ pred_update_path.leaf matches original predecessor hash");
    } else {
        println!("❌ pred_update_path.leaf does NOT match original predecessor hash");
        println!("This is likely causing constraint 54388!");
    }
    
    // Check new_leaf_path
    println!("\nNew leaf path:");
    println!("  leaf field: {:?}", insert_witness.new_leaf_path.leaf);
    println!("  leaf_index: {}", insert_witness.new_leaf_path.leaf_index);
    
    // The new_leaf_path.leaf should be the hash of the new leaf
    let new_leaf_hash = poseidon_hash(&vec![
        insert_witness.new_leaf.key,
        insert_witness.new_leaf.next_key,
        F::from(insert_witness.new_leaf.next_index as u64),
    ]);
    println!("\nNew leaf hash: {:?}", new_leaf_hash);
    
    if insert_witness.new_leaf_path.leaf == new_leaf_hash {
        println!("✅ new_leaf_path.leaf matches new leaf hash");
    } else {
        println!("❌ new_leaf_path.leaf does NOT match new leaf hash");
    }
}