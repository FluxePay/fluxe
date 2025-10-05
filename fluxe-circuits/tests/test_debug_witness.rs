use ark_bn254::Fr as F;
use fluxe_core::{
    merkle::SortedTree,
    crypto::poseidon_hash,
};

#[test]
fn test_debug_witness_creation() {
    println!("\n=== Debugging Witness Creation ===\n");
    
    // Create a simple sorted tree
    let mut nft_tree = SortedTree::new(16);
    
    // Insert a nullifier
    let nf = F::from(12345u64);
    
    // Get the witness
    let witness = nft_tree.insert_with_witness(nf).unwrap();
    
    println!("Target: {:?}", witness.target);
    println!("\nRange proof (non-membership):");
    println!("  low_leaf.key: {:?}", witness.range_proof.low_leaf.key);
    println!("  low_leaf.next_key: {:?}", witness.range_proof.low_leaf.next_key); 
    println!("  low_leaf.next_index: {}", witness.range_proof.low_leaf.next_index);
    
    // Compute what the hash should be
    let expected_hash = poseidon_hash(&[witness.range_proof.low_leaf.key,
        witness.range_proof.low_leaf.next_key,
        F::from(witness.range_proof.low_leaf.next_index as u64)]);
    println!("\nExpected hash of low_leaf: {:?}", expected_hash);
    
    println!("\nPred update path:");
    println!("  leaf field: {:?}", witness.pred_update_path.leaf);
    println!("  leaf_index: {}", witness.pred_update_path.leaf_index);
    
    if witness.pred_update_path.leaf == expected_hash {
        println!("\n✅ pred_update_path.leaf matches expected hash!");
    } else {
        println!("\n❌ MISMATCH!");
        println!("  Expected: {:?}", expected_hash);
        println!("  Got: {:?}", witness.pred_update_path.leaf);
    }
    
    // Also check the range proof path
    println!("\nRange proof low_path:");
    println!("  leaf field: {:?}", witness.range_proof.low_path.leaf);
    println!("  leaf_index: {}", witness.range_proof.low_path.leaf_index);
    
    if witness.range_proof.low_path.leaf == expected_hash {
        println!("✅ range_proof.low_path.leaf also matches!");
    } else {
        println!("❌ range_proof.low_path.leaf doesn't match!");
    }
    
    // They should be the same path since they're both for the predecessor
    if witness.pred_update_path.leaf == witness.range_proof.low_path.leaf {
        println!("\n✅ Both paths have the same leaf field (as expected)");
    } else {
        println!("\n❌ WARNING: pred_update_path and range_proof.low_path have different leaf fields!");
    }
}