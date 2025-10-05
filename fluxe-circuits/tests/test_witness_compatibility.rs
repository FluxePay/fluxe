use ark_bn254::Fr as F;
use fluxe_core::merkle::SortedTree;
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness as CircuitWitness;
use fluxe_core::crypto::poseidon_hash;

#[test]
fn test_witness_compatibility() {
    println!("\n=== Testing Witness Compatibility ===\n");
    
    // Create a sorted tree
    let mut nft_tree = SortedTree::new(16);
    
    // Insert a nullifier
    let nf = F::from(12345u64);
    
    // Get the core witness
    let core_witness = nft_tree.insert_with_witness(nf).unwrap();
    
    // Check the core witness fields
    println!("Core witness:");
    println!("  target: {:?}", core_witness.target);
    println!("  height: {}", core_witness.height);
    
    // Check the range proof
    println!("\nRange proof (non-membership):");
    println!("  low_leaf.key: {:?}", core_witness.range_proof.low_leaf.key);
    println!("  low_leaf.next_key: {:?}", core_witness.range_proof.low_leaf.next_key);
    println!("  low_leaf.next_index: {}", core_witness.range_proof.low_leaf.next_index);
    
    // Check the paths
    println!("\nPred update path:");
    println!("  leaf: {:?}", core_witness.pred_update_path.leaf);
    println!("  leaf_index: {}", core_witness.pred_update_path.leaf_index);
    println!("  siblings: {}", core_witness.pred_update_path.siblings.len());
    
    println!("\nNew leaf path:");
    println!("  leaf: {:?}", core_witness.new_leaf_path.leaf);
    println!("  leaf_index: {}", core_witness.new_leaf_path.leaf_index);
    println!("  siblings: {}", core_witness.new_leaf_path.siblings.len());
    
    // Now convert to circuit witness (exactly as test_simple_working does)
    let circuit_witness = CircuitWitness {
        target: core_witness.target,
        range_proof: core_witness.range_proof.clone(),
        new_leaf: core_witness.new_leaf.clone(),
        updated_pred_leaf: core_witness.updated_pred_leaf.clone(),
        new_leaf_path: core_witness.new_leaf_path.clone(),
        pred_update_path: core_witness.pred_update_path.clone(),
        height: core_witness.height,
    };
    
    // Verify the conversion preserved everything
    println!("\n=== After Conversion ===");
    println!("Target match: {}", circuit_witness.target == core_witness.target);
    println!("Height match: {}", circuit_witness.height == core_witness.height);
    
    // Check if the pred_update_path.leaf matches the hash of range_proof.low_leaf
    let expected_hash = poseidon_hash(&[circuit_witness.range_proof.low_leaf.key,
        circuit_witness.range_proof.low_leaf.next_key,
        F::from(circuit_witness.range_proof.low_leaf.next_index as u64)]);
    
    println!("\n=== Critical Check ===");
    println!("Expected hash of low_leaf: {:?}", expected_hash);
    println!("Actual pred_update_path.leaf: {:?}", circuit_witness.pred_update_path.leaf);
    println!("Match: {}", expected_hash == circuit_witness.pred_update_path.leaf);
    
    if expected_hash != circuit_witness.pred_update_path.leaf {
        panic!("❌ WITNESS INCOMPATIBILITY: pred_update_path.leaf doesn't match hash of range_proof.low_leaf!");
    }
    
    println!("\n✅ Witness conversion is correct!");
}