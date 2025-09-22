use ark_bls12_381::Fr as F;
use fluxe_core::crypto::poseidon_hash;
use std::str::FromStr;

#[test]
fn test_lineage_hash_computation() {
    println!("\n=== Testing lineage hash computation ===\n");
    
    // Test the lineage hash for 2-1 transfer
    // Two inputs with lineage_hash = 1 each
    // Output should have Hash([1, 1, 0])
    
    let input_lineage_1 = F::from(1u64);
    let input_lineage_2 = F::from(1u64);
    let context = F::from(0u64); // First output
    
    let lineage_input = vec![input_lineage_1, input_lineage_2, context];
    let computed_lineage = poseidon_hash(&lineage_input);
    
    println!("Input lineages: [1, 1]");
    println!("Context: 0");
    println!("Computed lineage: {:?}", computed_lineage);
    
    // Also test with single input for comparison
    let single_input = vec![F::from(1u64), F::from(0u64)];
    let single_lineage = poseidon_hash(&single_input);
    
    println!("\nFor comparison, single input:");
    println!("Input lineages: [1]");
    println!("Context: 0");
    println!("Computed lineage: {:?}", single_lineage);
    
    // Verify this matches what we saw in debug output
    let expected_from_debug = F::from_str("13023185322872331478523459779013149685728646315282703100040987207491170035623").unwrap();
    
    println!("\nFrom debug output: {:?}", expected_from_debug);
    println!("Match: {}", computed_lineage == expected_from_debug);
}