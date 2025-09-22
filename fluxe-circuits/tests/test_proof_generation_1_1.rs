use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, PreparedVerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;

// Import the exact same setup functions as the benchmark
#[path = "../benches/common/mod.rs"]
mod common;

use common::create_transfer_circuit;

#[test]
fn test_1_1_proof_generation() {
    println!("\n=== Testing 1-1 transfer proof generation ===\n");
    let mut rng = thread_rng();
    
    // Create circuit for setup
    println!("Creating setup circuit...");
    let setup_circuit = create_transfer_circuit(&mut rng, 1, 1);
    
    println!("Running circuit setup...");
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        setup_circuit, &mut rng
    ).expect("Setup should work");
    
    println!("Setup successful!");
    println!("Proving key size: {} elements", pk.a_query.len());
    
    // Create circuit for proving
    println!("\nCreating proving circuit...");
    let proving_circuit = create_transfer_circuit(&mut rng, 1, 1);
    
    println!("Generating proof...");
    let proof = Groth16::<Bls12_381>::prove(
        &pk, proving_circuit, &mut rng
    ).expect("Proof generation should work");
    
    println!("Proof generated successfully!");
    
    // Verify proof
    println!("\nPreparing verification...");
    let pvk = PreparedVerifyingKey::from(vk.clone());
    
    // Get public inputs
    let verification_circuit = create_transfer_circuit(&mut rng, 1, 1);
    let mut public_inputs = vec![
        verification_circuit.cmt_root_old,
        verification_circuit.cmt_root_new,
        verification_circuit.nft_root_old,
        verification_circuit.nft_root_new,
        verification_circuit.sanctions_root,
        verification_circuit.pool_rules_root,
    ];
    
    // Add nullifiers
    for nf in &verification_circuit.nf_list {
        public_inputs.push(*nf);
    }
    
    // Add output commitments
    for cm in &verification_circuit.cm_list {
        public_inputs.push(*cm);
    }
    
    // Add fee
    public_inputs.push(ark_bls12_381::Fr::from(10u64)); // Fee is 10
    
    println!("Verifying proof with {} public inputs...", public_inputs.len());
    let valid = Groth16::<Bls12_381>::verify_with_processed_vk(
        &pvk, &public_inputs, &proof
    ).expect("Verification should complete");
    
    if valid {
        println!("✅ Proof verification successful!");
    } else {
        panic!("❌ Proof verification failed!");
    }
}