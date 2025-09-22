use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;

// Import the exact same setup functions as the benchmark
#[path = "../benches/common/mod.rs"]
mod common;

use common::{create_transfer_circuit, create_burn_circuit};

#[test]
fn test_transfer_1_1_setup() {
    println!("Testing transfer 1-1 setup (same as benchmark)...");
    let mut rng = thread_rng();
    
    let transfer_circuit = create_transfer_circuit(&mut rng, 1, 1);
    
    println!("Generated transfer 1-1 circuit, attempting setup...");
    let result = Groth16::<Bls12_381>::circuit_specific_setup(transfer_circuit, &mut rng);
    
    match result {
        Ok((pk, vk)) => {
            println!("✅ Setup succeeded!");
            println!("Proving key size: {} elements", pk.a_query.len());
            println!("Verifying key size: {} elements", vk.gamma_abc_g1.len());
        }
        Err(e) => {
            panic!("❌ Setup failed: {:?}", e);
        }
    }
}

#[test]
fn test_transfer_2_2_setup() {
    println!("Testing transfer 2-2 setup (exact benchmark config)...");
    let mut rng = thread_rng();
    
    let transfer_circuit = create_transfer_circuit(&mut rng, 2, 2);
    
    println!("Generated transfer 2-2 circuit, attempting setup...");
    let result = Groth16::<Bls12_381>::circuit_specific_setup(transfer_circuit, &mut rng);
    
    match result {
        Ok((pk, vk)) => {
            println!("✅ Setup succeeded!");
            println!("Proving key size: {} elements", pk.a_query.len());
            println!("Verifying key size: {} elements", vk.gamma_abc_g1.len());
        }
        Err(e) => {
            panic!("❌ Setup failed: {:?}", e);
        }
    }
}

#[test]
fn test_burn_setup() {
    println!("Testing burn setup...");
    let mut rng = thread_rng();
    
    let burn_circuit = create_burn_circuit(&mut rng);
    
    println!("Generated burn circuit, attempting setup...");
    let result = Groth16::<Bls12_381>::circuit_specific_setup(burn_circuit, &mut rng);
    
    match result {
        Ok((pk, vk)) => {
            println!("✅ Setup succeeded!");
            println!("Proving key size: {} elements", pk.a_query.len());
            println!("Verifying key size: {} elements", vk.gamma_abc_g1.len());
        }
        Err(e) => {
            panic!("❌ Setup failed: {:?}", e);
        }
    }
}