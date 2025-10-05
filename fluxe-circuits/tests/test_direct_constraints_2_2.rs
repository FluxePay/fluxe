use ark_bn254::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_std::rand::thread_rng;

// Import the exact same setup functions as the benchmark
#[path = "../benches/common/mod.rs"]
mod common;

use common::create_transfer_circuit;

#[test]
fn test_transfer_2_1_constraints() {
    println!("Testing transfer 2-1 constraint generation...");
    let mut rng = thread_rng();
    
    let transfer_circuit = create_transfer_circuit(&mut rng, 2, 1);
    
    println!("Generated transfer 2-1 circuit");
    
    // Try to generate constraints directly
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("Generating constraints...");
    let result = transfer_circuit.generate_constraints(cs.clone());
    
    if let Err(e) = result {
        panic!("Constraint generation failed: {:?}", e);
    }
    
    println!("Total constraints: {}", cs.num_constraints());
    
    // Check satisfaction
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
            println!("Total constraints: {}", cs.num_constraints());
            panic!("Constraints not satisfied!");
        }
        panic!("Constraints not satisfied!");
    } else {
        println!("✅ All constraints satisfied!");
    }
}

#[test]
fn test_transfer_2_2_constraints() {
    println!("Testing transfer 2-2 constraint generation...");
    let mut rng = thread_rng();
    
    let transfer_circuit = create_transfer_circuit(&mut rng, 2, 2);
    
    println!("Generated transfer 2-2 circuit");
    
    // Try to generate constraints directly
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("Generating constraints...");
    let result = transfer_circuit.generate_constraints(cs.clone());
    
    if let Err(e) = result {
        panic!("Constraint generation failed: {:?}", e);
    }
    
    println!("Total constraints: {}", cs.num_constraints());
    
    // Check satisfaction
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
            println!("Total constraints: {}", cs.num_constraints());
            panic!("Constraints not satisfied!");
        }
        panic!("Constraints not satisfied!");
    } else {
        println!("✅ All constraints satisfied!");
    }
}