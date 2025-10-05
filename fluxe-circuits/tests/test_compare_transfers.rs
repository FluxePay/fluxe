use ark_bn254::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_std::rand::thread_rng;

// Import the exact same setup functions as the benchmark
#[path = "../benches/common/mod.rs"]
mod common;

use common::create_transfer_circuit;

#[test]
fn test_compare_1_1_vs_2_1() {
    println!("\n=== Comparing 1-1 vs 2-1 transfers ===\n");
    let mut rng = thread_rng();
    
    // Test 1-1 (known working)
    println!("Testing 1-1 transfer:");
    let circuit_1_1 = create_transfer_circuit(&mut rng, 1, 1);
    let cs_1_1 = ConstraintSystem::<F>::new_ref();
    let result_1_1 = circuit_1_1.generate_constraints(cs_1_1.clone());
    
    if let Err(e) = result_1_1 {
        println!("  1-1 failed: {:?}", e);
    } else {
        println!("  1-1 constraints: {}", cs_1_1.num_constraints());
        if !cs_1_1.is_satisfied().unwrap() {
            if let Ok(Some(unsat)) = cs_1_1.which_is_unsatisfied() {
                println!("  1-1 unsatisfied: {}", unsat);
            }
        } else {
            println!("  1-1 ✅ satisfied");
        }
    }
    
    // Test 2-1 (two inputs, one output)
    println!("\nTesting 2-1 transfer:");
    let circuit_2_1 = create_transfer_circuit(&mut rng, 2, 1);
    let cs_2_1 = ConstraintSystem::<F>::new_ref();
    let result_2_1 = circuit_2_1.generate_constraints(cs_2_1.clone());
    
    if let Err(e) = result_2_1 {
        println!("  2-1 failed: {:?}", e);
    } else {
        println!("  2-1 constraints: {}", cs_2_1.num_constraints());
        if !cs_2_1.is_satisfied().unwrap() {
            if let Ok(Some(unsat)) = cs_2_1.which_is_unsatisfied() {
                println!("  2-1 unsatisfied: {}", unsat);
            }
        } else {
            println!("  2-1 ✅ satisfied");
        }
    }
    
    // Test 1-2 (one input, two outputs)
    println!("\nTesting 1-2 transfer:");
    let circuit_1_2 = create_transfer_circuit(&mut rng, 1, 2);
    let cs_1_2 = ConstraintSystem::<F>::new_ref();
    let result_1_2 = circuit_1_2.generate_constraints(cs_1_2.clone());
    
    if let Err(e) = result_1_2 {
        println!("  1-2 failed: {:?}", e);
    } else {
        println!("  1-2 constraints: {}", cs_1_2.num_constraints());
        if !cs_1_2.is_satisfied().unwrap() {
            if let Ok(Some(unsat)) = cs_1_2.which_is_unsatisfied() {
                println!("  1-2 unsatisfied: {}", unsat);
            }
        } else {
            println!("  1-2 ✅ satisfied");
        }
    }
}

#[test]
fn test_debug_2_1_values() {
    println!("\n=== Debug 2-1 transfer values ===\n");
    let mut rng = thread_rng();
    let circuit = create_transfer_circuit(&mut rng, 2, 1);
    
    // Print key values
    println!("Input values: {:?}", circuit.values_in);
    println!("Output values: {:?}", circuit.values_out);
    println!("Fee: {:?}", circuit.fee);
    
    let total_in: u64 = circuit.values_in.iter().sum();
    let total_out: u64 = circuit.values_out.iter().sum();
    let fee_amount = 10u64; // We know the fee is 10 from the setup
    
    println!("\nTotal in: {}", total_in);
    println!("Total out: {}", total_out);
    println!("Fee: {}", fee_amount);
    println!("Balance: {} == {} + {} ? {}", 
        total_in, total_out, fee_amount, 
        total_in == total_out + fee_amount);
    
    // Check lineage hashes
    println!("\nInput lineage hashes:");
    for (i, note) in circuit.notes_in.iter().enumerate() {
        println!("  Input {}: {:?}", i, note.lineage_hash);
    }
    
    println!("\nOutput lineage hashes:");
    for (i, note) in circuit.notes_out.iter().enumerate() {
        println!("  Output {}: {:?}", i, note.lineage_hash);
    }
}