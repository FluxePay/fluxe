use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_std::rand::thread_rng;

// Import the exact same setup functions as the benchmark
#[path = "../benches/common/mod.rs"]
mod common;

use common::create_transfer_circuit;

#[test]
fn test_pinpoint_2_1_failure() {
    println!("\n=== Pinpointing 2-1 transfer failure ===\n");
    let mut rng = thread_rng();
    let circuit = create_transfer_circuit(&mut rng, 2, 1);
    
    // Create a custom constraint system to track progress
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Manually replicate the transfer circuit constraint generation with checkpoints
    
    println!("Starting constraint generation...");
    let mut last_count = 0;
    
    // Public inputs
    println!("\n1. Creating public inputs...");
    let cmt_root_old_var = FpVar::new_input(cs.clone(), || Ok(circuit.cmt_root_old)).unwrap();
    let cmt_root_new_var = FpVar::new_input(cs.clone(), || Ok(circuit.cmt_root_new)).unwrap();
    let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(circuit.nft_root_old)).unwrap();
    let nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(circuit.nft_root_new)).unwrap();
    let sanctions_root_var = FpVar::new_input(cs.clone(), || Ok(circuit.sanctions_root)).unwrap();
    let pool_rules_root_var = FpVar::new_input(cs.clone(), || Ok(circuit.pool_rules_root)).unwrap();
    
    // Nullifiers as public inputs
    for nf in &circuit.nf_list {
        let _ = FpVar::new_input(cs.clone(), || Ok(*nf)).unwrap();
    }
    
    // Output commitments as public inputs
    for cm in &circuit.cm_list {
        let _ = FpVar::new_input(cs.clone(), || Ok(*cm)).unwrap();
    }
    
    // Fee as public input
    let fee_var = FpVar::new_input(cs.clone(), || Ok(circuit.fee.to_field())).unwrap();
    
    let count = cs.num_constraints();
    println!("   After public inputs: {} constraints (+{})", count, count - last_count);
    last_count = count;
    
    // Create note witnesses
    println!("\n2. Creating note witnesses...");
    use fluxe_circuits::gadgets::note::NoteVar;
    
    let mut notes_in_var = Vec::new();
    for i in 0..circuit.notes_in.len() {
        println!("   Creating input note {} witness...", i);
        let note_var = NoteVar::new_witness(
            cs.clone(),
            || Ok(circuit.notes_in[i].clone()),
            circuit.values_in[i],
            &circuit.value_randomness_in[i],
        ).unwrap();
        notes_in_var.push(note_var);
        
        let count = cs.num_constraints();
        println!("     After input note {}: {} constraints (+{})", i, count, count - last_count);
        
        if count > 7995 {
            println!("\n❌ Passed constraint 7995 while creating input note {}!", i);
            if !cs.is_satisfied().unwrap() {
                if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                    println!("   First unsatisfied: {}", unsat);
                }
            }
            return;
        }
        last_count = count;
    }
    
    let mut notes_out_var = Vec::new();
    for i in 0..circuit.notes_out.len() {
        println!("   Creating output note {} witness...", i);
        let note_var = NoteVar::new_witness(
            cs.clone(),
            || Ok(circuit.notes_out[i].clone()),
            circuit.values_out[i],
            &circuit.value_randomness_out[i],
        ).unwrap();
        notes_out_var.push(note_var);
        
        let count = cs.num_constraints();
        println!("     After output note {}: {} constraints (+{})", i, count, count - last_count);
        
        if count > 7995 {
            println!("\n❌ Passed constraint 7995 while creating output note {}!", i);
            if !cs.is_satisfied().unwrap() {
                if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                    println!("   First unsatisfied: {}", unsat);
                }
            }
            return;
        }
        last_count = count;
    }
    
    // Continue with the rest of the circuit to find where 7995 occurs
    println!("\nContinuing to find constraint 7995...");
    
    let result = circuit.generate_constraints(cs.clone());
    if let Err(e) = result {
        println!("Constraint generation failed: {:?}", e);
    }
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("First unsatisfied constraint: {}", unsat);
        }
    }
}