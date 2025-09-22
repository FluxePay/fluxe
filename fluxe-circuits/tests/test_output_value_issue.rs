use ark_bls12_381::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;

use fluxe_circuits::gadgets::note::NoteVar;
use fluxe_core::{
    Note,
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
};

#[test]
fn test_output_note_value_witnessing() {
    println!("\n=== Testing output note value witnessing ===\n");
    
    let cs = ConstraintSystem::<F>::new_ref();
    let params = PedersenParams::setup_value_commitment();
    
    // Create output note
    let value_out = 990u64;
    let randomness_out = F::from(1000u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let recipient_addr = F::from(789u64);
    
    let mut note_out = Note::new(1, v_comm_out, recipient_addr, [0u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = F::from(1u64);
    note_out.memo_hash = F::from(0u64);
    
    println!("Constraints before witnessing: {}", cs.num_constraints());
    
    // Witness the output note
    let note_out_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note_out.clone()),
        value_out,
        &randomness_out,
    ).unwrap();
    
    println!("Constraints after witnessing: {}", cs.num_constraints());
    
    // Check the value field
    println!("Note value field is a witness variable");
    
    // Try range proof on the value
    use fluxe_circuits::gadgets::range_proof::RangeProofGadget;
    
    let before_range = cs.num_constraints();
    RangeProofGadget::prove_range_bits(cs.clone(), &note_out_var.value, 64).unwrap();
    let after_range = cs.num_constraints();
    
    println!("Range proof added {} constraints", after_range - before_range);
    println!("Total constraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
            
            // Check if it's in the range proof
            let unsat_num = unsat.parse::<usize>().unwrap_or(0);
            if unsat_num > before_range && unsat_num <= after_range {
                println!("⚠️ Failure is in the range proof!");
            }
        }
    } else {
        println!("✅ Output note value witnessing and range proof satisfied!");
    }
}

#[test]
fn test_two_inputs_one_output_values() {
    println!("\n=== Testing 2-input 1-output value flow ===\n");
    
    let cs = ConstraintSystem::<F>::new_ref();
    let params = PedersenParams::setup_value_commitment();
    
    // Create two input notes
    let value_in = 500u64;
    let randomness_in = F::from(42u64);
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );
    
    let owner_addr = F::from(123u64);
    
    let mut note1 = Note::new(1, v_comm_in.clone(), owner_addr, [7u8; 32], 1);
    note1.compliance_hash = F::from(1u64);
    note1.callbacks_hash = F::from(1u64);
    note1.lineage_hash = F::from(1u64);
    note1.memo_hash = F::from(0u64);
    
    let mut note2 = Note::new(1, v_comm_in, owner_addr, [8u8; 32], 1);
    note2.compliance_hash = F::from(1u64);
    note2.callbacks_hash = F::from(1u64);
    note2.lineage_hash = F::from(1u64);
    note2.memo_hash = F::from(0u64);
    
    // Witness input notes
    let note1_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note1.clone()),
        value_in,
        &randomness_in,
    ).unwrap();
    
    let note2_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note2.clone()),
        value_in,
        &randomness_in,
    ).unwrap();
    
    // Create output note
    let value_out = 990u64;
    let randomness_out = F::from(1000u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let mut note_out = Note::new(1, v_comm_out, F::from(789u64), [0u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = F::from(1u64);
    note_out.memo_hash = F::from(0u64);
    
    let note_out_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note_out.clone()),
        value_out,
        &randomness_out,
    ).unwrap();
    
    println!("Constraints after witnessing all notes: {}", cs.num_constraints());
    
    // Check value conservation
    use ark_r1cs_std::fields::fp::FpVar;
    
    let sum_in = &note1_var.value + &note2_var.value;
    let fee_var = FpVar::new_witness(cs.clone(), || Ok(F::from(10u64))).unwrap();
    let sum_out = &note_out_var.value + &fee_var;
    
    sum_in.enforce_equal(&sum_out).unwrap();
    
    println!("Constraints after value conservation: {}", cs.num_constraints());
    
    // Now add range proof
    use fluxe_circuits::gadgets::range_proof::RangeProofGadget;
    
    let before_range = cs.num_constraints();
    RangeProofGadget::prove_range_bits(cs.clone(), &note_out_var.value, 64).unwrap();
    let after_range = cs.num_constraints();
    
    println!("Constraints after range proof: {}", after_range);
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ All satisfied!");
    }
}