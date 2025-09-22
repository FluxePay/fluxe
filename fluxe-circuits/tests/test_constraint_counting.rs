use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_r1cs_std::prelude::*;

use fluxe_circuits::transfer::TransferCircuit;
use fluxe_circuits::gadgets::note::NoteVar;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_core::{
    Note, 
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, SortedTree},
    types::Amount,
};
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;

#[test]
fn test_constraint_counting_for_2_inputs() {
    println!("\n=== Constraint counting for 2-input transfer ===\n");
    
    // Create a minimal 2-input transfer circuit
    let params = PedersenParams::setup_value_commitment();
    
    // Create trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    
    // Create two input notes with same owner
    let value = 500u64;
    let randomness = F::from(42u64);
    let v_comm = PedersenCommitment::commit(&params, value, &PedersenRandomness { r: randomness });
    
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let nk = F::from(456u64);
    
    // First note
    let mut note1 = Note::new(1, v_comm.clone(), owner_addr, [7u8; 32], 1);
    note1.compliance_hash = F::from(1u64);
    note1.callbacks_hash = F::from(1u64);
    note1.lineage_hash = F::from(1u64);
    note1.memo_hash = F::from(0u64);
    
    // Second note
    let mut note2 = Note::new(1, v_comm, owner_addr, [8u8; 32], 1);
    note2.compliance_hash = F::from(1u64);
    note2.callbacks_hash = F::from(1u64);
    note2.lineage_hash = F::from(1u64);
    note2.memo_hash = F::from(0u64);
    
    // Test just the note witnessing
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("Initial constraints: {}", cs.num_constraints());
    
    // Witness first note
    let note1_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note1.clone()),
        value,
        &randomness,
    ).unwrap();
    println!("After witnessing note1: {}", cs.num_constraints());
    
    // Witness second note
    let note2_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note2.clone()),
        value,
        &randomness,
    ).unwrap();
    println!("After witnessing note2: {}", cs.num_constraints());
    
    // Try computing commitments
    let _cm1 = note1_var.commitment().unwrap();
    println!("After computing cm1: {}", cs.num_constraints());
    
    let _cm2 = note2_var.commitment().unwrap();
    println!("After computing cm2: {}", cs.num_constraints());
    
    // Test value operations
    use ark_r1cs_std::fields::fp::FpVar;
    let sum = &note1_var.value + &note2_var.value;
    println!("After summing values: {}", cs.num_constraints());
    
    // Test equality constraint
    let expected_sum = FpVar::new_witness(cs.clone(), || Ok(F::from(1000u64))).unwrap();
    sum.enforce_equal(&expected_sum).unwrap();
    println!("After enforcing sum equality: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ Basic operations satisfied!");
    }
}

#[test]
fn test_ec_auth_constraint_count() {
    println!("\n=== EC Auth constraint counting ===\n");
    
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Test EC operations for two inputs
    let owner_sk1 = F::from(123u64);
    let owner_sk2 = F::from(123u64); // Same owner
    
    use ark_r1cs_std::fields::fp::FpVar;
    use fluxe_circuits::gadgets::auth::AuthGadget;
    
    println!("Initial constraints: {}", cs.num_constraints());
    
    // First owner
    let sk1_var = FpVar::new_witness(cs.clone(), || Ok(owner_sk1)).unwrap();
    println!("After witnessing sk1: {}", cs.num_constraints());
    
    let (pk1_x, pk1_y) = AuthGadget::scalar_mult_generator(cs.clone(), &sk1_var).unwrap();
    println!("After first EC scalar mult: {}", cs.num_constraints());
    
    let addr1 = AuthGadget::compute_owner_address_from_fq(cs.clone(), &pk1_x, &pk1_y).unwrap();
    println!("After computing first address: {}", cs.num_constraints());
    
    // Second owner (same value)
    let sk2_var = FpVar::new_witness(cs.clone(), || Ok(owner_sk2)).unwrap();
    println!("After witnessing sk2: {}", cs.num_constraints());
    
    let (pk2_x, pk2_y) = AuthGadget::scalar_mult_generator(cs.clone(), &sk2_var).unwrap();
    println!("After second EC scalar mult: {}", cs.num_constraints());
    
    let addr2 = AuthGadget::compute_owner_address_from_fq(cs.clone(), &pk2_x, &pk2_y).unwrap();
    println!("After computing second address: {}", cs.num_constraints());
    
    // Check if they're equal (they should be)
    addr1.enforce_equal(&addr2).unwrap();
    println!("After enforcing address equality: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ EC auth operations satisfied!");
    }
}