use ark_bn254::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_tree::RangePathVar;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_core::{
    Note, 
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, SortedTree},
};

#[test]
fn test_nullifier_nonmembership_witness_creation() {
    println!("\n=== Testing nullifier non-membership witness creation ===\n");
    
    // Create a sorted tree and add sentinel
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    
    // Create two nullifiers
    let nf1 = F::from(100u64);
    let nf2 = F::from(200u64);
    
    // Get non-membership proofs BEFORE insertion
    let nm_proof1 = nft_tree.prove_non_membership(nf1).unwrap();
    let nm_proof2 = nft_tree.prove_non_membership(nf2).unwrap();
    
    println!("nm_proof1 low_leaf key: {:?}", nm_proof1.low_leaf.key);
    println!("nm_proof1 low_leaf next_key: {:?}", nm_proof1.low_leaf.next_key);
    println!("nm_proof1 target: {:?}", nm_proof1.target);
    println!();
    println!("nm_proof2 low_leaf key: {:?}", nm_proof2.low_leaf.key);
    println!("nm_proof2 low_leaf next_key: {:?}", nm_proof2.low_leaf.next_key);
    println!("nm_proof2 target: {:?}", nm_proof2.target);
    
    // Now test witnessing these in a circuit
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("\nInitial constraints: {}", cs.num_constraints());
    
    // Witness first non-membership proof
    let nm_proof1_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof1.clone())).unwrap();
    println!("After first RangePathVar witness: {}", cs.num_constraints());
    
    // Witness second non-membership proof - THIS IS WHERE IT FAILS
    let nm_proof2_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof2.clone())).unwrap();
    println!("After second RangePathVar witness: {}", cs.num_constraints());
    
    // Create root variable
    let root_var = FpVar::new_input(cs.clone(), || Ok(nft_tree.root())).unwrap();
    println!("After root input: {}", cs.num_constraints());
    
    // Verify first proof
    let valid1 = nm_proof1_var.verify(&root_var).unwrap();
    valid1.enforce_equal(&Boolean::TRUE).unwrap();
    println!("After verifying first proof: {}", cs.num_constraints());
    
    // Verify second proof
    let valid2 = nm_proof2_var.verify(&root_var).unwrap();
    valid2.enforce_equal(&Boolean::TRUE).unwrap();
    println!("After verifying second proof: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
}

#[test]
fn test_two_nullifier_nonmembership_in_transfer_context() {
    println!("\n=== Testing two nullifier non-membership in transfer context ===\n");
    
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
    let (_pk_x, _pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    let nk = F::from(456u64);
    
    // Create notes
    let mut note1 = Note::new(1, v_comm.clone(), owner_addr, [7u8; 32], 1);
    note1.compliance_hash = F::from(1u64);
    note1.callbacks_hash = F::from(1u64);
    note1.lineage_hash = F::from(1u64);
    note1.memo_hash = F::from(0u64);
    
    let mut note2 = Note::new(1, v_comm, owner_addr, [8u8; 32], 1);
    note2.compliance_hash = F::from(1u64);
    note2.callbacks_hash = F::from(1u64);
    note2.lineage_hash = F::from(1u64);
    note2.memo_hash = F::from(0u64);
    
    // Add to CMT tree
    let cm1 = note1.commitment();
    cmt_tree.append(cm1);
    
    let cm2 = note2.commitment();
    cmt_tree.append(cm2);
    
    // Generate nullifiers
    let nf1 = note1.nullifier(&nk);
    let nf2 = note2.nullifier(&nk);
    
    println!("nf1: {:?}", nf1);
    println!("nf2: {:?}", nf2);
    
    // Get non-membership proofs BEFORE any insertions
    let nm_proof1 = nft_tree.prove_non_membership(nf1).unwrap();
    let nm_proof2 = nft_tree.prove_non_membership(nf2).unwrap();
    
    // Now test in circuit
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Create nullifier variables
    let nf1_var = FpVar::new_witness(cs.clone(), || Ok(nf1)).unwrap();
    let nf2_var = FpVar::new_witness(cs.clone(), || Ok(nf2)).unwrap();
    
    println!("\nConstraints after nullifier witnesses: {}", cs.num_constraints());
    
    // Create root variable
    let root_var = FpVar::new_input(cs.clone(), || Ok(nft_tree.root())).unwrap();
    println!("After root input: {}", cs.num_constraints());
    
    // Witness first non-membership proof
    println!("\nCreating first RangePathVar witness...");
    let nm_proof1_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof1.clone()));
    match nm_proof1_var {
        Ok(_) => println!("✅ First RangePathVar created successfully"),
        Err(e) => println!("❌ Error creating first RangePathVar: {:?}", e),
    }
    println!("Constraints: {}", cs.num_constraints());
    
    // Witness second non-membership proof - THIS IS WHERE IT MIGHT FAIL
    println!("\nCreating second RangePathVar witness...");
    let nm_proof2_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof2.clone()));
    match nm_proof2_var {
        Ok(_) => println!("✅ Second RangePathVar created successfully"),
        Err(e) => println!("❌ Error creating second RangePathVar: {:?}", e),
    }
    println!("Constraints: {}", cs.num_constraints());
    
    if let (Ok(nm1), Ok(nm2)) = (nm_proof1_var, nm_proof2_var) {
        // Verify the proofs match the nullifiers
        nm1.target.enforce_equal(&nf1_var).unwrap();
        nm2.target.enforce_equal(&nf2_var).unwrap();
        
        println!("After enforcing target equality: {}", cs.num_constraints());
        
        // Verify the proofs
        nm1.enforce_valid(&root_var).unwrap();
        println!("After enforcing first nm proof valid: {}", cs.num_constraints());
        
        nm2.enforce_valid(&root_var).unwrap();
        println!("After enforcing second nm proof valid: {}", cs.num_constraints());
    }
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
}