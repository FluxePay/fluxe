use ark_bn254::Fr as F;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

use fluxe_circuits::gadgets::sorted_tree::RangePathVar;
use fluxe_circuits::gadgets::note::NoteVar;
use fluxe_circuits::gadgets::range_proof::RangeProofGadget;
use fluxe_circuits::utils::ec_helpers::compute_owner_address_circuit_compatible;
use fluxe_core::{
    Note, 
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, SortedTree},
};

#[test]
fn test_constraint_7995_exact_scenario() {
    println!("\n=== Testing exact constraint 7995 scenario ===\n");
    
    let params = PedersenParams::setup_value_commitment();
    
    // Create trees exactly as in the full transfer
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    
    // Create two input notes with same owner
    let value_in = 500u64;
    let randomness_in = F::from(42u64);
    let v_comm = PedersenCommitment::commit(&params, value_in, &PedersenRandomness { r: randomness_in });
    
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
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
    
    println!("\nnm_proof1 target: {:?}", nm_proof1.target);
    println!("nm_proof1 low_leaf.key: {:?}", nm_proof1.low_leaf.key);
    println!("nm_proof1 low_leaf.next_key: {:?}", nm_proof1.low_leaf.next_key);
    
    println!("\nnm_proof2 target: {:?}", nm_proof2.target);
    println!("nm_proof2 low_leaf.key: {:?}", nm_proof2.low_leaf.key);
    println!("nm_proof2 low_leaf.next_key: {:?}", nm_proof2.low_leaf.next_key);
    
    // Create output note
    let value_out = 990u64;
    let randomness_out = F::from(1000u64);
    let v_comm_out = PedersenCommitment::commit(&params, value_out, &PedersenRandomness { r: randomness_out });
    
    let recipient_addr = F::from(789u64);
    
    let mut note_out = Note::new(1, v_comm_out, recipient_addr, [0u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = F::from(1u64);
    note_out.memo_hash = F::from(0u64);
    
    // Now replicate the exact circuit constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("\n=== Starting circuit constraint generation ===\n");
    
    // Create public inputs (as in the transfer circuit)
    let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(nft_tree.root())).unwrap();
    println!("After NFT root input: {}", cs.num_constraints());
    
    // Create nullifier variables (as public inputs)
    let nf1_var = FpVar::new_input(cs.clone(), || Ok(nf1)).unwrap();
    let nf2_var = FpVar::new_input(cs.clone(), || Ok(nf2)).unwrap();
    println!("After nullifier inputs: {}", cs.num_constraints());
    
    // Witness input notes
    let _note1_var = NoteVar::new_witness(cs.clone(), || Ok(note1.clone()), value_in, &randomness_in).unwrap();
    let _note2_var = NoteVar::new_witness(cs.clone(), || Ok(note2.clone()), value_in, &randomness_in).unwrap();
    println!("After input note witnesses: {}", cs.num_constraints());
    
    // Witness output note
    let note_out_var = NoteVar::new_witness(cs.clone(), || Ok(note_out.clone()), value_out, &randomness_out).unwrap();
    println!("After output note witness: {}", cs.num_constraints());
    
    // Simulate what happens before constraint 7995
    // This would include EC auth, value conservation, etc.
    // Let's jump to the range proof part
    
    println!("\n=== Range proof for output value ===");
    let before_range = cs.num_constraints();
    RangeProofGadget::prove_range_bits(cs.clone(), &note_out_var.value, 64).unwrap();
    let after_range = cs.num_constraints();
    println!("Range proof added {} constraints (from {} to {})", 
             after_range - before_range, before_range, after_range);
    
    // Now the critical part - nullifier non-membership verification
    println!("\n=== Nullifier non-membership verification ===");
    
    // First nullifier
    println!("\nProcessing first nullifier...");
    let before_nm1 = cs.num_constraints();
    
    let nm_proof1_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof1.clone())).unwrap();
    println!("  After creating RangePathVar: {}", cs.num_constraints());
    
    nm_proof1_var.target.enforce_equal(&nf1_var).unwrap();
    println!("  After enforcing target equality: {}", cs.num_constraints());
    
    nm_proof1_var.enforce_valid(&nft_root_old_var).unwrap();
    let after_nm1 = cs.num_constraints();
    println!("  After enforce_valid: {}", after_nm1);
    println!("  First nullifier verification added {} constraints", after_nm1 - before_nm1);
    
    // Second nullifier - THIS IS WHERE WE EXPECT FAILURE AROUND 7995
    println!("\nProcessing second nullifier...");
    println!("Current constraint count: {}", cs.num_constraints());
    
    let before_nm2 = cs.num_constraints();
    
    // Create the witness - this should work
    let nm_proof2_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof2.clone()));
    match nm_proof2_var {
        Ok(proof_var) => {
            println!("  ✅ RangePathVar created successfully");
            println!("  After creating RangePathVar: {}", cs.num_constraints());
            
            // Try to enforce target equality
            let result = proof_var.target.enforce_equal(&nf2_var);
            match result {
                Ok(_) => {
                    println!("  ✅ Target equality enforced");
                    println!("  After enforcing target equality: {}", cs.num_constraints());
                    
                    // Try enforce_valid - this might be where it fails
                    let valid_result = proof_var.enforce_valid(&nft_root_old_var);
                    match valid_result {
                        Ok(_) => {
                            println!("  ✅ enforce_valid succeeded");
                            println!("  After enforce_valid: {}", cs.num_constraints());
                        }
                        Err(e) => {
                            println!("  ❌ enforce_valid failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("  ❌ Target equality failed: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("  ❌ Failed to create RangePathVar: {:?}", e);
        }
    }
    
    println!("\nFinal constraint count: {}", cs.num_constraints());
    
    // Check satisfaction
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("\n❌ First unsatisfied constraint: {}", unsat);
            
            // Try to identify which section it's in
            let unsat_num = unsat.parse::<usize>().unwrap_or(0);
            if unsat_num <= after_range {
                println!("  Failure is BEFORE or IN range proof");
            } else if unsat_num <= after_nm1 {
                println!("  Failure is in FIRST nullifier verification");
            } else {
                println!("  Failure is in SECOND nullifier verification");
                println!("  Constraint {} is {} constraints into second nullifier", 
                         unsat_num, unsat_num - after_nm1);
            }
        }
    } else {
        println!("\n✅ All constraints satisfied!");
    }
}