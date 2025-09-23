use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

use fluxe_circuits::transfer::TransferCircuit;
use fluxe_circuits::FluxeCircuit;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
use fluxe_core::{
    Note, 
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, SortedTree},
    types::Amount,
};

#[test]
fn test_minimal_2_input_circuit_parts() {
    println!("\n=== Testing 2-input circuit parts ===\n");
    
    use ark_relations::r1cs::ConstraintSystem;
    
    let params = PedersenParams::setup_value_commitment();
    
    // Create trees
    let cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    
    // Create notes with known values
    let value1 = 500u64;
    let value2 = 500u64;
    let randomness1 = F::from(42u64);
    let randomness2 = F::from(43u64); // Different randomness
    
    let v_comm1 = PedersenCommitment::commit(&params, value1, &PedersenRandomness { r: randomness1 });
    let v_comm2 = PedersenCommitment::commit(&params, value2, &PedersenRandomness { r: randomness2 });
    
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let nk = F::from(456u64);
    
    // Create two notes
    let mut note1 = Note::new(1, v_comm1, owner_addr, [7u8; 32], 1);
    note1.compliance_hash = F::from(1u64);
    note1.callbacks_hash = F::from(1u64);
    note1.lineage_hash = F::from(1u64);
    note1.memo_hash = F::from(0u64);
    
    let mut note2 = Note::new(1, v_comm2, owner_addr, [8u8; 32], 1);
    note2.compliance_hash = F::from(1u64);
    note2.callbacks_hash = F::from(1u64);  
    note2.lineage_hash = F::from(1u64);
    note2.memo_hash = F::from(0u64);
    
    // Test just commitment generation
    let cs = ConstraintSystem::<F>::new_ref();
    
    use fluxe_circuits::gadgets::note::NoteVar;
    use ark_r1cs_std::prelude::*;
    
    println!("Creating note witnesses...");
    let note1_var = NoteVar::new_witness(cs.clone(), || Ok(note1.clone()), value1, &randomness1).unwrap();
    println!("Constraints after note1: {}", cs.num_constraints());
    
    let note2_var = NoteVar::new_witness(cs.clone(), || Ok(note2.clone()), value2, &randomness2).unwrap();
    println!("Constraints after note2: {}", cs.num_constraints());
    
    // Test commitment computation
    let cm1_var = note1_var.commitment().unwrap();
    println!("Constraints after cm1 computation: {}", cs.num_constraints());
    
    let cm2_var = note2_var.commitment().unwrap();
    println!("Constraints after cm2 computation: {}", cs.num_constraints());
    
    // Test value sum
    let sum = &note1_var.value + &note2_var.value;
    println!("Constraints after sum: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint in simple test: {}", unsat);
        }
    } else {
        println!("✅ Simple 2-note test satisfied!");
    }
}

#[test]
fn test_debug_2_identical_inputs() {
    println!("\n=== Testing 2 identical inputs ===\n");
    
    let params = PedersenParams::setup_value_commitment();
    
    // Create trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    
    // Create TWO identical notes (except psi) with known working parameters
    let value = 500u64;
    let randomness = F::from(42u64);
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    // Try using different owner for second note to see if that helps
    let owner_sk1 = F::from(123u64);
    let owner_addr1 = compute_owner_address_circuit_compatible(owner_sk1);
    let (pk_x1, pk_y1) = get_pk_coords_circuit_compatible(owner_sk1);
    
    let owner_sk2 = F::from(124u64); // Different SK
    let owner_addr2 = compute_owner_address_circuit_compatible(owner_sk2);
    let (pk_x2, pk_y2) = get_pk_coords_circuit_compatible(owner_sk2);
    
    // Note: Using different owners for the two input notes
    println!("Owner 1 SK: {:?}", owner_sk1);
    println!("Owner 1 address: {:?}", owner_addr1);
    println!("Owner 1 public key: pk_x={:?}, pk_y={:?}", pk_x1, pk_y1);
    
    println!("Owner 2 SK: {:?}", owner_sk2);  
    println!("Owner 2 address: {:?}", owner_addr2);
    println!("Owner 2 public key: pk_x={:?}, pk_y={:?}", pk_x2, pk_y2);
    
    // Double-check the address computation
    use fluxe_core::crypto::poseidon_hash;
    let recomputed_addr1 = poseidon_hash(&[pk_x1, pk_y1]);
    println!("Recomputed address 1 from pk: {:?}", recomputed_addr1);
    assert_eq!(owner_addr1, recomputed_addr1, "Address 1 computation mismatch!");
    
    let recomputed_addr2 = poseidon_hash(&[pk_x2, pk_y2]);
    println!("Recomputed address 2 from pk: {:?}", recomputed_addr2);
    assert_eq!(owner_addr2, recomputed_addr2, "Address 2 computation mismatch!");
    let nk = F::from(456u64);
    
    // Create first input note
    let psi_bytes1 = [7u8; 32];
    // Use same owner for both to simplify debugging
    let mut note1 = Note::new(1, v_comm.clone(), owner_addr1, psi_bytes1, 1);
    note1.compliance_hash = F::from(1u64);
    note1.callbacks_hash = F::from(1u64);
    note1.lineage_hash = F::from(1u64);
    note1.memo_hash = F::from(0u64);
    
    // Create second input note with same owner and same v_comm
    let psi_bytes2 = [8u8; 32]; // Different psi
    let mut note2 = Note::new(1, v_comm, owner_addr1, psi_bytes2, 1);
    note2.compliance_hash = F::from(1u64);
    note2.callbacks_hash = F::from(1u64);
    note2.lineage_hash = F::from(1u64);
    note2.memo_hash = F::from(0u64);
    
    // Add to CMT tree
    let cm1 = note1.commitment();
    let index1 = cmt_tree.num_leaves();
    cmt_tree.append(cm1);
    
    let cm2 = note2.commitment();
    let index2 = cmt_tree.num_leaves();
    cmt_tree.append(cm2);
    
    // IMPORTANT: Get paths AFTER all notes are added to get consistent root
    let path1 = cmt_tree.get_path(index1).unwrap();
    let path2 = cmt_tree.get_path(index2).unwrap();
    
    let cmt_root_old = cmt_tree.root();
    
    println!("cm1: {:?}", cm1);
    println!("cm2: {:?}", cm2);
    println!("cmt_root_old: {:?}", cmt_root_old);
    println!("path1 leaf index: {}", path1.leaf_index);
    println!("path2 leaf index: {}", path2.leaf_index);
    
    // Compute nullifiers
    let nf1 = note1.nullifier(&nk);
    let nf2 = note2.nullifier(&nk);
    
    println!("nf1: {:?}", nf1);
    println!("nf2: {:?}", nf2);
    println!("Are nullifiers different? {}", nf1 != nf2);
    
    // Get non-membership proofs from original tree
    let nft_root_old = nft_tree.root();
    let nm_proof1 = nft_tree.prove_non_membership(nf1).unwrap();
    // CRITICAL: For the second nullifier, we need the non-membership proof
    // from the ORIGINAL tree state, not after the first insertion
    let nm_proof2 = nft_tree.prove_non_membership(nf2).unwrap();
    
    println!("\n=== Non-membership proofs ===");
    println!("NM1 target: {:?}", nm_proof1.target);
    println!("NM1 low_leaf key: {:?}", nm_proof1.low_leaf.key);
    println!("NM1 low_leaf next_key: {:?}", nm_proof1.low_leaf.next_key);
    println!("NM2 target: {:?}", nm_proof2.target);
    println!("NM2 low_leaf key: {:?}", nm_proof2.low_leaf.key);
    println!("NM2 low_leaf next_key: {:?}", nm_proof2.low_leaf.next_key);
    
    // Generate insert witnesses with proper chaining
    // First insertion
    println!("\n=== Tree state before first insertion ===");
    println!("Tree root: {:?}", nft_tree.root());
    let insert_witness_core1 = nft_tree.insert_with_witness(nf1).unwrap();
    println!("Tree root after first insert: {:?}", nft_tree.root());
    let insert_witness1 = SortedInsertWitness {
        target: insert_witness_core1.target,
        range_proof: insert_witness_core1.range_proof,
        new_leaf: insert_witness_core1.new_leaf,
        updated_pred_leaf: insert_witness_core1.updated_pred_leaf,
        new_leaf_path: insert_witness_core1.new_leaf_path,
        pred_update_path: insert_witness_core1.pred_update_path,
        height: insert_witness_core1.height,
    };
    let intermediate_root = nft_tree.root();
    
    println!("\n=== First insertion witness ===");
    println!("Target: {:?}", insert_witness1.target);
    println!("Range proof low_leaf key: {:?}", insert_witness1.range_proof.low_leaf.key);
    println!("Range proof low_leaf next_key: {:?}", insert_witness1.range_proof.low_leaf.next_key);
    println!("New leaf key: {:?}", insert_witness1.new_leaf.key);
    println!("New leaf next_key: {:?}", insert_witness1.new_leaf.next_key);
    println!("Updated pred leaf key: {:?}", insert_witness1.updated_pred_leaf.key);
    println!("Updated pred leaf next_key: {:?}", insert_witness1.updated_pred_leaf.next_key);
    println!("NFT root after first insertion: {:?}", intermediate_root);
    
    // Verify the witness computes the correct new root
    let tree_params = fluxe_core::merkle::TreeParams::new(insert_witness1.height);
    let computed_root1 = insert_witness1.compute_new_root(&tree_params);
    println!("First witness computed root: {:?}", computed_root1);
    assert_eq!(intermediate_root, computed_root1, "First witness doesn't compute correct root!");
    
    // Second insertion (tree already contains nf1)
    let insert_witness_core2 = nft_tree.insert_with_witness(nf2).unwrap();
    let insert_witness2 = SortedInsertWitness {
        target: insert_witness_core2.target,
        range_proof: insert_witness_core2.range_proof,
        new_leaf: insert_witness_core2.new_leaf,
        updated_pred_leaf: insert_witness_core2.updated_pred_leaf,
        new_leaf_path: insert_witness_core2.new_leaf_path,
        pred_update_path: insert_witness_core2.pred_update_path,
        height: insert_witness_core2.height,
    };
    
    let nft_root_new = nft_tree.root();
    
    println!("\n=== Second insertion witness ===");
    println!("Target: {:?}", insert_witness2.target);
    println!("Range proof low_leaf key: {:?}", insert_witness2.range_proof.low_leaf.key);
    println!("Range proof low_leaf next_key: {:?}", insert_witness2.range_proof.low_leaf.next_key);
    println!("New leaf key: {:?}", insert_witness2.new_leaf.key);
    println!("New leaf next_key: {:?}", insert_witness2.new_leaf.next_key);
    println!("Updated pred leaf key: {:?}", insert_witness2.updated_pred_leaf.key);
    println!("Updated pred leaf next_key: {:?}", insert_witness2.updated_pred_leaf.next_key);
    println!("NFT root after second insertion: {:?}", nft_root_new);
    
    // Verify the second witness computes the correct new root
    let computed_root2 = insert_witness2.compute_new_root(&tree_params);
    println!("Second witness computed root: {:?}", computed_root2);
    assert_eq!(nft_root_new, computed_root2, "Second witness doesn't compute correct root!");
    
    // CRITICAL: Verify the second insertion's range proof against the intermediate root
    println!("\n=== Verifying second insertion's range proof ===");
    let second_range_proof_valid = insert_witness2.range_proof.verify(&intermediate_root, &tree_params);
    println!("Second insertion's range_proof verifies against intermediate root: {}", second_range_proof_valid);
    if !second_range_proof_valid {
        println!("ERROR: Second insertion's range proof doesn't verify against intermediate root!");
        println!("This is the issue - the range proof was generated against a different tree state");
    }
    
    // Create single output with combined value
    let total_value_out = 1000u64 - 10u64; // Total minus fee
    let randomness_out = F::from(1000u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        total_value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let recipient_sk = F::from(2000u64);
    let recipient_addr = compute_owner_address_circuit_compatible(recipient_sk);
    
    // Compute lineage for output
    let parent_lineages = vec![note1.lineage_hash, note2.lineage_hash];
    let mut lineage_input = parent_lineages;
    lineage_input.push(F::from(0u64)); // context for first output
    let expected_lineage = poseidon_hash(&lineage_input);
    
    let mut note_out = Note::new(1, v_comm_out, recipient_addr, [0u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = expected_lineage;
    note_out.memo_hash = F::from(0u64);
    
    let cm_out = note_out.commitment();
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();
    
    // Debug: Check that the non-membership proofs are against the correct roots
    println!("\n=== Verifying witness consistency ===");
    
    // First NM proof should verify against original NFT root
    let tree_params = fluxe_core::merkle::TreeParams::new(16);
    let nm1_verified = nm_proof1.verify(&nft_root_old, &tree_params);
    println!("NM1 verifies against nft_root_old: {}", nm1_verified);
    
    // Second NM proof should also verify against original NFT root (both were generated before any insertions)
    let nm2_verified = nm_proof2.verify(&nft_root_old, &tree_params);
    println!("NM2 verifies against nft_root_old: {}", nm2_verified);
    
    // Check insertion witness roots
    println!("\n=== Checking insertion witness roots ===");
    println!("First insertion expects old_root: {:?}", nft_root_old);
    println!("First insertion produces new_root: {:?}", intermediate_root);
    println!("Second insertion expects old_root: {:?}", intermediate_root);
    println!("Second insertion produces new_root: {:?}", nft_root_new);
    
    // Debug: Print expected public inputs
    println!("\n=== Expected public inputs ===");
    println!("cmt_root_old: {:?}", cmt_root_old);
    println!("cmt_root_new: {:?}", cmt_root_new);
    println!("nft_root_old: {:?}", nft_root_old);
    println!("nft_root_new: {:?}", nft_root_new);
    println!("nf_list: {:?}", vec![nf1, nf2]);
    println!("cm_list: {:?}", vec![cm_out]);
    
    // Verify public inputs match what circuit expects
    let expected_public = vec![
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        F::from(999999u64), // sanctions_root
        F::from(888888u64), // pool_rules_root
        nf1,
        nf2,
        cm_out,
        F::from(10u128), // fee
    ];
    
    // Create circuit
    let circuit = TransferCircuit {
        notes_in: vec![note1, note2],
        values_in: vec![value, value],
        value_randomness_in: vec![randomness, randomness],
        notes_out: vec![note_out],
        values_out: vec![total_value_out],
        value_randomness_out: vec![randomness_out],
        owner_sks: vec![owner_sk1, owner_sk1], // Same owner for both
        owner_pks: vec![(pk_x1, pk_y1), (pk_x1, pk_y1)],
        nks: vec![nk, nk],
        cm_paths: vec![path1, path2],
        nf_nonmembership_proofs: vec![Some(nm_proof1.clone()), Some(nm_proof2.clone())],
        sanctions_nm_proofs_in: vec![None, None],
        sanctions_nm_proofs_out: vec![None],
        cmt_paths_out: vec![],
        nf_nonmembership: vec![Some(nm_proof1), Some(nm_proof2)],
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out: vec![append_witness],
        nf_insert_witnesses: vec![insert_witness1, insert_witness2],
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        sanctions_root: F::from(999999u64),
        pool_rules_root: F::from(888888u64),
        nf_list: vec![nf1, nf2],
        cm_list: vec![cm_out],
        fee: Amount::from(10u128),
    };
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Check public inputs
    let actual_public = circuit.public_inputs();
    println!("\n=== Public inputs comparison ===");
    println!("Expected {} public inputs, got {}", expected_public.len(), actual_public.len());
    
    for (i, (exp, act)) in expected_public.iter().zip(actual_public.iter()).enumerate() {
        if exp != act {
            println!("❌ Mismatch at index {}: expected {:?}, got {:?}", i, exp, act);
        }
    }
    
    println!("Generating constraints...");
    
    // First check how many constraints we have before generating
    println!("Constraints before generate_constraints: {}", cs.num_constraints());
    
    circuit.generate_constraints(cs.clone()).expect("Should generate constraints");
    
    println!("Total constraints: {}", cs.num_constraints());
    
    // Get more detailed information about the failing constraint
    if !cs.is_satisfied().unwrap() {
        println!("\n=== Constraint Debugging ===");
        
        // Try to isolate where the failure is by checking constraints at different points
        let check_points = vec![1000, 2000, 3000, 4000, 5000, 6000, 7000, 7500, 7900, 7990, 7995, 8000, 8100, 8200, 8251];
        
        for checkpoint in check_points {
            if checkpoint <= cs.num_constraints() {
                // This is a hack to check if constraints up to a certain point are satisfied
                // We'll check which constraint fails first
                if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                    if unsat.parse::<usize>().unwrap_or(999999) <= checkpoint {
                        println!("❌ First unsatisfied constraint: {} (before checkpoint {})", unsat, checkpoint);
                        break;
                    }
                }
            }
        }
        
        panic!("Constraints not satisfied!");
    }
    
    println!("✅ All constraints satisfied!");
}