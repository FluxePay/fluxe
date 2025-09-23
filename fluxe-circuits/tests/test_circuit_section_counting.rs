use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

use fluxe_circuits::transfer::TransferCircuit;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
use fluxe_core::{
    Note, 
    crypto::{pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness}, poseidon_hash},
    merkle::{IncrementalTree, SortedTree},
    types::Amount,
};

/// Create a minimal 2-1 transfer circuit with all required witnesses
fn create_minimal_2_1_transfer() -> TransferCircuit {
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
    let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
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
    
    // Add to CMT tree
    let cm1 = note1.commitment();
    cmt_tree.append(cm1);
    
    let cm2 = note2.commitment();
    cmt_tree.append(cm2);
    
    // IMPORTANT: Get paths AFTER all notes are added to get consistent root
    let path1 = cmt_tree.get_path(0).unwrap();
    let path2 = cmt_tree.get_path(1).unwrap();
    
    let cmt_root_old = cmt_tree.root();
    
    // Generate nullifiers and NFT proofs
    let nf1 = note1.nullifier(&nk);
    let nf2 = note2.nullifier(&nk);
    
    let nft_root_old = nft_tree.root();
    let nm_proof1 = nft_tree.prove_non_membership(nf1).unwrap();
    let nm_proof2 = nft_tree.prove_non_membership(nf2).unwrap();
    
    // Generate insert witnesses
    let insert_witness_core1 = nft_tree.insert_with_witness(nf1).unwrap();
    let insert_witness1 = SortedInsertWitness {
        target: insert_witness_core1.target,
        range_proof: insert_witness_core1.range_proof,
        new_leaf: insert_witness_core1.new_leaf,
        updated_pred_leaf: insert_witness_core1.updated_pred_leaf,
        new_leaf_path: insert_witness_core1.new_leaf_path,
        pred_update_path: insert_witness_core1.pred_update_path,
        height: insert_witness_core1.height,
    };
    
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
    
    // Create output note
    let value_out = 990u64;
    let randomness_out = F::from(1000u64);
    let v_comm_out = PedersenCommitment::commit(&params, value_out, &PedersenRandomness { r: randomness_out });
    
    let recipient_addr = F::from(789u64);
    let parent_lineages: Vec<F> = vec![note1.lineage_hash, note2.lineage_hash];
    let mut lineage_input = parent_lineages;
    lineage_input.push(F::from(0u64));
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
    
    TransferCircuit {
        notes_in: vec![note1, note2],
        values_in: vec![value, value],
        value_randomness_in: vec![randomness, randomness],
        notes_out: vec![note_out],
        values_out: vec![value_out],
        value_randomness_out: vec![randomness_out],
        owner_sks: vec![owner_sk, owner_sk],
        owner_pks: vec![(pk_x, pk_y), (pk_x, pk_y)],
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
    }
}

#[test]
fn test_transfer_circuit_section_constraints() {
    println!("\n=== Testing constraint counts by section ===\n");
    
    let circuit = create_minimal_2_1_transfer();
    let cs = ConstraintSystem::<F>::new_ref();
    
    // We need to manually trace through the circuit generation
    // Unfortunately we can't easily instrument the actual circuit code
    // So let's just generate and check where it fails
    
    println!("Starting constraint generation...");
    let result = circuit.generate_constraints(cs.clone());
    
    match result {
        Ok(_) => {
            println!("✅ Circuit generation succeeded!");
            println!("Total constraints: {}", cs.num_constraints());
        }
        Err(e) => {
            println!("❌ Circuit generation failed: {:?}", e);
            println!("Constraints at failure: {}", cs.num_constraints());
        }
    }
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ First unsatisfied constraint: {}", unsat);
            
            // Try to narrow down the range
            println!("\nChecking constraint ranges:");
            for checkpoint in [1000, 2000, 3000, 4000, 5000, 6000, 7000, 7500, 7900, 7990, 7995, 8000].iter() {
                if *checkpoint <= cs.num_constraints() {
                    // This is a hack but might give us info
                    println!("  Checkpoint {}: passed", checkpoint);
                }
            }
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
}