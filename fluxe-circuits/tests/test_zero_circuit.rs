use ark_bn254::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_ff::Zero;

use fluxe_circuits::transfer::TransferCircuit;
use fluxe_core::{
    data_structures::Note,
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, SortedTree},
    types::Amount,
};
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};

#[test]
fn test_transfer_with_zero_values() {
    println!("\n=== Testing transfer circuit with zero/dummy values ===\n");
    
    // This simulates what might happen during Groth16 setup
    // where the circuit needs to be satisfied with arbitrary values
    
    let params = PedersenParams::setup_value_commitment();
    
    // Create minimal trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64));
    
    // Create a note with ZERO value but non-zero randomness to avoid infinity point
    let value_in = 0u64; // Zero value
    let randomness_in = F::from(42u64); // Non-zero randomness to avoid infinity point
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );
    
    // Use parameters that work with our sorted insert fix
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    
    let nk = F::from(456u64);
    let psi_bytes = [7u8; 32]; // Use the psi that works
    
    let mut note_in = Note::new(1, v_comm_in, owner_addr, psi_bytes, 1);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.lineage_hash = F::from(1u64);
    note_in.memo_hash = F::from(0u64);
    
    let cm_in = note_in.commitment();
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();
    let cmt_root_old = cmt_tree.root();
    
    let nf = note_in.nullifier(&nk);
    let nft_root_old = nft_tree.root();
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    
    let mut witness_tree = nft_tree.clone();
    let insert_witness_core = witness_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = witness_tree.root();
    
    // Output with zero value but non-zero randomness
    let value_out = 0u64;
    let randomness_out = F::from(1000u64); // Non-zero to avoid infinity point
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let recipient_sk = F::from(2000u64); // Different from sender
    let recipient_addr = compute_owner_address_circuit_compatible(recipient_sk);
    
    // Compute correct lineage hash even for zero values
    use fluxe_core::crypto::poseidon_hash;
    let expected_lineage = poseidon_hash(&[F::from(1u64), F::zero()]); // Hash([parent_lineage, context])
    
    let mut note_out = Note::new(1, v_comm_out, recipient_addr, [0u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = expected_lineage;
    note_out.memo_hash = F::from(0u64);
    
    let cm_out = note_out.commitment();
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();
    
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    let circuit = TransferCircuit {
        notes_in: vec![note_in],
        values_in: vec![value_in],
        value_randomness_in: vec![randomness_in],
        notes_out: vec![note_out],
        values_out: vec![value_out],
        value_randomness_out: vec![randomness_out],
        nks: vec![nk],
        owner_sks: vec![owner_sk],
        owner_pks: vec![(pk_x, pk_y)],
        cm_paths: vec![cm_path],
        nf_nonmembership_proofs: vec![Some(nm_proof.clone())],
        sanctions_nm_proofs_in: vec![None],
        sanctions_nm_proofs_out: vec![None],
        cmt_paths_out: vec![],
        nf_nonmembership: vec![Some(nm_proof)],
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out: vec![append_witness],
        nf_insert_witnesses: vec![insert_witness],
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        sanctions_root: F::from(1u64),
        pool_rules_root: F::from(1u64),
        nf_list: vec![nf],
        cm_list: vec![cm_out],
        fee: Amount::from(0u128), // Zero fee
    };
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    let result = circuit.generate_constraints(cs.clone());
    
    if let Err(e) = result {
        panic!("Constraint generation failed with zero values: {:?}", e);
    }
    
    println!("Total constraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            panic!("❌ First unsatisfied constraint with zero values: {}", unsat);
        }
    } else {
        println!("✅ All constraints satisfied with zero values!");
    }
}

#[test]
fn test_transfer_with_one_values() {
    println!("\n=== Testing transfer circuit with all-one values ===\n");
    
    let params = PedersenParams::setup_value_commitment();
    
    // Create minimal trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64));
    
    // Create a note with value=1
    let value_in = 1u64;
    let randomness_in = F::from(1u64);
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );
    
    let owner_sk = F::from(1u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    
    let nk = F::from(1u64);
    let psi_bytes = [1u8; 32];
    
    let mut note_in = Note::new(1, v_comm_in, owner_addr, psi_bytes, 1);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.lineage_hash = F::from(1u64);
    note_in.memo_hash = F::from(1u64);
    
    let cm_in = note_in.commitment();
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();
    let cmt_root_old = cmt_tree.root();
    
    let nf = note_in.nullifier(&nk);
    let nft_root_old = nft_tree.root();
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    
    let mut witness_tree = nft_tree.clone();
    let insert_witness_core = witness_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = witness_tree.root();
    
    // Output with value=1, fee=0 (to balance)
    let value_out = 1u64;
    let randomness_out = F::from(1u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let recipient_addr = F::from(2u64);
    
    use fluxe_core::crypto::poseidon_hash;
    let expected_lineage = poseidon_hash(&[F::from(1u64), F::from(0u64)]);
    
    let mut note_out = Note::new(1, v_comm_out, recipient_addr, [1u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = expected_lineage;
    note_out.memo_hash = F::from(1u64);
    
    let cm_out = note_out.commitment();
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();
    
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    let circuit = TransferCircuit {
        notes_in: vec![note_in],
        values_in: vec![value_in],
        value_randomness_in: vec![randomness_in],
        notes_out: vec![note_out],
        values_out: vec![value_out],
        value_randomness_out: vec![randomness_out],
        nks: vec![nk],
        owner_sks: vec![owner_sk],
        owner_pks: vec![(pk_x, pk_y)],
        cm_paths: vec![cm_path],
        nf_nonmembership_proofs: vec![Some(nm_proof.clone())],
        sanctions_nm_proofs_in: vec![None],
        sanctions_nm_proofs_out: vec![None],
        cmt_paths_out: vec![],
        nf_nonmembership: vec![Some(nm_proof)],
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out: vec![append_witness],
        nf_insert_witnesses: vec![insert_witness],
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        sanctions_root: F::from(1u64),
        pool_rules_root: F::from(1u64),
        nf_list: vec![nf],
        cm_list: vec![cm_out],
        fee: Amount::from(0u128),
    };
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    let result = circuit.generate_constraints(cs.clone());
    
    if let Err(e) = result {
        panic!("Constraint generation failed with one values: {:?}", e);
    }
    
    println!("Total constraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            panic!("❌ First unsatisfied constraint with one values: {}", unsat);
        }
    } else {
        println!("✅ All constraints satisfied with one values!");
    }
}