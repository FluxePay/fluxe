/// Common utilities for benchmarks
use ark_bn254::Fr as F;
use ark_ff::{UniformRand, Zero};
use ark_std::rand::RngCore;

use fluxe_circuits::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
};
use fluxe_core::{
    data_structures::{Note, IngressReceipt, ExitReceipt, ComplianceState, ZkObject},
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    crypto::poseidon_hash,
    merkle::{MerklePath, IncrementalTree},
    types::*,
};

/// Create a simplified mint circuit for benchmarking
pub fn create_mint_circuit<R: RngCore>(rng: &mut R) -> MintCircuit {
    let params = PedersenParams::setup_value_commitment();
    let value = 1000u64;
    let randomness = F::rand(rng);
    
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    let note = Note::new(1, v_comm, F::rand(rng), [0u8; 32], 1);
    let ingress = IngressReceipt::new(1, Amount::from(value as u128), note.commitment(), 1);
    
    let mut cmt_tree = IncrementalTree::new(16);
    let mut ingress_tree = IncrementalTree::new(16);
    
    MintCircuit::new(
        vec![note],
        vec![value],
        vec![randomness],
        ingress,
        &mut cmt_tree,
        &mut ingress_tree,
    )
}

/// Create a simplified burn circuit for benchmarking
pub fn create_burn_circuit<R: RngCore>(rng: &mut R) -> BurnCircuit {
    use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
    use fluxe_core::merkle::SortedTree;
    use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
    
    let params = PedersenParams::setup_value_commitment();
    let value = 500u64;
    // Ensure randomness is never zero to avoid infinity point in commitment
    let mut randomness = F::rand(rng);
    if randomness == F::zero() {
        randomness = F::from(1u64);
    }
    
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    // Generate owner key pair and derive address using circuit-compatible method
    let owner_sk = F::rand(rng);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (owner_pk_x, owner_pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    
    // Generate nullifier key
    let nk = F::rand(rng);
    
    // Create note with proper psi and fields
    let psi_bytes = [42u8; 32];
    let mut note_in = Note::new(1, v_comm, owner_addr, psi_bytes, 1);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.lineage_hash = F::from(1u64);
    note_in.memo_hash = F::from(0u64);
    let cm_in = note_in.commitment();
    
    // Compute the actual nullifier using the note's method
    let nf_in = note_in.nullifier(&nk);
    
    // Create exit receipt with the actual nullifier
    let exit_receipt = ExitReceipt::new(1, Amount::from(value as u128), nf_in, 1);
    
    // Build actual CMT tree and get merkle path
    let mut cmt_tree = IncrementalTree::new(16);
    cmt_tree.append(cm_in);
    let cmt_root = cmt_tree.root();
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();
    
    // Build NFT tree and generate non-membership proof
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    let nft_root_old = nft_tree.root();
    
    // Get non-membership proof for nf_in
    let nf_nonmembership = nft_tree.prove_non_membership(nf_in).unwrap();
    
    // Insert nf_in and get witness
    let nf_insert_witness_core = nft_tree.insert_with_witness(nf_in).unwrap();
    let nf_insert_witness = SortedInsertWitness {
        target: nf_insert_witness_core.target,
        range_proof: nf_insert_witness_core.range_proof,
        new_leaf: nf_insert_witness_core.new_leaf,
        updated_pred_leaf: nf_insert_witness_core.updated_pred_leaf,
        new_leaf_path: nf_insert_witness_core.new_leaf_path,
        pred_update_path: nf_insert_witness_core.pred_update_path,
        height: nf_insert_witness_core.height,
    };
    let nft_root_new = nft_tree.root();
    
    // Build exit tree
    let mut exit_tree = IncrementalTree::new(16);
    let exit_root_old = exit_tree.root();
    exit_tree.append(exit_receipt.hash());
    let exit_append_witness = exit_tree.generate_append_witness(exit_receipt.hash());
    let exit_root_new = exit_tree.root();
    
    BurnCircuit {
        note_in,
        value_in: value,
        value_randomness_in: randomness,
        owner_sk,
        owner_pk_x,
        owner_pk_y,
        nk,
        cm_path,
        nf_nonmembership: Some(nf_nonmembership),
        nf_insert_witness: Some(nf_insert_witness),
        exit_receipt,
        exit_append_witness,
        cmt_root,
        nft_root_old,
        nft_root_new,
        exit_root_old,
        exit_root_new,
        asset_type: 1,
        amount: Amount::from(value as u128),
        nf_in,
    }
}

/// Create a simplified transfer circuit for benchmarking
pub fn create_transfer_circuit<R: RngCore>(rng: &mut R, num_inputs: usize, num_outputs: usize) -> TransferCircuit {
    use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
    use fluxe_core::merkle::SortedTree;
    use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
    
    let params = PedersenParams::setup_value_commitment();
    
    // Build CMT tree (don't add dummy notes - they break the paths)
    let mut cmt_tree = IncrementalTree::new(16);
    
    // Build NFT tree with sentinel
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    let nft_root_old = nft_tree.root();
    
    // Create input notes with proper owner authentication
    let mut notes_in = Vec::new();
    let mut values_in = Vec::new();
    let mut value_randomness_in = Vec::new();
    let mut owner_sks = Vec::new();
    let mut owner_pks = Vec::new();
    let mut nks = Vec::new();
    let mut cm_paths = Vec::new();
    let mut nf_list = Vec::new();
    let mut nf_nonmembership_proofs = Vec::new();
    let mut nf_insert_witnesses = Vec::new();
    
    // First collect all nullifiers and notes
    let mut leaf_indices = Vec::new();
    for i in 0..num_inputs {
        let value = 500u64;
        // Use deterministic non-zero randomness to avoid infinity point in commitment
        let randomness = F::from(42u64 + i as u64);
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        // Use deterministic owner keys that work with our sorted insert gadget
        // For now, use the same owner_sk for all inputs since 124 seems to cause issues
        let owner_sk = F::from(123u64);
        let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
        let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
        
        // Use deterministic nullifier key (same for all to match working test)
        let nk = F::from(456u64);
        
        // Create note with proper psi and fields
        // Use different psi_bytes for each input to ensure different nullifiers
        let psi_bytes = [7u8 + i as u8; 32];
        let mut note = Note::new(1, v_comm, owner_addr, psi_bytes, 1);
        note.compliance_hash = F::from(1u64);
        note.callbacks_hash = F::from(1u64);
        note.lineage_hash = F::from(1u64);
        note.memo_hash = F::from(0u64);
        let cm = note.commitment();
        
        // Add to CMT tree BUT DON'T GET PATH YET
        let leaf_index = cmt_tree.num_leaves();
        cmt_tree.append(cm);
        leaf_indices.push(leaf_index);
        
        // Compute nullifier using the note's method for consistency
        let nf = note.nullifier(&nk);
        
        notes_in.push(note);
        values_in.push(value);
        value_randomness_in.push(randomness);
        owner_sks.push(owner_sk);
        owner_pks.push((pk_x, pk_y));
        nks.push(nk);
        nf_list.push(nf);
    }
    
    // NOW get all paths after all commitments are in the tree
    for leaf_index in leaf_indices {
        let path = cmt_tree.get_path(leaf_index).unwrap();
        cm_paths.push(path);
    }
    
    // Generate witnesses for nullifiers with proper chaining
    // First, get all non-membership proofs against the ORIGINAL tree state
    for nf in &nf_list {
        // Get non-membership proof from ORIGINAL tree state
        let nm_proof = nft_tree.prove_non_membership(*nf).unwrap();
        nf_nonmembership_proofs.push(Some(nm_proof));
    }
    
    // Then generate insert witnesses with proper chaining
    let mut current_tree = nft_tree.clone();
    for nf in &nf_list {
        // Get insert witness and update the tree for next iteration
        let insert_witness_core = current_tree.insert_with_witness(*nf).unwrap();
        let insert_witness = SortedInsertWitness {
            target: insert_witness_core.target,
            range_proof: insert_witness_core.range_proof,
            new_leaf: insert_witness_core.new_leaf,
            updated_pred_leaf: insert_witness_core.updated_pred_leaf,
            new_leaf_path: insert_witness_core.new_leaf_path,
            pred_update_path: insert_witness_core.pred_update_path,
            height: insert_witness_core.height,
        };
        nf_insert_witnesses.push(insert_witness);
        // current_tree is now updated with the inserted nullifier
    }
    
    // Capture cmt_root_old after input notes are in tree but before outputs
    let cmt_root_old = cmt_tree.root();
    let nft_root_new = current_tree.root(); // Root after all nullifiers inserted
    
    // Create output notes
    let mut notes_out = Vec::new();
    let mut values_out = Vec::new();
    let mut value_randomness_out = Vec::new();
    let mut cm_list = Vec::new();
    let mut cmt_appends_out = Vec::new();
    
    let total_value: u64 = values_in.iter().sum();
    let fee = 10u64;
    let value_per_output = (total_value - fee) / num_outputs as u64;
    
    for i in 0..num_outputs {
        // Use deterministic non-zero randomness to avoid infinity point in commitment
        let randomness = F::from(1000u64 + i as u64);
        let v_comm = PedersenCommitment::commit(
            &params,
            value_per_output,
            &PedersenRandomness { r: randomness },
        );
        
        // Use deterministic recipient address
        let recipient_sk = F::from(2000u64 + i as u64);
        let recipient_addr = compute_owner_address_circuit_compatible(recipient_sk);
        
        // Compute lineage hash for output note
        // Collect parent lineages from all input notes
        let parent_lineages: Vec<F> = notes_in.iter()
            .map(|n| n.lineage_hash)
            .collect();
        let mut lineage_input = parent_lineages;
        lineage_input.push(F::from(i as u64)); // context is output index
        let expected_lineage = poseidon_hash(&lineage_input);
        
        let mut note = Note::new(1, v_comm, recipient_addr, [0u8; 32], 1);
        note.compliance_hash = F::from(1u64);
        note.callbacks_hash = F::from(1u64);
        note.lineage_hash = expected_lineage;
        note.memo_hash = F::from(0u64);
        let cm = note.commitment();
        
        // Get append witness for output (BEFORE appending to capture pre-insertion state)
        let append_witness = cmt_tree.generate_append_witness(cm);
        cmt_appends_out.push(append_witness);
        
        // Now append the commitment to the tree
        cmt_tree.append(cm);
        
        notes_out.push(note);
        values_out.push(value_per_output);
        value_randomness_out.push(randomness);
        cm_list.push(cm);
    }
    
    let cmt_root_new = cmt_tree.root();

    // SECURITY FIX: Generate proper sanctions non-membership proofs
    // Create a sanctions tree with some sanctioned addresses (but not our test addresses)
    let mut sanctions_tree = SortedTree::new(16);
    let _ = sanctions_tree.insert(F::from(0u64)); // Sentinel
    // Add some dummy sanctioned addresses (different from our test addresses)
    let _ = sanctions_tree.insert(F::from(99999u64));
    let _ = sanctions_tree.insert(F::from(88888u64));
    let sanctions_root = sanctions_tree.root();

    // Generate sanctions non-membership proofs for input note owners
    let mut sanctions_nm_proofs_in = Vec::new();
    for note in &notes_in {
        let nm_proof = sanctions_tree.prove_non_membership(note.owner_addr).unwrap();
        sanctions_nm_proofs_in.push(Some(nm_proof));
    }

    // Generate sanctions non-membership proofs for output note owners
    let mut sanctions_nm_proofs_out = Vec::new();
    for note in &notes_out {
        let nm_proof = sanctions_tree.prove_non_membership(note.owner_addr).unwrap();
        sanctions_nm_proofs_out.push(Some(nm_proof));
    }

    TransferCircuit {
        notes_in,
        values_in,
        value_randomness_in,
        notes_out,
        values_out,
        value_randomness_out,
        nks,
        owner_sks,
        owner_pks,
        cm_paths,
        nf_nonmembership_proofs: nf_nonmembership_proofs.clone(),
        sanctions_nm_proofs_in,
        sanctions_nm_proofs_out,
        cmt_paths_out: vec![],
        nf_nonmembership: nf_nonmembership_proofs,
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out,
        nf_insert_witnesses, // Properly generated insert witnesses for each nullifier
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        sanctions_root,
        pool_rules_root: F::from(888888u64),
        nf_list,
        cm_list,
        fee: Amount::from(fee as u128),
    }
}

/// Create a simplified object update circuit for benchmarking
pub fn create_object_update_circuit<R: RngCore>(rng: &mut R) -> ObjectUpdateCircuit {
    let state_old = ComplianceState::new_verified(1);
    let state_new = ComplianceState {
        level: 2,
        ..state_old.clone()
    };
    
    let obj_old = ZkObject {
        state_hash: state_old.hash(),
        serial: 100,
        cb_head_hash: F::from(0),
    };
    
    let obj_new = ZkObject {
        state_hash: state_new.hash(),
        serial: 101,
        cb_head_hash: F::from(0),
    };
    
    let obj_path_old = MerklePath {
        leaf_index: 0,
        siblings: vec![F::from(0u64); 16],
        leaf: F::rand(rng),
    };
    
    ObjectUpdateCircuit {
        obj_old,
        state_old,
        obj_new,
        state_new,
        callback_entry: None,
        callback_invocation: None,
        callback_signature: None,
        cb_path: None,
        cb_nonmembership: None,
        obj_path_old,
        obj_append_witness: None,
        obj_old_randomness: F::from(1u64),
        obj_new_randomness: F::from(2u64),
        decrypt_key: None,
        obj_root_old: F::rand(rng),
        obj_root_new: F::rand(rng),
        cb_root: F::rand(rng),
        current_time: 1000,
    }
}