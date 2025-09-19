/// Common utilities for benchmarks
use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
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
    merkle::{MerklePath, AppendWitness, IncrementalTree},
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
    let params = PedersenParams::setup_value_commitment();
    let value = 500u64;
    let randomness = F::rand(rng);
    
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    let note_in = Note::new(1, v_comm, F::rand(rng), [0u8; 32], 1);
    let exit_receipt = ExitReceipt::new(1, Amount::from(value as u128), F::rand(rng), 1);
    
    let path = MerklePath {
        leaf_index: 0,
        siblings: vec![F::from(0u64); 16],
        leaf: note_in.commitment(),
    };
    
    let exit_receipt_clone = exit_receipt.clone();
    
    BurnCircuit {
        note_in,
        value_in: value,
        value_randomness_in: randomness,
        owner_sk: F::rand(rng),
        owner_pk_x: F::rand(rng),
        owner_pk_y: F::rand(rng),
        nk: F::rand(rng),
        cm_path: path,
        nf_nonmembership: None,
        nf_insert_witness: None,
        exit_receipt,
        exit_append_witness: AppendWitness {
            leaf_index: 0,
            leaf: exit_receipt_clone.hash(),
            pre_siblings: vec![F::from(0u64); 16],
            height: 16,
        },
        cmt_root: F::rand(rng),
        nft_root_old: F::rand(rng),
        nft_root_new: F::rand(rng),
        exit_root_old: F::rand(rng),
        exit_root_new: F::rand(rng),
        asset_type: 1,
        amount: Amount::from(value as u128),
        nf_in: F::rand(rng),
    }
}

/// Create a simplified transfer circuit for benchmarking
pub fn create_transfer_circuit<R: RngCore>(rng: &mut R, num_inputs: usize, num_outputs: usize) -> TransferCircuit {
    let params = PedersenParams::setup_value_commitment();
    
    // Create input notes
    let mut notes_in = Vec::new();
    let mut values_in = Vec::new();
    let mut value_randomness_in = Vec::new();
    let mut nks = Vec::new();
    let mut cm_paths = Vec::new();
    let mut nf_list = Vec::new();
    
    for _ in 0..num_inputs {
        let value = 500u64;
        let randomness = F::rand(rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        let note = Note::new(1, v_comm, F::rand(rng), [0u8; 32], 1);
        notes_in.push(note.clone());
        values_in.push(value);
        value_randomness_in.push(randomness);
        nks.push(F::rand(rng));
        
        let path = MerklePath {
            leaf_index: 0,
            siblings: vec![F::from(0u64); 16],
            leaf: note.commitment(),
        };
        cm_paths.push(path);
        nf_list.push(F::rand(rng));
    }
    
    // Create output notes
    let mut notes_out = Vec::new();
    let mut values_out = Vec::new();
    let mut value_randomness_out = Vec::new();
    let mut cm_list = Vec::new();
    
    let value_per_output = (values_in.iter().sum::<u64>() - 10) / num_outputs as u64;
    
    for _ in 0..num_outputs {
        let randomness = F::rand(rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value_per_output,
            &PedersenRandomness { r: randomness },
        );
        
        let note = Note::new(1, v_comm, F::rand(rng), [0u8; 32], 1);
        notes_out.push(note.clone());
        values_out.push(value_per_output);
        value_randomness_out.push(randomness);
        cm_list.push(note.commitment());
    }
    
    TransferCircuit {
        notes_in,
        values_in,
        value_randomness_in,
        notes_out,
        values_out,
        value_randomness_out,
        nks,
        owner_sks: vec![F::rand(rng); num_inputs],
        owner_pks: vec![(F::rand(rng), F::rand(rng)); num_inputs],
        cm_paths,
        nf_nonmembership_proofs: vec![None; num_inputs],
        sanctions_nm_proofs_in: vec![None; num_inputs],
        sanctions_nm_proofs_out: vec![None; num_outputs],
        cmt_paths_out: vec![],
        nf_nonmembership: vec![None; num_inputs],
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out: vec![],
        nf_insert_witnesses: vec![],
        cmt_root_old: F::rand(rng),
        cmt_root_new: F::rand(rng),
        nft_root_old: F::rand(rng),
        nft_root_new: F::rand(rng),
        sanctions_root: F::rand(rng),
        pool_rules_root: F::rand(rng),
        nf_list,
        cm_list,
        fee: Amount::from(10u128),
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
        decrypt_key: None,
        obj_root_old: F::rand(rng),
        obj_root_new: F::rand(rng),
        cb_root: F::rand(rng),
        current_time: 1000,
    }
}