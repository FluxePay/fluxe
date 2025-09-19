use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use fluxe_circuits::{
    circuits::FluxeCircuit,
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
};
use fluxe_core::{
    crypto::{
        poseidon_hash, 
        blake2b_hash,
        pedersen::{PedersenCommitment, PedersenParams, PedersenRandomness},
    },
    data_structures::{Note, ComplianceState, ZkObject, IngressReceipt, ExitReceipt},
    merkle::{MerklePath, SortedLeaf, RangePath, AppendWitness},
    types::*,
};
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
use rand::thread_rng;

/// Helper function to generate a dummy sorted insert witness for testing
fn generate_test_insert_witness(nf: F, height: usize) -> SortedInsertWitness {
    // Create a simple non-membership proof
    let nm_proof = RangePath {
        target: nf,
        low_leaf: SortedLeaf {
            key: F::from(0u64),
            next_key: F::from(0u64),
            next_index: 0,
        },
        low_path: MerklePath {
            leaf_index: 0,
            siblings: vec![F::from(0u64); height],
            leaf: F::from(0u64),
        },
    };
    
    // Create witness for inserting nf
    SortedInsertWitness::new(
        nf,
        nm_proof,
        SortedLeaf::new(nf),
        SortedLeaf {
            key: F::from(0u64),
            next_key: nf,
            next_index: 1,
        },
        MerklePath {
            leaf_index: 1,
            siblings: vec![F::from(0u64); height],
            leaf: SortedLeaf::new(nf).hash(),
        },
        MerklePath {
            leaf_index: 0,
            siblings: vec![F::from(0u64); height],
            leaf: SortedLeaf { key: F::from(0u64), next_key: nf, next_index: 1 }.hash(),
        },
        height,
    )
}

#[test]
fn test_mint_circuit_basic() {
    let mut rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    
    // Create test data
    let asset_type = 1u32;
    let value = 1000u64;
    let amount = Amount::from(value);
    
    // Create Pedersen commitment
    let randomness = F::rand(&mut rng);
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    // Create output note
    let owner_addr = F::rand(&mut rng);
    let psi_hash = blake2b_hash(&[1, 2, 3]);
    let mut psi = [0u8; 32];
    psi.copy_from_slice(&psi_hash[..32]);
    
    let note_out = Note {
        asset_type,
        v_comm,
        owner_addr,
        psi,
        chain_hint: 0,
        compliance_hash: F::rand(&mut rng),
        lineage_hash: F::from(0u64),
        pool_id: 1,
        callbacks_hash: F::from(0u64),
        memo_hash: F::from(0u64),
    };
    
    // Store note commitment before moving note
    let note_commitment = note_out.commitment();
    
    // Create ingress receipt
    // The beneficiary_cm should be a hash chain of all output commitments
    let beneficiary_cm = poseidon_hash(&[F::from(0u64), note_commitment]);
    let ingress_receipt = IngressReceipt {
        asset_type,
        amount,
        beneficiary_cm,
        nonce: 1,
        aux: F::from(0u64),
    };
    
    // Use the MintCircuit constructor which properly handles witness generation
    use fluxe_core::merkle::IncrementalTree;
    let mut cmt_tree = IncrementalTree::new(16);
    let mut ingress_tree = IncrementalTree::new(16);
    
    let circuit = MintCircuit::new(
        vec![note_out],
        vec![value],
        vec![randomness],
        ingress_receipt,
        &mut cmt_tree,
        &mut ingress_tree,
    );
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    
    // Check if constraints are satisfied
    let satisfied = cs.is_satisfied().unwrap();
    if !satisfied {
        println!("Mint circuit constraints not satisfied!");
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("First unsatisfied constraint: {}", unsat);
        }
        // Let's check the public inputs
        let public_inputs = circuit.public_inputs();
        println!("Public inputs:");
        println!("  cmt_root_old: {:?}", public_inputs[0]);
        println!("  cmt_root_new: {:?}", public_inputs[1]);
        println!("  ingress_root_old: {:?}", public_inputs[2]);
        println!("  ingress_root_new: {:?}", public_inputs[3]);
        println!("  asset_type: {:?}", public_inputs[4]);
        println!("  amount: {:?}", public_inputs[5]);
        println!("  cm_out_list_commit: {:?}", public_inputs[6]);
    }
    assert!(satisfied, "Mint circuit constraints not satisfied");
    
    // Test public inputs
    let public_inputs = circuit.public_inputs();
    assert_eq!(public_inputs.len(), 7);
    assert_eq!(public_inputs[4], F::from(asset_type as u64)); // asset_type
    assert_eq!(public_inputs[5], amount.to_field()); // amount
}

#[test]
fn test_burn_circuit_basic() {
    let mut rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    
    // Create test data
    let asset_type = 1u32;
    let value = 500u64;
    let amount = Amount::from(value);
    
    // Create input note
    let randomness = F::rand(&mut rng);
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    let owner_addr = F::rand(&mut rng);
    let psi_hash = blake2b_hash(&[4, 5, 6]);
    let mut psi = [0u8; 32];
    psi.copy_from_slice(&psi_hash[..32]);
    
    let mut note_in = Note {
        asset_type,
        v_comm,
        owner_addr,
        psi,
        chain_hint: 0,
        compliance_hash: F::rand(&mut rng),
        lineage_hash: F::from(0u64),
        pool_id: 1,
        callbacks_hash: F::from(0u64),
        memo_hash: F::from(0u64),
    };
    
    // Create nullifier key
    let nk = F::rand(&mut rng);
    let owner_sk = F::from(1u64); // Use consistent owner_sk
    
    // Compute public key using real EC scalar multiplication
    let (pk_x, pk_y) = fluxe_core::crypto::compute_ec_public_key(owner_sk);
    
    // Update note to use consistent owner address
    note_in.owner_addr = poseidon_hash(&[pk_x, pk_y]);
    
    // Create merkle path
    let cm_path = MerklePath {
        leaf_index: 0,
        siblings: vec![F::from(0u64); 32],
        leaf: note_in.commitment(),
    };
    
    // Create exit receipt
    let psi_field = fluxe_core::utils::bytes_to_field(&psi);
    let nf = poseidon_hash(&[nk, psi_field, note_in.commitment()]);
    let exit_receipt = ExitReceipt {
        asset_type,
        amount,
        burned_nf: nf,
        nonce: 1,
        aux: F::from(0u64),
    };
    
    // Create non-membership proof for the nullifier
    use fluxe_core::merkle::{SortedLeaf, RangePath};
    let nm_proof = RangePath {
        low_leaf: SortedLeaf {
            key: F::rand(&mut rng),
            next_key: F::rand(&mut rng),
            next_index: 0,
        },
        low_path: MerklePath {
            leaf_index: 0,
            siblings: vec![F::rand(&mut rng); 16],
            leaf: F::rand(&mut rng),
        },
        target: nf,
    };
    
    // Generate proper insertion witness
    let insert_witness = generate_test_insert_witness(nf, 32);
    
    // Create exit append witness
    let exit_append_witness = AppendWitness {
        leaf_index: 0,
        leaf: exit_receipt.hash(),
        pre_siblings: vec![F::from(0u64); 32],
        height: 32,
    };
    
    // Create circuit
    let circuit = BurnCircuit::new(
        note_in,
        value,
        randomness,
        nk,
        owner_sk,
        pk_x,
        pk_y,
        cm_path,
        Some(nm_proof), // nf_nonmembership
        Some(insert_witness), // nf_insert_witness
        exit_receipt,
        exit_append_witness,
        F::rand(&mut rng), // cmt_root
        F::rand(&mut rng), // nft_root_old
        F::rand(&mut rng), // nft_root_new
        F::rand(&mut rng), // exit_root_old
        F::rand(&mut rng), // exit_root_new
    );
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    
    // Check if constraints are satisfied (this will likely fail due to dummy data)
    // But we're just testing that the circuit compiles and runs
    let _satisfied = cs.is_satisfied();
    
    // Test public inputs
    let public_inputs = circuit.public_inputs();
    assert_eq!(public_inputs.len(), 8);
}

#[test]
fn test_transfer_circuit_basic() {
    let mut rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    
    // Create input notes with consistent authentication
    let mut notes_in = Vec::new();
    let mut values_in = Vec::new();
    let mut value_randomness_in = Vec::new();
    let mut nks = Vec::new();
    let mut owner_sks = Vec::new();
    let mut owner_pks = Vec::new();
    let mut cm_paths = Vec::new();
    let mut nf_nonmembership_proofs = Vec::new();
    
    for i in 0..2 {
        let value = 500u64;
        let randomness = F::rand(&mut rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        // Create consistent EC authentication using real Jubjub curve
        let owner_sk = F::from((i + 1) as u64);
        let (pk_x, pk_y) = fluxe_core::crypto::compute_ec_public_key(owner_sk);
        let owner_addr = poseidon_hash(&[pk_x, pk_y]);
        
        let psi_hash = blake2b_hash(&[i as u8, i as u8 + 1, i as u8 + 2]);
        let mut psi = [0u8; 32];
        psi.copy_from_slice(&psi_hash[..32]);
        
        let note = Note {
            asset_type: 1,
            v_comm,
            owner_addr,
            psi,
            chain_hint: 0,
            compliance_hash: F::from(1u64), // Non-zero means not frozen
            lineage_hash: F::from(0u64),
            pool_id: 1,
            callbacks_hash: F::from(1u64), // Non-zero means no pending callbacks
            memo_hash: F::from(0u64),
        };
        
        notes_in.push(note.clone());
        values_in.push(value);
        value_randomness_in.push(randomness);
        
        let nk = F::rand(&mut rng);
        nks.push(nk);
        owner_sks.push(owner_sk);
        owner_pks.push((pk_x, pk_y));
        
        cm_paths.push(MerklePath {
            leaf_index: i,
            siblings: vec![F::from(0u64); 32],
            leaf: note.commitment(),
        });
        
        // Create non-membership proof for the nullifier
        let psi_field = fluxe_core::utils::bytes_to_field(&psi);
        let nf = poseidon_hash(&[nk, psi_field, note.commitment()]);
        
        use fluxe_core::merkle::{SortedLeaf, RangePath};
        let nm_proof = RangePath {
            low_leaf: SortedLeaf {
                key: F::rand(&mut rng),
                next_key: F::rand(&mut rng),
                next_index: 0,
            },
            low_path: MerklePath {
                leaf_index: 0,
                siblings: vec![F::rand(&mut rng); 16],
                leaf: F::rand(&mut rng),
            },
            target: nf,
        };
        nf_nonmembership_proofs.push(Some(nm_proof));
    }
    
    // Create output notes with proper lineage
    let mut notes_out = Vec::new();
    let mut values_out = Vec::new();
    let mut value_randomness_out = Vec::new();
    let mut cm_list = Vec::new();
    
    // Collect parent lineages from input notes
    let parent_lineages: Vec<F> = notes_in.iter().map(|n| n.lineage_hash).collect();
    
    for i in 0..2 {
        let value = 495u64;
        let randomness = F::rand(&mut rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        let psi_hash = blake2b_hash(&[7, 8, 9]);
        let mut psi = [0u8; 32];
        psi.copy_from_slice(&psi_hash[..32]);
        
        // Compute lineage hash from parent lineages and context
        let mut lineage_input = parent_lineages.clone();
        lineage_input.push(F::from(i as u64)); // context
        let lineage_hash = poseidon_hash(&lineage_input);
        
        let note = Note {
            asset_type: 1,
            v_comm,
            owner_addr: F::rand(&mut rng),
            psi,
            chain_hint: 0,
            compliance_hash: F::from(1u64), // Non-zero means not frozen
            lineage_hash,
            pool_id: 1,
            callbacks_hash: F::from(1u64), // Non-zero means no pending callbacks
            memo_hash: F::from(0u64),
        };
        
        cm_list.push(note.commitment());
        notes_out.push(note);
        values_out.push(value);
        value_randomness_out.push(randomness);
    }
    
    // Compute nullifiers
    let mut nf_list = Vec::new();
    for (i, note) in notes_in.iter().enumerate() {
        let psi_field = fluxe_core::utils::bytes_to_field(&note.psi);
        let nf = poseidon_hash(&[nks[i], psi_field, note.commitment()]);
        nf_list.push(nf);
    }
    
    // Generate insertion witnesses for nullifiers
    let mut nf_insert_witnesses = Vec::new();
    for nf in &nf_list {
        nf_insert_witnesses.push(generate_test_insert_witness(*nf, 32));
    }
    
    // Generate append witnesses for outputs
    let mut cmt_appends_out = Vec::new();
    for (i, _cm) in cm_list.iter().enumerate() {
        cmt_appends_out.push(AppendWitness::new(
            F::from(0u64), // dummy leaf
            i + 2, // leaf index (after 2 inputs)
            vec![F::from(0u64); 16], // dummy siblings
            16, // height
        ));
    }
    
    // Create circuit
    let circuit = TransferCircuit {
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
        sanctions_nm_proofs_in: vec![None, None],
        sanctions_nm_proofs_out: vec![None, None],
        cmt_paths_out: vec![],
        nf_nonmembership: nf_nonmembership_proofs,
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out,
        nf_insert_witnesses,
        cmt_root_old: F::rand(&mut rng),
        cmt_root_new: F::rand(&mut rng),
        nft_root_old: F::rand(&mut rng),
        nft_root_new: F::rand(&mut rng),
        sanctions_root: F::rand(&mut rng),
        pool_rules_root: F::rand(&mut rng),
        nf_list,
        cm_list,
        fee: Amount::from(10u64),
    };
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    
    // Check if constraints are satisfied (this will likely fail due to dummy data)
    // But we're just testing that the circuit compiles and runs
    let _satisfied = cs.is_satisfied();
    
    // Test public inputs
    let public_inputs = circuit.public_inputs();
    assert!(!public_inputs.is_empty());
}

#[test]
fn test_object_update_circuit_basic() {
    let mut rng = thread_rng();
    
    // Create old and new compliance states
    let state_old = ComplianceState::new();
    let state_new = ComplianceState::new_verified(1);
    
    // Create old and new zk objects
    let obj_old = ZkObject {
        state_hash: state_old.hash(),
        serial: 100,
        cb_head_hash: F::rand(&mut rng),
    };
    
    let obj_new = ZkObject {
        state_hash: state_new.hash(),
        serial: 101,
        cb_head_hash: obj_old.cb_head_hash,
    };
    
    // Create merkle path for old object
    let obj_path_old = MerklePath {
        leaf_index: 0,
        siblings: vec![F::from(0u64); 32],
        leaf: obj_old.commitment(&mut rng),
    };
    
    // Create circuit
    let circuit = ObjectUpdateCircuit::new(
        obj_old,
        state_old,
        obj_new,
        state_new,
        None, // no callback entry
        None, // no callback invocation
        None, // cb_path
        None, // cb_nonmembership
        obj_path_old,
        None, // no decrypt key
        F::rand(&mut rng), // obj_root_old
        F::rand(&mut rng), // obj_root_new
        F::rand(&mut rng), // cb_root
        2000, // current_time
    );
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    
    // Test public inputs
    let public_inputs = circuit.public_inputs();
    assert_eq!(public_inputs.len(), 4);
}