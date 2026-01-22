/// Golden end-to-end integration tests for the Fluxe protocol
/// These tests verify the complete flow: Mint → Transfer → Burn → ObjectUpdate
/// with actual proof generation and verification

use ark_bn254::Fr as F;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

use fluxe_circuits::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
    setup::TrustedSetup,
    circuits::FluxeCircuit,
    utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible},
};

use fluxe_core::{
    data_structures::{Note, IngressReceipt, ExitReceipt, ComplianceState, ZkObject},
    crypto::{
        pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
        poseidon_hash,
    },
    merkle::{IncrementalTree, SortedTree},
    types::*,
};

struct TestContext {
    // Trees
    cmt_tree: IncrementalTree,
    nft_tree: SortedTree,
    obj_tree: IncrementalTree,
    cb_tree: SortedTree,
    ingress_tree: IncrementalTree,
    exit_tree: IncrementalTree,
    
    // Keys
    mint_keys: TrustedSetup,
    burn_keys: TrustedSetup,
    transfer_keys: TrustedSetup, // Default 1-in/2-out
    transfer_keys_1_1: TrustedSetup, // For 1-in/1-out transfers  
    object_update_keys: TrustedSetup,
    
    // State
    supply: HashMap<AssetType, Amount>,
    
    // RNG
    rng: ChaCha20Rng,
}

impl TestContext {
    fn new() -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Generate setup keys for all circuits
        let setup_manager = fluxe_circuits::setup::SetupManager::with_default_config();
        let mint_keys = setup_manager.generate_mint_setup(&mut rng).unwrap();
        let burn_keys = setup_manager.generate_burn_setup(&mut rng).unwrap();
        let transfer_keys = setup_manager.generate_transfer_setup(&mut rng).unwrap(); // Default 1-in/2-out
        let transfer_keys_1_1 = setup_manager.generate_transfer_setup_custom(&mut rng, 1, 1).unwrap();
        let object_update_keys = setup_manager.generate_object_update_setup(&mut rng).unwrap();
        
        // Initialize trees
        let mut nft_tree = SortedTree::new(16);
        let _ = nft_tree.insert(F::from(0u64)); // Sentinel
        
        let mut cb_tree = SortedTree::new(16);
        let _ = cb_tree.insert(F::from(0u64)); // Sentinel
        
        Self {
            cmt_tree: IncrementalTree::new(16),
            nft_tree,
            obj_tree: IncrementalTree::new(16),
            cb_tree,
            ingress_tree: IncrementalTree::new(16),
            exit_tree: IncrementalTree::new(16),
            mint_keys,
            burn_keys,
            transfer_keys,
            transfer_keys_1_1,
            object_update_keys,
            supply: HashMap::new(),
            rng,
        }
    }
}

#[test]
fn test_golden_scenario_mint_transfer_burn() {
    let mut ctx = TestContext::new();
    let params = PedersenParams::setup_value_commitment();
    
    println!("\n=== Golden E2E Test: Mint → Transfer → Burn ===\n");
    
    // Test parameters
    let asset_type = 1u32;
    let mint_value = 1000u64;
    
    // User keys
    let alice_sk = F::from(123u64);
    let alice_addr = compute_owner_address_circuit_compatible(alice_sk);
    let (alice_pk_x, alice_pk_y) = get_pk_coords_circuit_compatible(alice_sk);
    let alice_nk = F::from(456u64);
    
    let bob_sk = F::from(789u64);
    let bob_addr = compute_owner_address_circuit_compatible(bob_sk);
    
    // ========== STEP 1: MINT ==========
    println!("Step 1: Minting {} units to Alice", mint_value);
    
    // Create mint note
    let mint_randomness = F::from(42u64);
    let mint_v_comm = PedersenCommitment::commit(
        &params,
        mint_value,
        &PedersenRandomness { r: mint_randomness },
    );
    
    let mut mint_note = Note::new(
        asset_type,
        mint_v_comm,
        alice_addr,
        [1u8; 32], // psi
        1, // chain_hint
    );
    mint_note.compliance_hash = F::from(1u64);
    mint_note.callbacks_hash = F::from(1u64);
    mint_note.lineage_hash = F::from(1u64);
    mint_note.memo_hash = F::from(0u64);
    
    // Create ingress receipt
    // The beneficiary_cm should be a hash chain of all output commitments
    let cm = mint_note.commitment();
    let beneficiary_cm = poseidon_hash(&[F::from(0u64), cm]);  // Hash chain starting from 0
    let ingress = IngressReceipt::new(
        1, // source_chain (Ethereum)
        asset_type,
        Amount::from(mint_value as u128),
        beneficiary_cm,
        1, // nonce
    );
    
    // Setup mint circuit
    let mint_circuit = MintCircuit::new(
        vec![mint_note.clone()],
        vec![mint_value],
        vec![mint_randomness],
        ingress.clone(),
        &mut ctx.cmt_tree,
        &mut ctx.ingress_tree,
    );
    
    // Generate and verify mint proof
    let mint_proof = Groth16::<ark_bn254::Bn254>::prove(
        &ctx.mint_keys.proving_key,
        mint_circuit.clone(),
        &mut ctx.rng,
    ).expect("Mint proof generation failed");
    
    let mint_public_inputs = mint_circuit.public_inputs();
    let mint_verified = Groth16::<ark_bn254::Bn254>::verify(
        &ctx.mint_keys.verifying_key,
        &mint_public_inputs,
        &mint_proof,
    ).expect("Mint verification failed");
    
    assert!(mint_verified, "Mint proof verification failed");
    println!("  ✓ Mint proof verified");
    
    // Update supply
    *ctx.supply.entry(asset_type).or_insert(Amount::zero()) = 
        *ctx.supply.entry(asset_type).or_insert(Amount::zero()) + Amount::from(mint_value as u128);
    
    println!("  Supply after mint: {} units", mint_value);
    
    // ========== STEP 2: TRANSFER ==========
    println!("\nStep 2: Transferring 600 units from Alice to Bob");
    
    let transfer_value_to_bob = 600u64;
    let transfer_value_to_alice = 390u64; // Change back to Alice (1000 - 600 - 10 fee)
    let fee = 10u64;
    
    // Create output notes
    let bob_randomness = F::from(100u64);
    let bob_v_comm = PedersenCommitment::commit(
        &params,
        transfer_value_to_bob,
        &PedersenRandomness { r: bob_randomness },
    );
    
    // Compute lineage for outputs (with 1 input)
    let expected_lineage_0 = poseidon_hash(&[mint_note.lineage_hash, F::from(0u64)]); // First output
    let expected_lineage_1 = poseidon_hash(&[mint_note.lineage_hash, F::from(1u64)]); // Second output
    
    let mut bob_note = Note::new(
        asset_type,
        bob_v_comm,
        bob_addr,
        [2u8; 32],
        1,
    );
    bob_note.compliance_hash = F::from(1u64);
    bob_note.callbacks_hash = F::from(1u64);
    bob_note.lineage_hash = expected_lineage_0;
    bob_note.memo_hash = F::from(0u64);
    
    let alice_change_randomness = F::from(101u64);
    let alice_change_v_comm = PedersenCommitment::commit(
        &params,
        transfer_value_to_alice,
        &PedersenRandomness { r: alice_change_randomness },
    );
    
    let mut alice_change_note = Note::new(
        asset_type,
        alice_change_v_comm,
        alice_addr,
        [3u8; 32],
        1,
    );
    alice_change_note.compliance_hash = F::from(1u64);
    alice_change_note.callbacks_hash = F::from(1u64);
    alice_change_note.lineage_hash = expected_lineage_1;
    alice_change_note.memo_hash = F::from(0u64);
    
    // Get Merkle path for input note
    let mint_note_path = ctx.cmt_tree.get_path(0).expect("Should get path for mint note");
    
    // Store old roots BEFORE any modifications
    let cmt_root_old = ctx.cmt_tree.root();
    let nft_root_old = ctx.nft_tree.root();
    
    // Get nullifier non-membership proof (before insertion)
    let mint_nf = mint_note.nullifier(&alice_nk);
    let mint_nf_nm_proof = ctx.nft_tree.prove_non_membership(mint_nf)
        .expect("Should prove non-membership");
    
    // Get insert witness for nullifier and update tree
    let mint_nf_insert_witness = ctx.nft_tree.insert_with_witness(mint_nf)
        .expect("Should insert nullifier");
    let nft_root_new = ctx.nft_tree.root();
    
    // Get append witnesses for output notes (before appending)
    let bob_cm = bob_note.commitment();
    let bob_append_witness = ctx.cmt_tree.generate_append_witness(bob_cm);
    ctx.cmt_tree.append(bob_cm);
    
    let alice_change_cm = alice_change_note.commitment();
    let alice_change_append_witness = ctx.cmt_tree.generate_append_witness(alice_change_cm);
    ctx.cmt_tree.append(alice_change_cm);
    let cmt_root_new = ctx.cmt_tree.root();
    
    // Setup transfer circuit
    let transfer_circuit = TransferCircuit::new_with_nft_witnesses(
        vec![mint_note.clone()],
        vec![mint_value],
        vec![mint_randomness],
        vec![bob_note.clone(), alice_change_note.clone()],
        vec![transfer_value_to_bob, transfer_value_to_alice],
        vec![bob_randomness, alice_change_randomness],
        vec![alice_nk],
        vec![alice_sk],
        vec![(alice_pk_x, alice_pk_y)],
        vec![mint_note_path],
        vec![Some(mint_nf_nm_proof)],
        vec![convert_sorted_witness(mint_nf_insert_witness)],
        vec![None, None], // sanctions_nm_proofs
        vec![None, None], // sanctions_nm_proofs_out
        vec![], // source_pool_policies
        vec![], // dest_pool_policies
        vec![], // pool_policy_paths
        vec![bob_append_witness, alice_change_append_witness],
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        F::from(0u64), // sanctions_root
        F::from(0u64), // pool_rules_root
        Amount::from(fee as u128),
    );
    
    // Debug circuit structure
    println!("  Transfer circuit: {} inputs, {} outputs", 
        transfer_circuit.notes_in.len(), 
        transfer_circuit.notes_out.len());
    
    // Generate and verify transfer proof
    let transfer_proof = Groth16::<ark_bn254::Bn254>::prove(
        &ctx.transfer_keys.proving_key,
        transfer_circuit.clone(),
        &mut ctx.rng,
    ).expect("Transfer proof generation failed");
    
    let transfer_public_inputs = transfer_circuit.public_inputs();
    println!("  Public inputs count: {}", transfer_public_inputs.len());
    
    // Try to verify the proof
    match Groth16::<ark_bn254::Bn254>::verify(
        &ctx.transfer_keys.verifying_key,
        &transfer_public_inputs,
        &transfer_proof,
    ) {
        Ok(verified) => {
            assert!(verified, "Transfer proof verification returned false");
        }
        Err(e) => {
            panic!("Transfer verification error: {:?}", e);
        }
    }
    println!("  ✓ Transfer proof verified");
    println!("  Bob received: {} units", transfer_value_to_bob);
    println!("  Alice change: {} units", transfer_value_to_alice);
    println!("  Fee: {} units", fee);
    
    // ========== STEP 3: BURN ==========
    println!("\nStep 3: Bob burns 500 units");
    
    let burn_value = 500u64;
    
    // Get Bob's note path
    let bob_note_index = 1; // Second note added to tree
    let bob_note_path = ctx.cmt_tree.get_path(bob_note_index)
        .expect("Should get path for Bob's note");
    
    // Store old roots BEFORE any modifications
    let nft_root_old = ctx.nft_tree.root();
    let exit_root_old = ctx.exit_tree.root();
    
    // Get nullifier non-membership proof for Bob's note
    let bob_nk = F::from(999u64);
    let bob_nf = bob_note.nullifier(&bob_nk);
    let bob_nf_nm_proof = ctx.nft_tree.prove_non_membership(bob_nf)
        .expect("Should prove non-membership");
    
    // Get insert witness for Bob's nullifier and update tree
    let bob_nf_insert_witness = ctx.nft_tree.insert_with_witness(bob_nf)
        .expect("Should insert nullifier");
    let nft_root_new = ctx.nft_tree.root();
    
    // Create exit receipt
    let exit_receipt = ExitReceipt::new(
        1, // destination_chain (Ethereum)
        asset_type,
        Amount::from(burn_value as u128),
        bob_nf,
        1, // nonce
    );
    
    // Get append witness for exit tree (before appending)
    let exit_append_witness = ctx.exit_tree.generate_append_witness(exit_receipt.hash());
    ctx.exit_tree.append(exit_receipt.hash());
    let exit_root_new = ctx.exit_tree.root();
    
    // Setup burn circuit
    let burn_circuit = BurnCircuit {
        note_in: bob_note.clone(),
        value_in: transfer_value_to_bob,
        value_randomness_in: bob_randomness,
        owner_sk: bob_sk,
        owner_pk_x: get_pk_coords_circuit_compatible(bob_sk).0,
        owner_pk_y: get_pk_coords_circuit_compatible(bob_sk).1,
        nk: bob_nk,
        cm_path: bob_note_path,
        nf_nonmembership: Some(bob_nf_nm_proof),
        nf_insert_witness: Some(convert_sorted_witness(bob_nf_insert_witness)),
        exit_receipt: exit_receipt.clone(),
        exit_append_witness,
        cmt_root: ctx.cmt_tree.root(),
        nft_root_old,
        nft_root_new,
        exit_root_old,
        exit_root_new,
        asset_type,
        amount: Amount::from(burn_value as u128),
        nf_in: bob_nf,
    };
    
    // Generate and verify burn proof
    let burn_proof = Groth16::<ark_bn254::Bn254>::prove(
        &ctx.burn_keys.proving_key,
        burn_circuit.clone(),
        &mut ctx.rng,
    ).expect("Burn proof generation failed");
    
    let burn_public_inputs = burn_circuit.public_inputs();
    let burn_verified = Groth16::<ark_bn254::Bn254>::verify(
        &ctx.burn_keys.verifying_key,
        &burn_public_inputs,
        &burn_proof,
    ).expect("Burn verification failed");
    
    assert!(burn_verified, "Burn proof verification failed");
    println!("  ✓ Burn proof verified");
    
    // Update supply
    let current_supply = ctx.supply.get(&asset_type).unwrap();
    *ctx.supply.get_mut(&asset_type).unwrap() = 
        *current_supply - Amount::from(burn_value as u128);
    
    println!("  Supply after burn: {} units", 
             mint_value - burn_value);
    
    // ========== FINAL VERIFICATION ==========
    println!("\n=== Final State ===");
    println!("  Total minted: {} units", mint_value);
    println!("  Total burned: {} units", burn_value);
    println!("  Net supply: {} units", ctx.supply.get(&asset_type).unwrap().value());
    println!("  Alice balance: {} units (in change note)", transfer_value_to_alice);
    println!("  Bob balance: {} units (after burn)", transfer_value_to_bob - burn_value);
    
    println!("\n✅ All proofs verified successfully!");
}

#[test]
fn test_golden_scenario_with_object_update() {
    let mut ctx = TestContext::new();
    
    println!("\n=== Golden E2E Test: Object Update with Callbacks ===\n");
    
    // Create initial compliance state
    let state_old = ComplianceState::new_verified(1);
    let mut state_new = state_old.clone();
    state_new.level = 2;
    state_new.risk_score = 50;
    
    // Create zk-objects
    let obj_old = ZkObject {
        state_hash: state_old.hash(),
        serial: 1,
        cb_head_hash: F::from(0),
    };
    
    let obj_new = ZkObject {
        state_hash: state_new.hash(),
        serial: 2,
        cb_head_hash: F::from(0),
    };
    
    // Add old object to tree with deterministic randomness
    let obj_old_randomness = F::from(1u64);  // Must match what's in the circuit constructor
    let obj_new_randomness = F::from(2u64);  // Must match what's in the circuit constructor
    
    let obj_old_cm = obj_old.commitment_with_randomness(&obj_old_randomness);
    ctx.obj_tree.append(obj_old_cm);
    let obj_path = ctx.obj_tree.get_path(0).unwrap();
    
    // Store old root BEFORE adding new object
    let obj_root_old = ctx.obj_tree.root();
    
    // Get append witness for new object (before appending)
    let obj_new_cm = obj_new.commitment_with_randomness(&obj_new_randomness);
    let obj_append_witness = ctx.obj_tree.generate_append_witness(obj_new_cm);
    ctx.obj_tree.append(obj_new_cm);
    let obj_root_new = ctx.obj_tree.root();
    
    // Create object update circuit
    let object_update_circuit = ObjectUpdateCircuit::new_with_signature(
        obj_old,
        state_old,
        obj_new,
        state_new,
        None, // callback_entry
        None, // callback_invocation
        None, // callback_signature
        None, // cb_path
        None, // cb_nonmembership
        obj_path,
        Some(obj_append_witness),
        None, // decrypt_key
        obj_root_old,
        obj_root_new,
        ctx.cb_tree.root(),
        1000, // current_time
    );
    
    // Generate and verify object update proof
    println!("  Generating object update proof...");
    let object_update_proof = Groth16::<ark_bn254::Bn254>::prove(
        &ctx.object_update_keys.proving_key,
        object_update_circuit.clone(),
        &mut ctx.rng,
    ).expect("Object update proof generation failed");
    
    let object_update_public_inputs = object_update_circuit.public_inputs();
    println!("  Object update public inputs count: {}", object_update_public_inputs.len());
    
    match Groth16::<ark_bn254::Bn254>::verify(
        &ctx.object_update_keys.verifying_key,
        &object_update_public_inputs,
        &object_update_proof,
    ) {
        Ok(verified) => {
            assert!(verified, "Object update proof verification returned false");
        }
        Err(e) => {
            panic!("Object update verification error: {:?}", e);
        }
    }
    println!("  ✓ Object update proof verified");
    println!("  Compliance level: {} → {}", 1, 2);
    println!("  Risk score: 0 → 50");
    println!("  Serial: 1 → 2");
    
    println!("\n✅ Object update with state transition verified!");
}

// Helper to convert core witness to circuit witness
fn convert_sorted_witness(w: fluxe_core::merkle::SortedInsertWitness) -> fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
    fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
        target: w.target,
        range_proof: w.range_proof,
        new_leaf: w.new_leaf,
        updated_pred_leaf: w.updated_pred_leaf,
        new_leaf_path: w.new_leaf_path,
        pred_update_path: w.pred_update_path,
        height: w.height,
    }
}