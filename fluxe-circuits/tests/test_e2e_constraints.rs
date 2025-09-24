/// End-to-end constraint satisfaction tests for the Fluxe protocol
/// These tests verify the complete flow without expensive proof generation

use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use std::collections::HashMap;

use fluxe_circuits::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
    gadgets::sorted_insert::SortedInsertWitness,
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
    
    // State
    supply: HashMap<AssetType, Amount>,
}

impl TestContext {
    fn new() -> Self {
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
            supply: HashMap::new(),
        }
    }
}

#[test]
fn test_e2e_constraint_satisfaction() {
    let mut ctx = TestContext::new();
    let params = PedersenParams::setup_value_commitment();
    
    println!("\n=== E2E Constraint Test: Mint → Transfer → Burn ===\n");
    
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
    println!("Step 1: Testing Mint constraints");
    
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
    
    // Create ingress receipt with proper beneficiary_cm
    let cm = mint_note.commitment();
    let beneficiary_cm = poseidon_hash(&[F::from(0u64), cm]);
    let ingress = IngressReceipt::new(
        asset_type,
        Amount::from(mint_value as u128),
        beneficiary_cm,
        1,
    );
    
    // Store old roots before any changes
    let cmt_root_old_mint = ctx.cmt_tree.root();
    let ingress_root_old = ctx.ingress_tree.root();
    
    // Create mint circuit
    let mint_circuit = MintCircuit::new(
        vec![mint_note.clone()],
        vec![mint_value],
        vec![mint_randomness],
        ingress.clone(),
        &mut ctx.cmt_tree,
        &mut ctx.ingress_tree,
    );
    
    // Test mint constraints
    let cs_mint = ConstraintSystem::<F>::new_ref();
    mint_circuit.generate_constraints(cs_mint.clone())
        .expect("Mint constraint generation failed");
    
    if !cs_mint.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs_mint.which_is_unsatisfied() {
            panic!("Mint: Unsatisfied constraint: {}", unsat);
        }
    }
    println!("✅ Mint constraints satisfied ({} constraints)", cs_mint.num_constraints());
    
    // Update supply
    let mint_amount = Amount::from(mint_value as u128);
    let current = ctx.supply.get(&asset_type).unwrap_or(&Amount::from(0u128)).value();
    let new_amount = Amount::from(current + mint_value as u128);
    ctx.supply.insert(asset_type, new_amount);
    
    // ========== STEP 2: TRANSFER (Alice → Bob) ==========
    println!("\nStep 2: Testing Transfer constraints");
    
    // Alice's note is now in the tree, prepare to spend it
    let alice_cm = cm;
    let alice_cm_path = ctx.cmt_tree.get_proof(alice_cm).unwrap();
    
    // Compute Alice's nullifier
    let alice_nf = mint_note.nullifier(&alice_nk);
    
    // Store old roots BEFORE any tree modifications
    let cmt_root_old_transfer = ctx.cmt_tree.root();
    let nft_root_old_transfer = ctx.nft_tree.root();
    
    // Get non-membership proof BEFORE insertion
    let alice_nm_proof = ctx.nft_tree.prove_non_membership(alice_nf).unwrap();
    
    // Create Bob's output note
    let bob_value = 600u64;
    let bob_randomness = F::from(99u64);
    let bob_v_comm = PedersenCommitment::commit(
        &params,
        bob_value,
        &PedersenRandomness { r: bob_randomness },
    );
    
    // Compute lineage for Bob's note
    let bob_lineage = poseidon_hash(&[mint_note.lineage_hash, F::from(0u64)]);
    
    let mut bob_note = Note::new(
        asset_type,
        bob_v_comm,
        bob_addr,
        [2u8; 32],
        1,
    );
    bob_note.compliance_hash = F::from(1u64);
    bob_note.callbacks_hash = F::from(1u64);
    bob_note.lineage_hash = bob_lineage;
    bob_note.memo_hash = F::from(0u64);
    
    // Create Alice's change output
    let alice_change_value = 390u64; // 1000 - 600 - 10 fee
    let alice_change_randomness = F::from(88u64);
    let alice_change_v_comm = PedersenCommitment::commit(
        &params,
        alice_change_value,
        &PedersenRandomness { r: alice_change_randomness },
    );
    
    // Compute lineage for Alice's change
    let alice_change_lineage = poseidon_hash(&[mint_note.lineage_hash, F::from(1u64)]);
    
    let mut alice_change = Note::new(
        asset_type,
        alice_change_v_comm,
        alice_addr,
        [3u8; 32],
        1,
    );
    alice_change.compliance_hash = F::from(1u64);
    alice_change.callbacks_hash = F::from(1u64);
    alice_change.lineage_hash = alice_change_lineage;
    alice_change.memo_hash = F::from(0u64);
    
    // Get append witnesses BEFORE appending
    let bob_cm = bob_note.commitment();
    let alice_change_cm = alice_change.commitment();
    let bob_append_witness = ctx.cmt_tree.generate_append_witness(bob_cm);
    ctx.cmt_tree.append(bob_cm);
    let alice_change_append_witness = ctx.cmt_tree.generate_append_witness(alice_change_cm);
    ctx.cmt_tree.append(alice_change_cm);
    
    // Get new CMT root after appends
    let cmt_root_new_transfer = ctx.cmt_tree.root();
    
    // Insert nullifier and get witness
    let alice_insert_witness_core = ctx.nft_tree.insert_with_witness(alice_nf).unwrap();
    let alice_insert_witness = SortedInsertWitness {
        target: alice_insert_witness_core.target,
        range_proof: alice_insert_witness_core.range_proof,
        new_leaf: alice_insert_witness_core.new_leaf,
        updated_pred_leaf: alice_insert_witness_core.updated_pred_leaf,
        new_leaf_path: alice_insert_witness_core.new_leaf_path,
        pred_update_path: alice_insert_witness_core.pred_update_path,
        height: alice_insert_witness_core.height,
    };
    let nft_root_new_transfer = ctx.nft_tree.root();
    
    // Create transfer circuit
    let transfer_circuit = TransferCircuit {
        notes_in: vec![mint_note.clone()],
        values_in: vec![mint_value],
        value_randomness_in: vec![mint_randomness],
        notes_out: vec![bob_note.clone(), alice_change.clone()],
        values_out: vec![bob_value, alice_change_value],
        value_randomness_out: vec![bob_randomness, alice_change_randomness],
        nks: vec![alice_nk],
        owner_sks: vec![alice_sk],
        owner_pks: vec![(alice_pk_x, alice_pk_y)],
        cm_paths: vec![alice_cm_path],
        nf_nonmembership_proofs: vec![Some(alice_nm_proof.clone())],
        sanctions_nm_proofs_in: vec![None],
        sanctions_nm_proofs_out: vec![None, None],
        cmt_paths_out: vec![],
        nf_nonmembership: vec![Some(alice_nm_proof)],
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out: vec![bob_append_witness, alice_change_append_witness],
        nf_insert_witnesses: vec![alice_insert_witness],
        cmt_root_old: cmt_root_old_transfer,
        cmt_root_new: cmt_root_new_transfer,
        nft_root_old: nft_root_old_transfer,
        nft_root_new: nft_root_new_transfer,
        sanctions_root: F::from(555u64),
        pool_rules_root: F::from(666u64),
        nf_list: vec![alice_nf],
        cm_list: vec![bob_cm, alice_change_cm],
        fee: Amount::from(10u128),
    };
    
    // Test transfer constraints
    let cs_transfer = ConstraintSystem::<F>::new_ref();
    transfer_circuit.generate_constraints(cs_transfer.clone())
        .expect("Transfer constraint generation failed");
    
    if !cs_transfer.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs_transfer.which_is_unsatisfied() {
            panic!("Transfer: Unsatisfied constraint: {}", unsat);
        }
    }
    println!("✅ Transfer constraints satisfied ({} constraints)", cs_transfer.num_constraints());
    
    // ========== STEP 3: BURN (Bob burns his note) ==========
    println!("\nStep 3: Testing Burn constraints");
    
    // Bob's note is now in the tree
    let bob_cm_path = ctx.cmt_tree.get_proof(bob_cm).unwrap();
    
    // Bob's keys
    let bob_nk = F::from(321u64);
    let (bob_pk_x, bob_pk_y) = get_pk_coords_circuit_compatible(bob_sk);
    
    // Compute Bob's nullifier
    let bob_nf = bob_note.nullifier(&bob_nk);
    
    // Store old roots BEFORE tree modifications
    let cmt_root_burn = ctx.cmt_tree.root(); // No change for burn
    let nft_root_old_burn = ctx.nft_tree.root();
    let exit_root_old = ctx.exit_tree.root();
    
    // Get non-membership proof BEFORE insertion
    let bob_nm_proof = ctx.nft_tree.prove_non_membership(bob_nf).unwrap();
    
    // Create exit receipt
    let exit_receipt = ExitReceipt::new(
        asset_type,
        Amount::from(bob_value as u128),
        bob_nf,
        1,
    );
    
    // Get append witness for exit tree BEFORE appending
    let exit_hash = exit_receipt.hash();
    let exit_append_witness = ctx.exit_tree.generate_append_witness(exit_hash);
    ctx.exit_tree.append(exit_hash);
    let exit_root_new = ctx.exit_tree.root();
    
    // Insert Bob's nullifier
    let bob_insert_witness_core = ctx.nft_tree.insert_with_witness(bob_nf).unwrap();
    let bob_insert_witness = SortedInsertWitness {
        target: bob_insert_witness_core.target,
        range_proof: bob_insert_witness_core.range_proof,
        new_leaf: bob_insert_witness_core.new_leaf,
        updated_pred_leaf: bob_insert_witness_core.updated_pred_leaf,
        new_leaf_path: bob_insert_witness_core.new_leaf_path,
        pred_update_path: bob_insert_witness_core.pred_update_path,
        height: bob_insert_witness_core.height,
    };
    let nft_root_new_burn = ctx.nft_tree.root();
    
    // Create burn circuit
    let burn_circuit = BurnCircuit {
        note_in: bob_note.clone(),
        value_in: bob_value,
        value_randomness_in: bob_randomness,
        owner_sk: bob_sk,
        owner_pk_x: bob_pk_x,
        owner_pk_y: bob_pk_y,
        nk: bob_nk,
        cm_path: bob_cm_path,
        nf_nonmembership: Some(bob_nm_proof),
        nf_insert_witness: Some(bob_insert_witness),
        exit_receipt,
        exit_append_witness,
        cmt_root: cmt_root_burn,
        nft_root_old: nft_root_old_burn,
        nft_root_new: nft_root_new_burn,
        exit_root_old,
        exit_root_new,
        asset_type,
        amount: Amount::from(bob_value as u128),
        nf_in: bob_nf,
    };
    
    // Test burn constraints
    let cs_burn = ConstraintSystem::<F>::new_ref();
    burn_circuit.generate_constraints(cs_burn.clone())
        .expect("Burn constraint generation failed");
    
    if !cs_burn.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs_burn.which_is_unsatisfied() {
            panic!("Burn: Unsatisfied constraint: {}", unsat);
        }
    }
    println!("✅ Burn constraints satisfied ({} constraints)", cs_burn.num_constraints());
    
    // Update supply
    let burn_amount = Amount::from(bob_value as u128);
    let current = ctx.supply.get(&asset_type).unwrap_or(&Amount::from(0u128)).value();
    let new_amount = Amount::from(current.saturating_sub(bob_value as u128));
    ctx.supply.insert(asset_type, new_amount);
    
    // Final supply check
    let final_supply = ctx.supply.get(&asset_type).copied().unwrap_or(Amount::from(0u128));
    let expected_supply = Amount::from((mint_value - bob_value) as u128);
    assert_eq!(final_supply, expected_supply, "Supply mismatch after burn");
    
    println!("\n=== ✅ All E2E constraint tests passed! ===");
    println!("Final supply: {} units", final_supply.value());
}

#[test]
fn test_object_update_constraints() {
    println!("\n=== Testing Object Update constraints ===\n");
    
    let mut ctx = TestContext::new();
    
    // Create initial compliance state
    let state_old = ComplianceState::new_verified(1);
    let state_new = ComplianceState {
        level: 2,
        ..state_old.clone()
    };
    
    // Create old object
    let obj_old = ZkObject {
        state_hash: state_old.hash(),
        serial: 100,
        cb_head_hash: F::from(0),
    };
    
    // Create new object with incremented serial
    let obj_new = ZkObject {
        state_hash: state_new.hash(),
        serial: 101,
        cb_head_hash: F::from(0),
    };
    
    // Add old object to tree with deterministic randomness
    let obj_old_randomness = F::from(1u64);
    let obj_old_cm = obj_old.commitment_with_randomness(&obj_old_randomness);
    let obj_path_old = ctx.obj_tree.get_proof(obj_old_cm).unwrap_or_else(|| {
        // If not in tree, add it first
        ctx.obj_tree.append(obj_old_cm);
        ctx.obj_tree.get_proof(obj_old_cm).unwrap()
    });
    
    // Store old root before any changes
    let obj_root_old = ctx.obj_tree.root();
    
    // Get append witness for new object BEFORE appending with deterministic randomness
    let obj_new_randomness = F::from(2u64);
    let obj_new_cm = obj_new.commitment_with_randomness(&obj_new_randomness);
    let obj_append_witness = ctx.obj_tree.generate_append_witness(obj_new_cm);
    ctx.obj_tree.append(obj_new_cm);
    let obj_root_new = ctx.obj_tree.root();
    
    // Create circuit
    let circuit = ObjectUpdateCircuit {
        obj_old: obj_old.clone(),
        state_old: state_old.clone(),
        obj_new: obj_new.clone(),
        state_new: state_new.clone(),
        callback_entry: None,
        callback_invocation: None,
        callback_signature: None,
        cb_path: None,
        cb_nonmembership: None,
        obj_path_old,
        obj_append_witness: Some(obj_append_witness),
        obj_old_randomness,
        obj_new_randomness,
        decrypt_key: None,
        obj_root_old,
        obj_root_new,
        cb_root: F::from(777u64),
        current_time: 1000,
    };
    
    // Test constraints
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs.clone())
        .expect("ObjectUpdate constraint generation failed");
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            panic!("ObjectUpdate: Unsatisfied constraint: {}", unsat);
        }
    }
    println!("✅ ObjectUpdate constraints satisfied ({} constraints)", cs.num_constraints());
}