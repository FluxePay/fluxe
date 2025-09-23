use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

use fluxe_circuits::transfer::TransferCircuit;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_core::{
    data_structures::Note,
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    crypto::poseidon_hash,
    merkle::{IncrementalTree, SortedTree},
    types::Amount,
};
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;

#[test]
fn test_analyze_constraint_failure() {
    println!("\n=== Analyzing Constraint Failure ===\n");
    
    let params = PedersenParams::setup_value_commitment();
    
    // Setup trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    
    // Store the initial NFT root
    let nft_root_initial = nft_tree.root();
    println!("Initial NFT root: {:?}", nft_root_initial);
    
    // Create input note
    let value_in = 100u64;
    let randomness_in = F::from(42u64);
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );
    
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    
    let nk = F::from(456u64);
    let mut note_in = Note::new(1, v_comm_in, owner_addr, [7u8; 32], 1);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.lineage_hash = F::from(1u64);
    note_in.memo_hash = F::from(0u64);
    
    let cm_in = note_in.commitment();
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();
    let cmt_root_old = cmt_tree.root();
    
    let nf = note_in.nullifier(&nk);
    
    // IMPORTANT: The NFT root when we generate the non-membership proof
    let nft_root_old = nft_tree.root();
    println!("NFT root before any insertion (for non-membership): {:?}", nft_root_old);
    
    // Get non-membership proof BEFORE insertion
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    
    // Now insert and get witness
    let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    println!("NFT root after insertion: {:?}", nft_root_new);
    
    // Verify the witness computes the correct new root
    let tree_params = fluxe_core::merkle::TreeParams::new(insert_witness_core.height);
    let computed_new_root = insert_witness_core.compute_new_root(&tree_params);
    println!("Computed new root from witness: {:?}", computed_new_root);
    
    if computed_new_root != nft_root_new {
        println!("❌ ERROR: Computed root doesn't match actual root!");
        println!("This is likely the cause of constraint 54388");
    } else {
        println!("✅ Computed root matches actual root");
    }
    
    // Create output note
    let value_out = 90u64;
    let randomness_out = F::from(99u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let expected_lineage = poseidon_hash(&[note_in.lineage_hash, F::from(0u64)]);
    let mut note_out = Note::new(1, v_comm_out, F::from(789u64), [8u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = expected_lineage;
    note_out.memo_hash = F::from(0u64);
    
    let cm_out = note_out.commitment();
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();
    
    // Create the insert witness
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    // Debug: Check all the witness values
    println!("\n--- Witness Details ---");
    println!("Target (nullifier): {:?}", insert_witness.target);
    println!("Target matches nf: {}", insert_witness.target == nf);
    
    // Check the roots being passed to the circuit
    println!("\n--- Roots being used ---");
    println!("nft_root_old (passed to circuit): {:?}", nft_root_old);
    println!("nft_root_new (passed to circuit): {:?}", nft_root_new);
    println!("nft_root_initial (tree creation): {:?}", nft_root_initial);
    
    // Create circuit with the exact same values
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
        nft_root_old,  // This should be the root BEFORE insertion
        nft_root_new,  // This should be the root AFTER insertion
        sanctions_root: F::from(555u64),
        pool_rules_root: F::from(666u64),
        nf_list: vec![nf],
        cm_list: vec![cm_out],
        fee: Amount::from(10u128),
    };
    
    // Generate constraints
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("Should generate constraints");
    
    println!("\nTotal constraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ Unsatisfied constraint: {}", unsat);
            
            // Try to understand where constraint 54388 is
            let total = cs.num_constraints();
            let percentage = (54388.0 / total as f64) * 100.0;
            println!("Constraint 54388 is at {:.1}% of {} total constraints", percentage, total);
        }
    } else {
        println!("✅ All constraints satisfied!");
    }
}