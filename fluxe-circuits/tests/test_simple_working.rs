use ark_bn254::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_std::rand::{SeedableRng, rngs::StdRng};

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
fn test_simplest_possible_transfer() {
    println!("\n=== Testing simplest possible 1-1 transfer ===\n");
    
    // Use deterministic randomness
    let rng = StdRng::seed_from_u64(12345);
    let params = PedersenParams::setup_value_commitment();
    
    // Setup trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    
    // Create input note with specific values
    let value_in = 100u64;
    let randomness_in = F::from(42u64); // Non-zero
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );
    
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    
    let nk = F::from(456u64);
    let psi_bytes = [7u8; 32];
    
    let mut note_in = Note::new(1, v_comm_in, owner_addr, psi_bytes, 1);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.lineage_hash = F::from(1u64);
    note_in.memo_hash = F::from(0u64);
    
    // Add to commitment tree
    let cm_in = note_in.commitment();
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();
    let cmt_root_old = cmt_tree.root();
    
    // Generate nullifier
    let nf = note_in.nullifier(&nk);
    let nft_root_old = nft_tree.root();
    
    // Get non-membership proof BEFORE insertion
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    
    // Insert and get witness
    let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    
    // Create output note
    let value_out = 90u64; // 100 - 10 fee
    let randomness_out = F::from(99u64); // Non-zero
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let recipient_addr = F::from(789u64);
    
    // Compute lineage for output
    let expected_lineage = poseidon_hash(&[note_in.lineage_hash, F::from(0u64)]);
    
    println!("Debug values:");
    println!("  owner_addr: {:?}", owner_addr);
    println!("  nf: {:?}", nf);
    println!("  cm_in: {:?}", cm_in);
    println!("  expected_lineage: {:?}", expected_lineage);
    println!("  nft_root_old: {:?}", nft_root_old);
    println!("  nft_root_new: {:?}", nft_root_new);
    
    let mut note_out = Note::new(1, v_comm_out, recipient_addr, [8u8; 32], 1);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.lineage_hash = expected_lineage;
    note_out.memo_hash = F::from(0u64);
    
    // Add output to commitment tree
    let cm_out = note_out.commitment();
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();
    
    // Also compute what the new root SHOULD be according to the witness (before conversion)
    let tree_params_core = fluxe_core::merkle::TreeParams::new(insert_witness_core.height);
    let computed_new_root_core = insert_witness_core.compute_new_root(&tree_params_core);
    println!("  computed_new_root from core witness: {:?}", computed_new_root_core);
    
    // Convert witness
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    // Now compute what the new root SHOULD be according to the witness
    let tree_params = fluxe_core::merkle::TreeParams::new(insert_witness.height);
    let computed_new_root = insert_witness.compute_new_root(&tree_params);
    println!("  computed_new_root from witness: {:?}", computed_new_root);
    
    // Debug the witness paths
    println!("  new_leaf_path.leaf: {:?}", insert_witness.new_leaf_path.leaf);
    println!("  new_leaf_path.leaf_index: {:?}", insert_witness.new_leaf_path.leaf_index);
    println!("  new_leaf.hash(): {:?}", insert_witness.new_leaf.hash());
    println!("  pred_update_path.leaf: {:?}", insert_witness.pred_update_path.leaf);
    println!("  pred_update_path.leaf_index: {:?}", insert_witness.pred_update_path.leaf_index);
    println!("  range_proof.low_leaf.hash(): {:?}", insert_witness.range_proof.low_leaf.hash());
    
    if nft_root_new != computed_new_root {
        println!("  ERROR: nft_root_new != computed_new_root!");
        println!("  Expected: {:?}", nft_root_new);
        println!("  Got: {:?}", computed_new_root);
    }
    
    // Create circuit
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
        sanctions_root: F::from(555u64),
        pool_rules_root: F::from(666u64),
        nf_list: vec![nf],
        cm_list: vec![cm_out],
        fee: Amount::from(10u128),
    };
    
    // Test constraints
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("Should generate constraints");
    
    println!("Constraints: {}", cs.num_constraints());
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            panic!("Unsatisfied constraint: {}", unsat);
        }
    }
    
    println!("✅ Simple 1-1 transfer works!");
    
    // Skip setup test - would need to recreate all the witness data
}