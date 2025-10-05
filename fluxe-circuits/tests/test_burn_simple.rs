use ark_bn254::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_std::rand::thread_rng;

use fluxe_circuits::burn::BurnCircuit;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_core::{
    data_structures::{Note, ExitReceipt},
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{SortedTree, IncrementalTree},
    types::Amount,
};

#[test]
fn test_burn_circuit_simple() {
    let rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    
    let value = 500u64;
    // Use non-zero randomness to avoid infinity point
    let randomness = F::from(42u64);
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    // Use specific parameters that work with our sorted insert gadget
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (owner_pk_x, owner_pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    
    println!("owner_sk: {:?}", owner_sk);
    println!("owner_addr: {:?}", owner_addr);
    println!("owner_pk_x: {:?}", owner_pk_x);
    println!("owner_pk_y: {:?}", owner_pk_y);
    
    // Use specific psi bytes
    let psi_bytes = [7u8; 32];
    let mut note_in = Note::new(1, v_comm, owner_addr, psi_bytes, 1);
    // Set fields to match successful test
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64); 
    note_in.lineage_hash = F::from(1u64);
    note_in.memo_hash = F::from(0u64);
    
    let nk = F::from(456u64);
    let nf = note_in.nullifier(&nk);
    let exit_receipt = ExitReceipt::new(1, Amount::from(value as u128), nf, 1);
    
    // Setup commitment tree and add the note
    let mut cmt_tree = IncrementalTree::new(16);
    let cm = note_in.commitment();
    cmt_tree.append(cm);
    let cmt_root = cmt_tree.root();
    let path = cmt_tree.get_path(0).expect("Should get path");
    
    // Setup nullifier tree with sentinel
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel
    let nft_root_old = nft_tree.root();
    
    // Get non-membership proof and insert witness
    let nm_proof = nft_tree.prove_non_membership(nf).expect("Should prove non-membership");
    let insert_witness_core = nft_tree.insert_with_witness(nf).expect("Should insert with witness");
    let nft_root_new = nft_tree.root();
    
    // Convert core witness to circuit witness
    let insert_witness = fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    // Setup exit tree
    let mut exit_tree = IncrementalTree::new(16);
    let exit_root_old = exit_tree.root();
    let exit_append_witness = exit_tree.generate_append_witness(exit_receipt.hash());
    exit_tree.append(exit_receipt.hash());
    let exit_root_new = exit_tree.root();
    
    let burn_circuit = BurnCircuit {
        note_in,
        value_in: value,
        value_randomness_in: randomness,
        owner_sk,
        owner_pk_x,
        owner_pk_y,
        nk,
        cm_path: path,
        nf_nonmembership: Some(nm_proof),
        nf_insert_witness: Some(insert_witness),
        exit_receipt: exit_receipt.clone(),
        exit_append_witness,
        cmt_root,
        nft_root_old,
        nft_root_new,
        exit_root_old,
        exit_root_new,
        asset_type: 1,
        amount: Amount::from(value as u128),
        nf_in: nf,
    };
    
    // Test constraint generation
    let cs = ConstraintSystem::<F>::new_ref();
    
    burn_circuit.generate_constraints(cs.clone()).expect("Constraint generation should succeed");
    
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            println!("❌ Unsatisfied constraint: {}", unsat);
            println!("Total constraints: {}", cs.num_constraints());
        }
        panic!("Constraints should be satisfied");
    }
}