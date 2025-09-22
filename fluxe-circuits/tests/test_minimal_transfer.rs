use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

use fluxe_circuits::transfer::TransferCircuit;
use fluxe_core::{
    Note, Amount,
    merkle::{IncrementalTree, SortedTree},
    crypto::{PedersenCommitment, PedersenParams, PedersenRandomness, poseidon_hash, domain_sep_to_field, DOM_NF},
};

#[test]
fn test_minimal_transfer() {
    println!("\n=== Testing Minimal Transfer Circuit ===\n");
    
    // Setup minimal state
    let owner_sk = F::from(123u64);
    let pk_x = F::from(456u64);
    let pk_y = F::from(789u64);
    let owner_addr = poseidon_hash(&vec![pk_x, pk_y]);
    let nk = F::from(111u64);
    
    // Create trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    
    // Create a single input note with minimal values
    let params = PedersenParams::setup_value_commitment();
    let value_in = 100u64;
    let randomness_in = F::from(1u64); // Non-zero to avoid infinity
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );
    
    let mut note_in = Note::new(1, v_comm_in, owner_addr, [0u8; 32], 1);
    note_in.lineage_hash = F::from(1u64);
    
    // Add to commitment tree
    let cm_in = note_in.commitment();
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_path(0).unwrap();  // Get path for first element
    let cmt_root_old = cmt_tree.root();
    
    // Compute nullifier
    let nf = poseidon_hash(&vec![
        domain_sep_to_field(DOM_NF),
        nk,
        F::from(0u64), // psi
        cm_in,
    ]);
    
    // Get nullifier witnesses BEFORE any insertions
    let nft_root_old = nft_tree.root();
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    let insert_witness = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    
    // Create minimal output
    let value_out = 90u64;
    let randomness_out = F::from(1u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let mut note_out = Note::new(1, v_comm_out, F::from(999u64), [0u8; 32], 1);
    note_out.lineage_hash = poseidon_hash(&vec![note_in.lineage_hash, F::from(0u64)]);
    
    // Add output to commitment tree
    let cm_out = note_out.commitment();
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();
    
    // Convert witnesses to circuit format
    let circuit_insert_witness = fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
        target: insert_witness.target,
        range_proof: insert_witness.range_proof,
        new_leaf: insert_witness.new_leaf,
        updated_pred_leaf: insert_witness.updated_pred_leaf,
        new_leaf_path: insert_witness.new_leaf_path,
        pred_update_path: insert_witness.pred_update_path,
        height: insert_witness.height,
    };
    
    // Create the minimal circuit
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
        nf_insert_witnesses: vec![circuit_insert_witness],
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        sanctions_root: F::from(0u64),
        pool_rules_root: F::from(0u64),
        nf_list: vec![nf],
        cm_list: vec![cm_out],
        fee: Amount::from(10u128),
    };
    
    // Test constraint generation with detailed tracking
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("Starting constraint generation...");
    let initial = cs.num_constraints();
    println!("Initial constraints: {}", initial);
    
    match circuit.generate_constraints(cs.clone()) {
        Ok(_) => {
            println!("Constraint generation succeeded!");
            println!("Total constraints: {}", cs.num_constraints());
            
            if !cs.is_satisfied().unwrap() {
                if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                    println!("❌ Unsatisfied constraint: {}", unsat);
                    
                    // Calculate position
                    let total = cs.num_constraints();
                    if let Ok(num) = unsat.parse::<usize>() {
                        let percentage = (num as f64 / total as f64) * 100.0;
                        println!("Position: {:.2}% through {} total constraints", percentage, total);
                    }
                } else {
                    println!("❌ Constraints unsatisfied but couldn't identify which one");
                }
            } else {
                println!("✅ All constraints satisfied!");
            }
        }
        Err(e) => {
            println!("❌ Constraint generation failed: {:?}", e);
        }
    }
}