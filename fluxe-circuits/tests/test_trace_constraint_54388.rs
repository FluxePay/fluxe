use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use fluxe_circuits::transfer::TransferCircuit;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_core::{
    Note, Amount,
    merkle::{IncrementalTree, SortedTree},
    crypto::{PedersenParams, PedersenCommitment, PedersenRandomness, poseidon_hash},
};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn test_trace_constraint_54388() {
    println!("\n=== Tracing Constraint 54388 ===\n");
    
    // Use exact same setup as test_simple_working
    let rng = StdRng::seed_from_u64(12345);
    
    // Setup parameters exactly like test_simple_working
    let owner_sk = F::from(123u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    let nk = F::from(456u64); // Note: test_simple_working uses 456, not 111!
    
    // Create trees
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel - CRITICAL FOR MATCHING test_simple_working!
    
    // Create input note
    let params = PedersenParams::setup_value_commitment();
    let value_in = 100u64;
    let randomness_in = F::from(42u64); // MUST be 42 to match test_simple_working!
    let v_comm_in = PedersenCommitment::commit(&params, value_in, &PedersenRandomness { r: randomness_in });
    
    let psi_bytes = [7u8; 32];
    let mut note_in = Note::new(1, v_comm_in, owner_addr, psi_bytes, 1);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.lineage_hash = F::from(1u64);  // Changed from 2 to 1 to match test_simple_working
    note_in.memo_hash = F::from(0u64);
    
    // Add to commitment tree
    let cm_in = note_in.commitment();
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();  // Changed to get_proof to match test_simple_working
    let cmt_root_old = cmt_tree.root();
    
    // Get nullifier
    let nf = note_in.nullifier(&nk);
    let nft_root_old = nft_tree.root();
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();
    
    // Create output note
    let value_out = 90u64;
    let randomness_out = F::from(99u64); // Same as test_simple_working
    let v_comm_out = PedersenCommitment::commit(&params, value_out, &PedersenRandomness { r: randomness_out });
    
    let recipient_addr = F::from(789u64);
    let expected_lineage = poseidon_hash(&[note_in.lineage_hash, F::from(0u64)]);
    
    println!("Debug values:");
    println!("  owner_addr: {:?}", owner_addr);
    println!("  nf: {:?}", nf);
    println!("  cm_in: {:?}", cm_in);
    println!("  expected_lineage: {:?}", expected_lineage);
    
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
    
    // Convert witness
    let insert_witness = fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    // Create circuit exactly like test_simple_working
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
    
    // Create constraint system and generate constraints
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Add a hook to track when we hit constraint 54388
    let last_count = 0;
    let target = 54388;
    
    println!("Generating constraints...");
    match circuit.generate_constraints(cs.clone()) {
        Ok(_) => {
            let total = cs.num_constraints();
            println!("Total constraints: {}", total);
            
            if !cs.is_satisfied().unwrap() {
                if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                    println!("❌ Unsatisfied constraint: {}", unsat);
                    
                    if unsat == "54388" {
                        println!("\n=== Found constraint 54388! ===");
                        println!("This is the failing constraint");
                        
                        // Try to understand what this constraint represents
                        let percentage = (54388.0 / total as f64) * 100.0;
                        println!("Position: {:.2}% through {} total constraints", percentage, total);
                        
                        // Calculate which section this is likely in
                        // We know sorted insert generates ~29k constraints
                        // And it's at 77% position, so it's likely IN the sorted insert section
                        let sorted_insert_start = total - 29246; // Approximate
                        let position_in_insert = 54388 - sorted_insert_start;
                        println!("Likely position in sorted insert: constraint {}", position_in_insert);
                        
                        // That would be around constraint 25k in the sorted insert
                        // which is near the end (29k total), so it's likely in the
                        // structural verification section
                    }
                }
            } else {
                println!("✅ All constraints satisfied!");
            }
        }
        Err(e) => {
            println!("❌ Failed to generate constraints: {:?}", e);
        }
    }
}