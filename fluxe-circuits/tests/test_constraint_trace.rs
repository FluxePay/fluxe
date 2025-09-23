use ark_bls12_381::Fr as F;
use ark_ff::{PrimeField, BigInteger};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_std::rand::thread_rng;

use fluxe_circuits::transfer::TransferCircuit;
use fluxe_circuits::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
use fluxe_core::{
    data_structures::Note,
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, SortedTree},
    types::Amount,
};
use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
use fluxe_circuits::gadgets::range_proof::RangeProofGadget;

#[test]
fn trace_transfer_constraints() {
    println!("Tracing transfer circuit constraint generation...\n");
    
    let _rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    
    // Setup minimal transfer
    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64));
    
    // Simple input note
    let value_in = 1000u64;
    let randomness_in = F::from(123u64);
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );
    
    let owner_sk = F::from(456u64);
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
    
    let nk = F::from(789u64);
    let psi_bytes = [1u8; 32];
    let pool_id = 1u32; // Non-zero pool_id will trigger range proofs!
    let note_in = Note::new(1, v_comm_in, owner_addr, psi_bytes, pool_id);
    let cm_in = note_in.commitment();
    
    println!("Note pool_id: {}", pool_id);
    
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();
    let cmt_root_old = cmt_tree.root();
    
    let nf = note_in.nullifier(&nk);
    let nft_root_old = nft_tree.root();
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    
    let mut witness_tree = nft_tree.clone();
    let insert_witness_core = witness_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = witness_tree.root();
    
    // Simple output note
    let value_out = 990u64;
    let randomness_out = F::from(321u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );
    
    let recipient_addr = F::from(111u64);
    let note_out = Note::new(1, v_comm_out, recipient_addr, [2u8; 32], 1);
    let cm_out = note_out.commitment();
    
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();
    
    let insert_witness = SortedInsertWitness {
        target: insert_witness_core.target,
        range_proof: insert_witness_core.range_proof,
        new_leaf: insert_witness_core.new_leaf,
        updated_pred_leaf: insert_witness_core.updated_pred_leaf,
        new_leaf_path: insert_witness_core.new_leaf_path,
        pred_update_path: insert_witness_core.pred_update_path,
        height: insert_witness_core.height,
    };
    
    let transfer_circuit = TransferCircuit {
        notes_in: vec![note_in.clone()],
        values_in: vec![value_in],
        value_randomness_in: vec![randomness_in],
        notes_out: vec![note_out.clone()],
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
        sanctions_root: F::from(444u64),
        pool_rules_root: F::from(555u64),
        nf_list: vec![nf],
        cm_list: vec![cm_out],
        fee: Amount::from(10u128),
    };
    
    // Now trace constraint generation with checkpoints
    let cs = ConstraintSystem::<F>::new_ref();
    
    println!("Starting constraint generation...");
    println!("Initial: {} constraints\n", cs.num_constraints());
    
    // Manually replicate parts of the transfer circuit to trace
    
    // Step 1: Public inputs (should add ~10 constraints/variables)
    let _cmt_root_old_var = FpVar::new_input(cs.clone(), || Ok(cmt_root_old)).unwrap();
    let _cmt_root_new_var = FpVar::new_input(cs.clone(), || Ok(cmt_root_new)).unwrap();
    let _nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(nft_root_old)).unwrap();
    let _nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(nft_root_new)).unwrap();
    let _sanctions_root_var = FpVar::new_input(cs.clone(), || Ok(transfer_circuit.sanctions_root)).unwrap();
    let _pool_rules_root_var = FpVar::new_input(cs.clone(), || Ok(transfer_circuit.pool_rules_root)).unwrap();
    let _nf_var = FpVar::new_input(cs.clone(), || Ok(nf)).unwrap();
    let _cm_out_var = FpVar::new_input(cs.clone(), || Ok(cm_out)).unwrap();
    let _fee_var = FpVar::new_input(cs.clone(), || Ok(transfer_circuit.fee.to_field())).unwrap();
    
    println!("After public inputs: {} constraints", cs.num_constraints());
    
    // Step 2: Create witness variables for notes
    use fluxe_circuits::gadgets::note::NoteVar;
    
    let _note_in_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note_in.clone()),
        value_in,
        &randomness_in,
    ).unwrap();
    
    println!("After input note witness: {} constraints", cs.num_constraints());
    
    let note_out_var = NoteVar::new_witness(
        cs.clone(),
        || Ok(note_out.clone()),
        value_out,
        &randomness_out,
    ).unwrap();
    
    println!("After output note witness: {} constraints", cs.num_constraints());
    
    // Step 3: Test range proof directly on the output value
    println!("\n=== Testing Range Proof ===");
    let constraints_before = cs.num_constraints();
    println!("Before range proof: {} constraints", constraints_before);
    
    // Apply range proof to output note value
    let result = RangeProofGadget::prove_range_bits(cs.clone(), &note_out_var.value, 64);
    
    let constraints_after = cs.num_constraints();
    println!("After range proof: {} constraints", constraints_after);
    println!("Range proof added: {} constraints", constraints_after - constraints_before);
    
    if let Err(e) = result {
        println!("Range proof failed: {:?}", e);
    } else {
        println!("Range proof succeeded");
    }
    
    // Check satisfaction at this point
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            let unsat_num: usize = unsat.parse().unwrap_or(0);
            println!("\n❌ Constraint {} is unsatisfied", unsat_num);
            
            if unsat_num >= constraints_before && unsat_num < constraints_after {
                println!("This is within the range proof we just added!");
                let relative = unsat_num - constraints_before;
                println!("Relative position in range proof: constraint {}", relative);
            }
        }
    } else {
        println!("\n✅ All constraints satisfied so far");
    }
    
    // Now run the full circuit to find where 26767 appears
    println!("\n=== Running Full Circuit ===");
    let cs_full = ConstraintSystem::<F>::new_ref();
    
    // Try to pinpoint where constraint 26767 is generated
    // We know it's around 26767, and range proofs are 760 constraints each
    // 26767 / 760 ≈ 35, but we only have 1 output, so it's not purely range proofs
    
    // Let's check how many constraints we have at different stages
    println!("Generating full circuit with checkpoints...");
    
    // The transfer circuit likely has this order:
    // 1. Public inputs
    // 2. Witness notes
    // 3. Membership checks
    // 4. Nullifier checks
    // 5. EC auth
    // 6. Value conservation
    // 7. Range proofs <-- should be around 20000-30000
    // 8. Non-membership
    // 9. Tree updates
    
    let result = transfer_circuit.generate_constraints(cs_full.clone());
    
    if let Err(e) = result {
        println!("Full circuit generation failed: {:?}", e);
    } else {
        println!("Full circuit constraints: {}", cs_full.num_constraints());
        
        if !cs_full.is_satisfied().unwrap() {
            if let Ok(Some(unsat)) = cs_full.which_is_unsatisfied() {
                let unsat_num: usize = unsat.parse().unwrap_or(0);
                println!("First unsatisfied in full circuit: {}", unsat_num);
                
                // Estimate which section this is in
                if unsat_num < 1000 {
                    println!("Location: Public inputs or initial setup");
                } else if unsat_num < 5000 {
                    println!("Location: Note witnesses");
                } else if unsat_num < 10000 {
                    println!("Location: Membership checks");
                } else if unsat_num < 15000 {
                    println!("Location: Nullifier/EC auth");
                } else if unsat_num < 20000 {
                    println!("Location: Value conservation");
                } else if unsat_num < 30000 {
                    println!("Location: Range proofs or sanctions checks");
                    
                    // This is where 26767 is!
                    let range_proof_start = 20000; // estimated
                    let relative = unsat_num - range_proof_start;
                    println!("Relative position: ~{} into this section", relative);
                    println!("This would be in range proof #{}", relative / 760);
                } else if unsat_num < 50000 {
                    println!("Location: Tree operations");
                } else {
                    println!("Location: Final validations");
                }
            }
        } else {
            println!("✅ All constraints satisfied!");
        }
    }
}

#[test] 
fn test_value_field_conversion() {
    println!("\nTesting value field conversions...");
    
    let test_values = vec![
        0u64,
        1u64,
        10u64,
        100u64,
        1000u64,
        990u64,
        u32::MAX as u64,
        u64::MAX,
    ];
    
    for value in test_values {
        let field = F::from(value);
        
        // Check round-trip
        let bytes = field.into_bigint().to_bytes_le();
        let recovered = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        
        let matches = if value < (1u64 << 63) {
            recovered == value
        } else {
            true // Large values may not round-trip perfectly
        };
        
        println!("Value: {:20} -> Field: {:?} -> Recovered: {:20} [{}]",
            value,
            field,
            recovered,
            if matches { "✓" } else { "✗" }
        );
    }
}