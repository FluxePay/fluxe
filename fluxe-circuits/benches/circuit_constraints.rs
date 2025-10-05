use criterion::{criterion_group, criterion_main, Criterion};
use ark_bn254::Fr as F;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_ff::{UniformRand, PrimeField};
use ark_std::rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use fluxe_circuits::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
    utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible},
};
use fluxe_core::{
    data_structures::{Note, IngressReceipt, ExitReceipt, ComplianceState, ZkObject},
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, MerklePath},
    types::*,
};

/// Circuit statistics
#[derive(Debug, Clone)]
struct CircuitStats {
    num_constraints: usize,
    num_public_inputs: usize,
    num_private_inputs: usize,
    num_linear_combinations: usize,
}

impl CircuitStats {
    fn from_constraint_system(cs: &ConstraintSystem<F>) -> Self {
        Self {
            num_constraints: cs.num_constraints,
            num_public_inputs: cs.instance_assignment.len() - 1, // minus 1 for the "one" variable
            num_private_inputs: cs.witness_assignment.len(),
            num_linear_combinations: cs.num_constraints + cs.instance_assignment.len() + cs.witness_assignment.len(),
        }
    }
    
    fn print_summary(&self, circuit_name: &str) {
        println!("\n{} Circuit Statistics:", circuit_name);
        println!("  Constraints:         {:>8}", self.num_constraints);
        println!("  Public inputs:       {:>8}", self.num_public_inputs);
        println!("  Private inputs:      {:>8}", self.num_private_inputs);
        println!("  Linear combinations: {:>8}", self.num_linear_combinations);
        println!("  Total variables:     {:>8}", self.num_public_inputs + self.num_private_inputs);
    }
}

fn create_mint_circuit<R: RngCore>(rng: &mut R) -> MintCircuit {
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

fn create_burn_circuit<R: RngCore>(rng: &mut R) -> BurnCircuit {
    use fluxe_core::merkle::SortedTree;
    use fluxe_core::crypto::poseidon::poseidon_hash;
    use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
    
    let params = PedersenParams::setup_value_commitment();
    let value = 500u64;
    let randomness = F::rand(rng);
    
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    // Generate owner key pair and compute the exact address the circuit will derive
    let owner_sk = F::rand(rng);
    // Use circuit-compatible conversion method
    let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
    let (pk_x_fr, pk_y_fr) = get_pk_coords_circuit_compatible(owner_sk);
    
    // Generate nullifier key
    let nk = F::rand(rng);
    
    // Create note with proper psi
    let psi_bytes = [42u8; 32]; // Use deterministic value for benchmarking
    let note_in = Note::new(1, v_comm, owner_addr, psi_bytes, 1);
    
    // Compute the actual nullifier
    let cm_in = note_in.commitment();
    let psi = F::from_le_bytes_mod_order(&psi_bytes);
    let nf_in = poseidon_hash(&[F::from(2u64), nk, psi, cm_in]); // DOM_NF = 2
    
    // Create exit receipt with the actual nullifier
    let exit_receipt = ExitReceipt::new(1, Amount::from(value as u128), nf_in, 1);
    
    // Build actual CMT tree and get merkle path
    let mut cmt_tree = IncrementalTree::new(16);
    cmt_tree.append(cm_in);
    let cmt_root = cmt_tree.root();
    let cm_path = cmt_tree.get_proof(cm_in).unwrap();
    
    // Build NFT tree and generate non-membership proof
    let mut nft_tree = SortedTree::new(16);
    // Insert a sentinel value to make tree non-empty
    let _ = nft_tree.insert(F::from(0u64));
    let nft_root_old = nft_tree.root();
    
    // Get non-membership proof for nf_in
    let nf_nonmembership = nft_tree.prove_non_membership(nf_in).unwrap();
    
    // Insert nf_in and get witness
    let nf_insert_witness_core = nft_tree.insert_with_witness(nf_in).unwrap();
    // Convert to gadgets' SortedInsertWitness
    let nf_insert_witness = SortedInsertWitness {
        target: nf_insert_witness_core.target,
        range_proof: nf_insert_witness_core.range_proof,
        new_leaf: nf_insert_witness_core.new_leaf,
        updated_pred_leaf: nf_insert_witness_core.updated_pred_leaf,
        new_leaf_path: nf_insert_witness_core.new_leaf_path,
        pred_update_path: nf_insert_witness_core.pred_update_path,
        height: nf_insert_witness_core.height,
    };
    let nft_root_new = nft_tree.root();
    
    // Build exit tree
    let mut exit_tree = IncrementalTree::new(16);
    let exit_root_old = exit_tree.root();
    exit_tree.append(exit_receipt.hash());
    let exit_append_witness = exit_tree.generate_append_witness(exit_receipt.hash());
    let exit_root_new = exit_tree.root();
    
    BurnCircuit {
        note_in,
        value_in: value,
        value_randomness_in: randomness,
        owner_sk,
        owner_pk_x: pk_x_fr,
        owner_pk_y: pk_y_fr,
        nk,
        cm_path,
        nf_nonmembership: Some(nf_nonmembership),
        nf_insert_witness: Some(nf_insert_witness),
        exit_receipt,
        exit_append_witness,
        cmt_root,
        nft_root_old,
        nft_root_new,
        exit_root_old,
        exit_root_new,
        asset_type: 1,
        amount: Amount::from(value as u128),
        nf_in,
    }
}

fn create_transfer_circuit<R: RngCore>(rng: &mut R, num_inputs: usize, num_outputs: usize) -> TransferCircuit {
    use fluxe_core::merkle::{SortedTree};
    use fluxe_core::crypto::poseidon::poseidon_hash;
    use fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness;
    
    let params = PedersenParams::setup_value_commitment();
    
    // Build the CMT tree with dummy notes first
    let mut cmt_tree = IncrementalTree::new(16);
    
    // Add some dummy commitments to make tree non-trivial
    for _ in 0..10 {
        cmt_tree.append(F::rand(rng));
    }
    
    // Build NFT tree with sentinel
    let mut nft_tree = SortedTree::new(16);
    let _ = nft_tree.insert(F::from(0u64)); // Sentinel to make tree non-empty
    let nft_root_old = nft_tree.root();
    
    // Create input notes with proper witnesses
    let mut notes_in = Vec::new();
    let mut values_in = Vec::new();
    let mut value_randomness_in = Vec::new();
    let mut owner_sks = Vec::new();
    let mut owner_pks = Vec::new();
    let mut nks = Vec::new();
    let mut cm_paths = Vec::new();
    let mut nf_list = Vec::new();
    let mut nf_nonmembership_proofs = Vec::new();
    let mut nf_insert_witnesses: Vec<SortedInsertWitness> = Vec::new();
    
    for i in 0..num_inputs {
        let value = 500u64;
        let randomness = F::rand(rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        // Generate owner key pair properly
        let owner_sk = F::rand(rng);
        let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
        let (pk_x_fr, pk_y_fr) = get_pk_coords_circuit_compatible(owner_sk);
        
        // Generate nullifier key
        let nk = F::rand(rng);
        
        // Create note with deterministic psi for reproducibility
        let psi_bytes = [(i + 1) as u8; 32];
        let note = Note::new(1, v_comm, owner_addr, psi_bytes, 1);
        let cm = note.commitment();
        
        // Add to CMT tree and get path
        let leaf_index = cmt_tree.num_leaves();
        cmt_tree.append(cm);
        let path = cmt_tree.get_proof(cm).unwrap();
        
        // Compute nullifier properly
        let psi = F::from_le_bytes_mod_order(&psi_bytes);
        let nf = poseidon_hash(&[F::from(2u64), nk, psi, cm]); // DOM_NF = 2
        
        // Get non-membership proof for nullifier
        let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
        nf_nonmembership_proofs.push(Some(nm_proof.clone()));
        
        // Get insert witness for nullifier
        let insert_witness_core = nft_tree.insert_with_witness(nf).unwrap();
        // Convert to gadgets' SortedInsertWitness
        let insert_witness = SortedInsertWitness {
            target: insert_witness_core.target,
            range_proof: insert_witness_core.range_proof,
            new_leaf: insert_witness_core.new_leaf,
            updated_pred_leaf: insert_witness_core.updated_pred_leaf,
            new_leaf_path: insert_witness_core.new_leaf_path,
            pred_update_path: insert_witness_core.pred_update_path,
            height: insert_witness_core.height,
        };
        nf_insert_witnesses.push(insert_witness);
        
        notes_in.push(note);
        values_in.push(value);
        value_randomness_in.push(randomness);
        owner_sks.push(owner_sk);
        owner_pks.push((pk_x_fr, pk_y_fr));
        nks.push(nk);
        cm_paths.push(path);
        nf_list.push(nf);
    }
    
    let cmt_root_old = cmt_tree.root();
    let nft_root_new = nft_tree.root();
    
    // Create output notes
    let mut notes_out = Vec::new();
    let mut values_out = Vec::new();
    let mut value_randomness_out = Vec::new();
    let mut cm_list = Vec::new();
    let mut cmt_appends_out = Vec::new();
    
    let total_value: u64 = values_in.iter().sum();
    let fee = 10u64;
    let value_per_output = (total_value - fee) / num_outputs as u64;
    
    for _ in 0..num_outputs {
        let randomness = F::rand(rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value_per_output,
            &PedersenRandomness { r: randomness },
        );
        
        let recipient_addr = F::rand(rng); // Random recipient
        let note = Note::new(1, v_comm, recipient_addr, [0u8; 32], 1);
        let cm = note.commitment();
        
        // Append and get witness for output
        cmt_tree.append(cm);
        let append_witness = cmt_tree.generate_append_witness(cm);
        cmt_appends_out.push(append_witness);
        
        notes_out.push(note);
        values_out.push(value_per_output);
        value_randomness_out.push(randomness);
        cm_list.push(cm);
    }
    
    let cmt_root_new = cmt_tree.root();
    
    // Create sanctions proofs (empty tree for benchmarking, but with proper structure)
    let sanctions_tree = IncrementalTree::new(16);
    let sanctions_root = sanctions_tree.root();
    
    // For sanctions non-membership, we'd need proper RangePath objects
    // For now, keeping None but this is where real non-membership proofs would go
    let sanctions_nm_proofs_in = vec![None; num_inputs];
    let sanctions_nm_proofs_out = vec![None; num_outputs];
    
    // Pool policy (simplified but with real root)
    let pool_rules_root = F::rand(rng);
    
    TransferCircuit {
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
        sanctions_nm_proofs_in,
        sanctions_nm_proofs_out,
        cmt_paths_out: Vec::new(), // Not used in current circuit implementation
        nf_nonmembership: nf_nonmembership_proofs,
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out,
        nf_insert_witnesses,
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        sanctions_root,
        pool_rules_root,
        nf_list,
        cm_list,
        fee: Amount::from(fee as u128),
    }
}

fn create_object_update_circuit<R: RngCore>(rng: &mut R) -> ObjectUpdateCircuit {
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
        obj_append_witness: None,
        obj_old_randomness: F::from(1u64),
        obj_new_randomness: F::from(2u64),
        decrypt_key: None,
        obj_root_old: F::rand(rng),
        obj_root_new: F::rand(rng),
        cb_root: F::rand(rng),
        current_time: 1000,
    }
}

fn bench_circuit_constraints(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    println!("\n========================================");
    println!("FLUXE CIRCUIT CONSTRAINT ANALYSIS");
    println!("========================================");
    
    // Mint Circuit
    let mint_circuit = create_mint_circuit(&mut rng);
    let cs = ConstraintSystem::<F>::new_ref();
    mint_circuit.generate_constraints(cs.clone()).expect("Constraint generation failed");
    let mint_stats = CircuitStats::from_constraint_system(&cs.borrow().unwrap());
    mint_stats.print_summary("Mint");
    
    // Burn Circuit
    let burn_circuit = create_burn_circuit(&mut rng);
    let cs = ConstraintSystem::<F>::new_ref();
    match burn_circuit.generate_constraints(cs.clone()) {
        Ok(_) => {
            let burn_stats = CircuitStats::from_constraint_system(&cs.borrow().unwrap());
            burn_stats.print_summary("Burn");
        }
        Err(e) => {
            println!("\nBurn Circuit: FAILED");
            println!("  Error: {:?}", e);
            println!("  Note: This is likely due to EC point validation in owner authentication");
        }
    }
    
    // Transfer Circuit (various sizes)
    println!("\nTransfer Circuit Variations:");
    for (n_in, n_out) in [(1, 1), (2, 2), (2, 4), (4, 4)] {
        let transfer_circuit = create_transfer_circuit(&mut rng, n_in, n_out);
        let cs = ConstraintSystem::<F>::new_ref();
        match transfer_circuit.generate_constraints(cs.clone()) {
            Ok(_) => {
                let stats = CircuitStats::from_constraint_system(&cs.borrow().unwrap());
                stats.print_summary(&format!("Transfer ({} in, {} out)", n_in, n_out));
            }
            Err(e) => {
                println!("\nTransfer ({} in, {} out): FAILED", n_in, n_out);
                println!("  Error: {:?}", e);
            }
        }
    }
    
    // Object Update Circuit
    let object_update_circuit = create_object_update_circuit(&mut rng);
    let cs = ConstraintSystem::<F>::new_ref();
    object_update_circuit.generate_constraints(cs.clone()).expect("Constraint generation failed");
    let object_update_stats = CircuitStats::from_constraint_system(&cs.borrow().unwrap());
    object_update_stats.print_summary("ObjectUpdate");
    
    println!("\n========================================");
    println!("CONSTRAINT GROWTH ANALYSIS");
    println!("========================================");
    
    // Analyze constraint growth with transfer size
    println!("\nTransfer Circuit Constraint Growth:");
    println!("Inputs x Outputs | Constraints | Growth Rate");
    println!("-----------------|-------------|------------");
    
    let mut prev_constraints = 0;
    for (n_in, n_out) in [(1, 1), (1, 2), (2, 2), (2, 4), (4, 4), (4, 8)] {
        let transfer_circuit = create_transfer_circuit(&mut rng, n_in, n_out);
        let cs = ConstraintSystem::<F>::new_ref();
        transfer_circuit.generate_constraints(cs.clone()).expect("Constraint generation failed");
        let num_constraints = cs.borrow().unwrap().num_constraints;
        
        let growth_rate = if prev_constraints > 0 {
            format!("{:+.1}%", 
                ((num_constraints as f64 - prev_constraints as f64) / prev_constraints as f64) * 100.0)
        } else {
            "baseline".to_string()
        };
        
        println!("{:>3} x {:>3}        | {:>11} | {:>11}", 
            n_in, n_out, num_constraints, growth_rate);
        
        prev_constraints = num_constraints;
    }
    
    // Benchmark constraint generation time
    c.bench_function("constraint_generation_mint", |b| {
        b.iter(|| {
            let circuit = create_mint_circuit(&mut rng);
            let cs = ConstraintSystem::<F>::new_ref();
            circuit.generate_constraints(cs).expect("Constraint generation failed");
        });
    });
    
    c.bench_function("constraint_generation_transfer_2x2", |b| {
        b.iter(|| {
            let circuit = create_transfer_circuit(&mut rng, 2, 2);
            let cs = ConstraintSystem::<F>::new_ref();
            circuit.generate_constraints(cs).expect("Constraint generation failed");
        });
    });
    
    println!("\n========================================");
    println!("MEMORY USAGE ESTIMATES");
    println!("========================================");
    
    // Estimate memory usage
    println!("\nApproximate Memory Requirements:");
    println!("Circuit              | Proving Key | Verifying Key");
    println!("---------------------|-------------|---------------");
    
    // Rough estimates based on constraint counts
    let transfer_2x2_constraints = {
        let circuit = create_transfer_circuit(&mut rng, 2, 2);
        let cs = ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let constraints = cs.borrow().unwrap().num_constraints;
        constraints
    };
    
    let circuits = [
        ("Mint", mint_stats.num_constraints),
        // ("Burn", burn_stats.num_constraints), // Commented out - circuit fails
        ("Transfer (2x2)", transfer_2x2_constraints),
        ("ObjectUpdate", object_update_stats.num_constraints),
    ];
    
    for (name, constraints) in circuits {
        // Rough estimates: ~200 bytes per constraint for proving key, ~32 bytes for verifying key
        let pk_size = constraints * 200;
        let vk_size = constraints * 32;
        
        println!("{:<20} | {:>9} KB | {:>11} KB", 
            name, 
            pk_size / 1024,
            vk_size / 1024);
    }
    
    println!("\n========================================\n");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_circuit_constraints
}
criterion_main!(benches);