use criterion::{criterion_group, criterion_main, Criterion};
use ark_bls12_381::{Bls12_381, Fr as F};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_ff::UniformRand;
use ark_std::rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use fluxe_circuits::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
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
    let params = PedersenParams::setup_value_commitment();
    let value = 500u64;
    let randomness = F::rand(rng);
    
    let v_comm = PedersenCommitment::commit(
        &params,
        value,
        &PedersenRandomness { r: randomness },
    );
    
    let note_in = Note::new(1, v_comm, F::rand(rng), [0u8; 32], 1);
    let exit_receipt = ExitReceipt::new(1, Amount::from(value as u128), F::rand(rng), 1);
    
    let path = MerklePath {
        leaf_index: 0,
        siblings: vec![F::from(0u64); 16],
        leaf: note_in.commitment(),
    };
    
    BurnCircuit {
        note_in,
        value_in: value,
        value_randomness_in: randomness,
        owner_sk: F::rand(rng),
        nk: F::rand(rng),
        cm_path: path,
        nf_nonmembership: None, // Simplified for benchmarking
        exit_receipt,
        cmt_root: F::rand(rng),
        nft_root_old: F::rand(rng),
        nft_root_new: F::rand(rng),
        exit_root_old: F::rand(rng),
        exit_root_new: F::rand(rng),
        asset_type: 1,
        amount: Amount::from(value as u128),
        nf_in: F::rand(rng),
    }
}

fn create_transfer_circuit<R: RngCore>(rng: &mut R, num_inputs: usize, num_outputs: usize) -> TransferCircuit {
    let params = PedersenParams::setup_value_commitment();
    
    // Create input notes
    let mut notes_in = Vec::new();
    let mut values_in = Vec::new();
    let mut value_randomness_in = Vec::new();
    let mut nks = Vec::new();
    let mut cm_paths = Vec::new();
    let mut nf_list = Vec::new();
    
    for _ in 0..num_inputs {
        let value = 500u64;
        let randomness = F::rand(rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        let note = Note::new(1, v_comm, F::rand(rng), [0u8; 32], 1);
        notes_in.push(note.clone());
        values_in.push(value);
        value_randomness_in.push(randomness);
        nks.push(F::rand(rng));
        
        let path = MerklePath {
            leaf_index: 0,
            siblings: vec![F::from(0u64); 16],
            leaf: note.commitment(),
        };
        cm_paths.push(path);
        nf_list.push(F::rand(rng));
    }
    
    // Create output notes
    let mut notes_out = Vec::new();
    let mut values_out = Vec::new();
    let mut value_randomness_out = Vec::new();
    let mut cm_list = Vec::new();
    
    let value_per_output = (values_in.iter().sum::<u64>() - 10) / num_outputs as u64;
    
    for _ in 0..num_outputs {
        let randomness = F::rand(rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value_per_output,
            &PedersenRandomness { r: randomness },
        );
        
        let note = Note::new(1, v_comm, F::rand(rng), [0u8; 32], 1);
        notes_out.push(note.clone());
        values_out.push(value_per_output);
        value_randomness_out.push(randomness);
        cm_list.push(note.commitment());
    }
    
    TransferCircuit {
        notes_in,
        values_in,
        value_randomness_in,
        notes_out,
        values_out,
        value_randomness_out,
        nks,
        cm_paths,
        nf_nonmembership_proofs: vec![None; num_inputs], // Simplified for benchmarking
        sanctions_nm_proofs_in: vec![None; num_inputs],
        sanctions_nm_proofs_out: vec![None; num_outputs],
        cmt_root_old: F::rand(rng),
        cmt_root_new: F::rand(rng),
        nft_root_old: F::rand(rng),
        nft_root_new: F::rand(rng),
        sanctions_root: F::rand(rng),
        pool_rules_root: F::rand(rng),
        nf_list,
        cm_list,
        fee: Amount::from(10u128),
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
        cb_path: None,
        cb_nonmembership: None,
        obj_path_old,
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
    burn_circuit.generate_constraints(cs.clone()).expect("Constraint generation failed");
    let burn_stats = CircuitStats::from_constraint_system(&cs.borrow().unwrap());
    burn_stats.print_summary("Burn");
    
    // Transfer Circuit (various sizes)
    println!("\nTransfer Circuit Variations:");
    for (n_in, n_out) in [(1, 1), (2, 2), (2, 4), (4, 4)] {
        let transfer_circuit = create_transfer_circuit(&mut rng, n_in, n_out);
        let cs = ConstraintSystem::<F>::new_ref();
        transfer_circuit.generate_constraints(cs.clone()).expect("Constraint generation failed");
        let stats = CircuitStats::from_constraint_system(&cs.borrow().unwrap());
        stats.print_summary(&format!("Transfer ({} in, {} out)", n_in, n_out));
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
        ("Burn", burn_stats.num_constraints),
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

criterion_group!(benches, bench_circuit_constraints);
criterion_main!(benches);