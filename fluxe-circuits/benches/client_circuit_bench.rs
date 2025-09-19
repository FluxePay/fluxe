use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ark_bls12_381::{Bls12_381, Fr as F};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_ff::UniformRand;
use ark_snark::SNARK;
use ark_std::rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

use fluxe_circuits::mint::MintCircuit;
use fluxe_core::{
    data_structures::{Note, IngressReceipt},
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::IncrementalTree,
    types::*,
};

/// Benchmark results structure
#[derive(Debug)]
struct BenchmarkResults {
    circuit_name: String,
    constraint_count: usize,
    setup_time_ms: f64,
    prove_time_ms: f64,
    verify_time_ms: f64,
    proof_size_bytes: usize,
}

impl BenchmarkResults {
    fn print(&self) {
        println!("\n{} Performance:", self.circuit_name);
        println!("  Constraints:     {}", self.constraint_count);
        println!("  Setup time:      {:.2} ms", self.setup_time_ms);
        println!("  Proving time:    {:.2} ms", self.prove_time_ms);
        println!("  Verification:    {:.2} ms", self.verify_time_ms);
        println!("  Proof size:      {} bytes", self.proof_size_bytes);
    }
}

/// Create a mint circuit for benchmarking
fn create_mint_circuit_for_bench<R: RngCore>(
    rng: &mut R,
    num_outputs: usize,
) -> (MintCircuit, Vec<F>) {
    let params = PedersenParams::setup_value_commitment();
    
    // Create output notes
    let mut notes = Vec::new();
    let mut values = Vec::new();
    let mut randomness = Vec::new();
    
    let value_per_note = 1000u64 / num_outputs as u64;
    
    for _ in 0..num_outputs {
        let r = F::rand(rng);
        let v_comm = PedersenCommitment::commit(
            &params,
            value_per_note,
            &PedersenRandomness { r },
        );
        
        let note = Note::new(
            1, // asset_type
            v_comm,
            F::rand(rng), // owner_addr
            [0u8; 32], // memo
            1, // pool_id
        );
        
        notes.push(note);
        values.push(value_per_note);
        randomness.push(r);
    }
    
    let total_value = values.iter().sum::<u64>();
    let ingress = IngressReceipt::new(
        1, // asset_type
        Amount::from(total_value as u128),
        notes[0].commitment(), // simplified - in practice would be merkle root
        1, // nonce
    );
    
    let mut cmt_tree = IncrementalTree::new(16);
    let mut ingress_tree = IncrementalTree::new(16);
    
    let circuit = MintCircuit::new(
        notes,
        values,
        randomness,
        ingress,
        &mut cmt_tree,
        &mut ingress_tree,
    );
    
    // Create dummy public inputs for benchmarking
    let public_inputs = vec![
        cmt_tree.root(),
        ingress_tree.root(),
        F::from(1u64), // asset_type
        F::from(total_value),
    ];
    
    (circuit, public_inputs)
}

/// Benchmark a single circuit
fn benchmark_circuit<C: ConstraintSynthesizer<F> + Clone>(
    circuit_name: &str,
    circuit: C,
    public_inputs: Vec<F>,
    rng: &mut ChaCha20Rng,
) -> BenchmarkResults {
    // Count constraints
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    let constraint_count = cs.borrow().unwrap().num_constraints;
    
    // Setup
    let setup_start = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), rng).unwrap();
    let setup_time = setup_start.elapsed();
    
    // Prove
    let prove_start = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, rng).unwrap();
    let prove_time = prove_start.elapsed();
    
    // Verify
    let pvk = prepare_verifying_key(&vk);
    let verify_start = Instant::now();
    let valid = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();
    let verify_time = verify_start.elapsed();
    
    assert!(valid, "Proof verification failed!");
    
    // Calculate proof size (simplified - actual size depends on serialization)
    let proof_size = 192; // Groth16 proof is 3 group elements = 3 * 64 bytes
    
    BenchmarkResults {
        circuit_name: circuit_name.to_string(),
        constraint_count,
        setup_time_ms: setup_time.as_secs_f64() * 1000.0,
        prove_time_ms: prove_time.as_secs_f64() * 1000.0,
        verify_time_ms: verify_time.as_secs_f64() * 1000.0,
        proof_size_bytes: proof_size,
    }
}

fn bench_client_circuits(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    println!("\n================================================");
    println!("FLUXE CLIENT-SIDE CIRCUIT BENCHMARKS");
    println!("================================================");
    
    // Benchmark Mint Circuit with different output counts
    let mut group = c.benchmark_group("mint_circuit");
    
    for num_outputs in [1, 2, 4] {
        group.bench_function(BenchmarkId::new("outputs", num_outputs), |b| {
            b.iter(|| {
                let (circuit, _) = create_mint_circuit_for_bench(&mut rng, num_outputs);
                let cs = ConstraintSystem::<F>::new_ref();
                circuit.generate_constraints(cs).unwrap();
            });
        });
    }
    group.finish();
    
    // Run comprehensive benchmark for 1-output mint
    println!("\nRunning comprehensive benchmarks...");
    let (mint_circuit, public_inputs) = create_mint_circuit_for_bench(&mut rng, 1);
    let mint_results = benchmark_circuit("Mint (1 output)", mint_circuit, public_inputs, &mut rng);
    mint_results.print();
    
    // Benchmark constraint generation specifically
    let mut group = c.benchmark_group("constraint_generation");
    
    group.bench_function("mint_1_output", |b| {
        b.iter(|| {
            let (circuit, _) = create_mint_circuit_for_bench(&mut rng, 1);
            let cs = ConstraintSystem::<F>::new_ref();
            let _: () = circuit.generate_constraints(cs).unwrap();
            black_box(());
        });
    });
    
    group.bench_function("mint_2_outputs", |b| {
        b.iter(|| {
            let (circuit, _) = create_mint_circuit_for_bench(&mut rng, 2);
            let cs = ConstraintSystem::<F>::new_ref();
            let _: () = circuit.generate_constraints(cs).unwrap();
            black_box(());
        });
    });
    
    group.finish();
    
    // Benchmark proving specifically
    let mut group = c.benchmark_group("proving");
    group.sample_size(10); // Reduce sample size for expensive operations
    
    group.bench_function("mint_prove", |b| {
        let (circuit, _) = create_mint_circuit_for_bench(&mut rng, 1);
        let (pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        
        b.iter(|| {
            let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng).unwrap();
            black_box(proof);
        });
    });
    
    group.finish();
    
    println!("\n================================================");
    println!("BENCHMARK SUMMARY");
    println!("================================================");
    
    // Print summary table
    println!("\nCircuit Performance Comparison:");
    println!("Circuit          | Constraints | Prove (ms) | Verify (ms)");
    println!("-----------------|-------------|------------|------------");
    println!("Mint (1 output)  | {:>11} | {:>10.2} | {:>10.2}",
        mint_results.constraint_count,
        mint_results.prove_time_ms,
        mint_results.verify_time_ms,
    );
    
    // Estimate scaling
    println!("\nConstraint Growth Analysis:");
    println!("Outputs | Constraints | Growth");
    println!("--------|-------------|-------");
    
    let mut prev_constraints = 0;
    for outputs in [1, 2, 4] {
        let (circuit, _) = create_mint_circuit_for_bench(&mut rng, outputs);
        let cs = ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let constraints = cs.borrow().unwrap().num_constraints;
        
        let growth = if prev_constraints > 0 {
            format!("+{:.0}%", ((constraints as f64 / prev_constraints as f64) - 1.0) * 100.0)
        } else {
            "baseline".to_string()
        };
        
        println!("{:>7} | {:>11} | {:>6}", outputs, constraints, growth);
        prev_constraints = constraints;
    }
    
    println!("\n================================================\n");
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_client_circuits
}
criterion_main!(benches);