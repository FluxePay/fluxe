use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Duration;

mod common;

use common::{create_mint_circuit, create_burn_circuit, create_transfer_circuit, create_object_update_circuit};

/// Setup proving keys for benchmarking
struct BenchmarkSetup {
    mint_pk: ProvingKey<Bls12_381>,
    burn_pk: ProvingKey<Bls12_381>,
    transfer_pk: ProvingKey<Bls12_381>,
    object_update_pk: ProvingKey<Bls12_381>,
}

impl BenchmarkSetup {
    fn new() -> Self {
        println!("Setting up proving keys (this may take a while)...");
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Setup for MintCircuit
        let mint_circuit = create_mint_circuit(&mut rng);
        let (mint_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
            mint_circuit, &mut rng
        ).expect("Mint setup failed");
        
        // Setup for BurnCircuit
        let burn_circuit = create_burn_circuit(&mut rng);
        let (burn_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
            burn_circuit, &mut rng
        ).expect("Burn setup failed");
        
        // Setup for TransferCircuit (2-in, 2-out)
        let transfer_circuit = create_transfer_circuit(&mut rng, 2, 2);
        let (transfer_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
            transfer_circuit, &mut rng
        ).expect("Transfer setup failed");
        
        // Setup for ObjectUpdateCircuit
        let object_update_circuit = create_object_update_circuit(&mut rng);
        let (object_update_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
            object_update_circuit, &mut rng
        ).expect("ObjectUpdate setup failed");
        
        println!("Setup complete!");
        
        Self {
            mint_pk,
            burn_pk,
            transfer_pk,
            object_update_pk,
        }
    }
}


fn bench_mint_proof_generation(c: &mut Criterion) {
    let setup = BenchmarkSetup::new();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    c.bench_function("mint_proof_generation", |b| {
        b.iter(|| {
            let circuit = create_mint_circuit(&mut rng);
            let proof = Groth16::<Bls12_381>::prove(
                &setup.mint_pk,
                circuit,
                &mut rng
            ).expect("Proof generation failed");
            black_box(proof);
        });
    });
}

fn bench_burn_proof_generation(c: &mut Criterion) {
    let setup = BenchmarkSetup::new();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    c.bench_function("burn_proof_generation", |b| {
        b.iter(|| {
            let circuit = create_burn_circuit(&mut rng);
            let proof = Groth16::<Bls12_381>::prove(
                &setup.burn_pk,
                circuit,
                &mut rng
            ).expect("Proof generation failed");
            black_box(proof);
        });
    });
}

fn bench_transfer_proof_generation(c: &mut Criterion) {
    let setup = BenchmarkSetup::new();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    let mut group = c.benchmark_group("transfer_proof_generation");
    
    // Benchmark different transfer sizes
    for (num_inputs, num_outputs) in [(1, 1), (2, 2), (2, 4), (4, 4)] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}in_{}out", num_inputs, num_outputs)),
            &(num_inputs, num_outputs),
            |b, &(n_in, n_out)| {
                b.iter(|| {
                    let circuit = create_transfer_circuit(&mut rng, n_in, n_out);
                    let proof = Groth16::<Bls12_381>::prove(
                        &setup.transfer_pk,
                        circuit,
                        &mut rng
                    ).expect("Proof generation failed");
                    black_box(proof);
                });
            }
        );
    }
    group.finish();
}

fn bench_object_update_proof_generation(c: &mut Criterion) {
    let setup = BenchmarkSetup::new();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    c.bench_function("object_update_proof_generation", |b| {
        b.iter(|| {
            let circuit = create_object_update_circuit(&mut rng);
            let proof = Groth16::<Bls12_381>::prove(
                &setup.object_update_pk,
                circuit,
                &mut rng
            ).expect("Proof generation failed");
            black_box(proof);
        });
    });
}

fn bench_batch_proof_generation(c: &mut Criterion) {
    let setup = BenchmarkSetup::new();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    let mut group = c.benchmark_group("batch_proof_generation");
    group.measurement_time(Duration::from_secs(20));
    
    // Benchmark batch sizes
    for batch_size in [1, 5, 10, 20] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_proofs", batch_size)),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut proofs = Vec::new();
                    for _ in 0..size {
                        let circuit = create_transfer_circuit(&mut rng, 2, 2);
                        let proof = Groth16::<Bls12_381>::prove(
                            &setup.transfer_pk,
                            circuit,
                            &mut rng
                        ).expect("Proof generation failed");
                        proofs.push(proof);
                    }
                    black_box(proofs);
                });
            }
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_mint_proof_generation,
    bench_burn_proof_generation,
    bench_transfer_proof_generation,
    bench_object_update_proof_generation,
    bench_batch_proof_generation
);
criterion_main!(benches);