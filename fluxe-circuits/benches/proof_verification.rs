use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ark_bls12_381::{Bls12_381, Fr as F};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::time::Duration;

mod common;

use common::{create_mint_circuit, create_burn_circuit, create_transfer_circuit, create_object_update_circuit};
use fluxe_circuits::circuits::FluxeCircuit;

/// Pre-generated proofs and keys for verification benchmarks
struct VerificationSetup {
    mint_vk: VerifyingKey<Bls12_381>,
    mint_proof: Proof<Bls12_381>,
    mint_public_inputs: Vec<F>,
    
    burn_vk: VerifyingKey<Bls12_381>,
    burn_proof: Proof<Bls12_381>,
    burn_public_inputs: Vec<F>,
    
    transfer_vk: VerifyingKey<Bls12_381>,
    transfer_proof: Proof<Bls12_381>,
    transfer_public_inputs: Vec<F>,
    
    object_update_vk: VerifyingKey<Bls12_381>,
    object_update_proof: Proof<Bls12_381>,
    object_update_public_inputs: Vec<F>,
}

impl VerificationSetup {
    fn new() -> Self {
        println!("Generating proofs for verification benchmarks...");
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Generate mint proof
        let mint_circuit = create_mint_circuit(&mut rng);
        let mint_public_inputs = mint_circuit.public_inputs();
        let (mint_pk, mint_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            mint_circuit.clone(), &mut rng
        ).expect("Mint setup failed");
        let mint_proof = Groth16::<Bls12_381>::prove(
            &mint_pk, mint_circuit, &mut rng
        ).expect("Mint proof failed");
        
        // Generate burn proof
        let burn_circuit = create_burn_circuit(&mut rng);
        let burn_public_inputs = burn_circuit.public_inputs();
        let (burn_pk, burn_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            burn_circuit.clone(), &mut rng
        ).expect("Burn setup failed");
        let burn_proof = Groth16::<Bls12_381>::prove(
            &burn_pk, burn_circuit, &mut rng
        ).expect("Burn proof failed");
        
        // Generate transfer proof
        let transfer_circuit = create_transfer_circuit(&mut rng, 2, 2);
        let transfer_public_inputs = transfer_circuit.public_inputs();
        let (transfer_pk, transfer_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            transfer_circuit.clone(), &mut rng
        ).expect("Transfer setup failed");
        let transfer_proof = Groth16::<Bls12_381>::prove(
            &transfer_pk, transfer_circuit, &mut rng
        ).expect("Transfer proof failed");
        
        // Generate object update proof
        let object_update_circuit = create_object_update_circuit(&mut rng);
        let object_update_public_inputs = object_update_circuit.public_inputs();
        let (object_update_pk, object_update_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            object_update_circuit.clone(), &mut rng
        ).expect("ObjectUpdate setup failed");
        let object_update_proof = Groth16::<Bls12_381>::prove(
            &object_update_pk, object_update_circuit, &mut rng
        ).expect("ObjectUpdate proof failed");
        
        println!("Proof generation complete!");
        
        Self {
            mint_vk,
            mint_proof,
            mint_public_inputs,
            burn_vk,
            burn_proof,
            burn_public_inputs,
            transfer_vk,
            transfer_proof,
            transfer_public_inputs,
            object_update_vk,
            object_update_proof,
            object_update_public_inputs,
        }
    }
}


fn bench_mint_verification(c: &mut Criterion) {
    let setup = VerificationSetup::new();
    
    c.bench_function("mint_proof_verification", |b| {
        b.iter(|| {
            let result = Groth16::<Bls12_381>::verify(
                &setup.mint_vk,
                &setup.mint_public_inputs,
                &setup.mint_proof,
            ).expect("Verification failed");
            black_box(result);
        });
    });
}

fn bench_burn_verification(c: &mut Criterion) {
    let setup = VerificationSetup::new();
    
    c.bench_function("burn_proof_verification", |b| {
        b.iter(|| {
            let result = Groth16::<Bls12_381>::verify(
                &setup.burn_vk,
                &setup.burn_public_inputs,
                &setup.burn_proof,
            ).expect("Verification failed");
            black_box(result);
        });
    });
}

fn bench_transfer_verification(c: &mut Criterion) {
    let setup = VerificationSetup::new();
    
    c.bench_function("transfer_proof_verification", |b| {
        b.iter(|| {
            let result = Groth16::<Bls12_381>::verify(
                &setup.transfer_vk,
                &setup.transfer_public_inputs,
                &setup.transfer_proof,
            ).expect("Verification failed");
            black_box(result);
        });
    });
}

fn bench_object_update_verification(c: &mut Criterion) {
    let setup = VerificationSetup::new();
    
    c.bench_function("object_update_proof_verification", |b| {
        b.iter(|| {
            let result = Groth16::<Bls12_381>::verify(
                &setup.object_update_vk,
                &setup.object_update_public_inputs,
                &setup.object_update_proof,
            ).expect("Verification failed");
            black_box(result);
        });
    });
}

fn bench_batch_verification(c: &mut Criterion) {
    let setup = VerificationSetup::new();
    
    let mut group = c.benchmark_group("batch_verification");
    
    // Benchmark different batch sizes
    for batch_size in [1, 5, 10, 20, 50] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_proofs", batch_size)),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut results = Vec::new();
                    for _ in 0..size {
                        let result = Groth16::<Bls12_381>::verify(
                            &setup.transfer_vk,
                            &setup.transfer_public_inputs,
                            &setup.transfer_proof,
                        ).expect("Verification failed");
                        results.push(result);
                    }
                    black_box(results);
                });
            }
        );
    }
    group.finish();
}

fn bench_parallel_verification(c: &mut Criterion) {
    let setup = VerificationSetup::new();
    
    let mut group = c.benchmark_group("parallel_verification");
    group.measurement_time(Duration::from_secs(10));
    
    // Create multiple proofs for parallel verification
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut proofs = Vec::new();
    let mut public_inputs = Vec::new();
    
    for _ in 0..10 {
        let circuit = create_transfer_circuit(&mut rng, 2, 2);
        let inputs = circuit.public_inputs();
        let (pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
            circuit.clone(), &mut rng
        ).expect("Setup failed");
        let proof = Groth16::<Bls12_381>::prove(
            &pk, circuit, &mut rng
        ).expect("Proof failed");
        
        proofs.push(proof);
        public_inputs.push(inputs);
    }
    
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        
        group.bench_function("parallel_10_proofs", |b| {
            b.iter(|| {
                let results: Vec<bool> = proofs
                    .par_iter()
                    .zip(public_inputs.par_iter())
                    .map(|(proof, inputs)| {
                        Groth16::<Bls12_381>::verify(
                            &setup.transfer_vk,
                            inputs,
                            proof,
                        ).expect("Verification failed")
                    })
                    .collect();
                black_box(results);
            });
        });
    }
    
    group.bench_function("sequential_10_proofs", |b| {
        b.iter(|| {
            let results: Vec<bool> = proofs
                .iter()
                .zip(public_inputs.iter())
                .map(|(proof, inputs)| {
                    Groth16::<Bls12_381>::verify(
                        &setup.transfer_vk,
                        inputs,
                        proof,
                    ).expect("Verification failed")
                })
                .collect();
            black_box(results);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_mint_verification,
    bench_burn_verification,
    bench_transfer_verification,
    bench_object_update_verification,
    bench_batch_verification,
    bench_parallel_verification
);
criterion_main!(benches);