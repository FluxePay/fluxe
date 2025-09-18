use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ark_bls12_381::{Bls12_381, Fr as F};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use ark_ff::UniformRand;
use ark_std::rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::time::Duration;

use fluxe_circuits::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
    circuits::FluxeCircuit,
};
use fluxe_core::{
    data_structures::{Note, IngressReceipt, ExitReceipt, ComplianceState, ZkObject},
    crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    merkle::{IncrementalTree, MerklePath},
    types::*,
};

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