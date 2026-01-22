//! Performance benchmarks for FLUXE GlobalStateManager operations
//!
//! Benchmarks:
//! - GlobalStateManager creation
//! - Chain registration
//! - Commitment additions (process_mint, process_transfer)
//! - Nullifier lookups
//! - Supply tracking
//! - State root retrieval

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fluxe_core::state_manager::GlobalStateManager;
use fluxe_core::data_structures::IngressReceipt;
use fluxe_core::types::{Amount, ChainType};
use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;

/// Benchmark GlobalStateManager creation
fn bench_state_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_manager_creation");

    for tree_depth in [16, 20, 24, 28, 32].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(tree_depth),
            tree_depth,
            |b, &depth| {
                b.iter(|| {
                    GlobalStateManager::new(black_box(depth))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark chain registration
fn bench_chain_registration(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_registration");

    group.bench_function("register_single_chain", |b| {
        b.iter_with_setup(
            || GlobalStateManager::new(20),
            |mut manager| {
                manager.register_chain(black_box(1), ChainType::EVM).unwrap();
                manager
            },
        );
    });

    group.bench_function("register_10_chains", |b| {
        b.iter_with_setup(
            || GlobalStateManager::new(20),
            |mut manager| {
                for i in 1..=10 {
                    let chain_type = if i % 2 == 0 { ChainType::EVM } else { ChainType::SVM };
                    manager.register_chain(i, chain_type).unwrap();
                }
                manager
            },
        );
    });

    group.finish();
}

/// Benchmark commitment additions via process_mint
fn bench_commitment_additions(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_additions");

    for count in [1, 5, 10, 20].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            count,
            |b, &count| {
                let mut rng = thread_rng();

                b.iter_with_setup(
                    || {
                        let mut manager = GlobalStateManager::new(20);
                        manager.register_chain(1, ChainType::EVM).unwrap();

                        let commitments: Vec<F> = (0..count)
                            .map(|_| F::rand(&mut rng))
                            .collect();

                        let receipt = IngressReceipt {
                            source_chain: 1,
                            asset_type: 1,
                            amount: Amount::from(1000u64),
                            beneficiary_cm: F::rand(&mut rng),
                            nonce: 1,
                            aux: F::from(0u64),
                        };

                        (manager, receipt, commitments)
                    },
                    |(mut manager, receipt, commitments)| {
                        manager.process_mint(1, black_box(&receipt), black_box(&commitments)).unwrap();
                        manager
                    },
                );
            },
        );
    }
    group.finish();
}

/// Benchmark transfer processing (nullifiers + commitments)
fn bench_process_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_transfer");

    // 2-in-2-out transfer
    group.bench_function("2_in_2_out", |b| {
        let mut rng = thread_rng();

        b.iter_with_setup(
            || {
                let manager = GlobalStateManager::new(20);
                let nullifiers: Vec<F> = (0..2).map(|_| F::rand(&mut rng)).collect();
                let commitments: Vec<F> = (0..2).map(|_| F::rand(&mut rng)).collect();
                (manager, nullifiers, commitments)
            },
            |(mut manager, nullifiers, commitments)| {
                manager.process_transfer(black_box(&nullifiers), black_box(&commitments)).unwrap();
                manager
            },
        );
    });

    // 4-in-4-out transfer
    group.bench_function("4_in_4_out", |b| {
        let mut rng = thread_rng();

        b.iter_with_setup(
            || {
                let manager = GlobalStateManager::new(20);
                let nullifiers: Vec<F> = (0..4).map(|_| F::rand(&mut rng)).collect();
                let commitments: Vec<F> = (0..4).map(|_| F::rand(&mut rng)).collect();
                (manager, nullifiers, commitments)
            },
            |(mut manager, nullifiers, commitments)| {
                manager.process_transfer(black_box(&nullifiers), black_box(&commitments)).unwrap();
                manager
            },
        );
    });

    group.finish();
}

/// Benchmark nullifier lookups (existence check)
fn bench_nullifier_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("nullifier_lookup");

    for nullifier_count in [100, 1000, 5000, 10000].iter() {
        let mut rng = thread_rng();
        let mut manager = GlobalStateManager::new(20);

        // Add nullifiers via transfers
        for _ in 0..*nullifier_count {
            let nullifier = F::rand(&mut rng);
            let commitment = F::rand(&mut rng);
            let _ = manager.process_transfer(&[nullifier], &[commitment]);
        }

        let existing_nullifier = F::rand(&mut rng);
        let _ = manager.process_transfer(&[existing_nullifier], &[F::rand(&mut rng)]);

        let non_existing = F::rand(&mut rng);

        group.bench_with_input(
            BenchmarkId::new("existing", nullifier_count),
            nullifier_count,
            |b, _| {
                b.iter(|| {
                    manager.nullifier_exists(black_box(existing_nullifier))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("non_existing", nullifier_count),
            nullifier_count,
            |b, _| {
                b.iter(|| {
                    manager.nullifier_exists(black_box(non_existing))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark nullifier non-membership proof generation
fn bench_nullifier_non_membership_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("nullifier_non_membership_proof");

    for nullifier_count in [100, 500, 1000].iter() {
        let mut rng = thread_rng();
        let mut manager = GlobalStateManager::new(20);

        // Add nullifiers
        for _ in 0..*nullifier_count {
            let nullifier = F::rand(&mut rng);
            let commitment = F::rand(&mut rng);
            let _ = manager.process_transfer(&[nullifier], &[commitment]);
        }

        let target = F::rand(&mut rng);

        group.bench_with_input(
            BenchmarkId::from_parameter(nullifier_count),
            nullifier_count,
            |b, _| {
                b.iter(|| {
                    manager.get_nullifier_non_membership_proof(black_box(target))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark commitment proof retrieval
fn bench_commitment_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_proof");

    for commitment_count in [100, 500, 1000, 5000].iter() {
        let mut rng = thread_rng();
        let mut manager = GlobalStateManager::new(20);
        manager.register_chain(1, ChainType::EVM).unwrap();

        let mut all_commitments = Vec::new();

        // Add commitments via mints
        for i in 0..*commitment_count {
            let commitment = F::rand(&mut rng);
            all_commitments.push(commitment);

            let receipt = IngressReceipt {
                source_chain: 1,
                asset_type: 1,
                amount: Amount::from(100u64),
                beneficiary_cm: F::rand(&mut rng),
                nonce: i as u64,
                aux: F::from(0u64),
            };

            let _ = manager.process_mint(1, &receipt, &[commitment]);
        }

        // Pick a commitment to search for
        let target_commitment = all_commitments[*commitment_count / 2];
        let non_existing = F::rand(&mut rng);

        group.bench_with_input(
            BenchmarkId::new("existing", commitment_count),
            commitment_count,
            |b, _| {
                b.iter(|| {
                    manager.get_commitment_proof(black_box(target_commitment))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("non_existing", commitment_count),
            commitment_count,
            |b, _| {
                b.iter(|| {
                    manager.get_commitment_proof(black_box(non_existing))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark state root retrieval
fn bench_get_roots(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_roots");

    let mut rng = thread_rng();
    let mut manager = GlobalStateManager::new(20);
    manager.register_chain(1, ChainType::EVM).unwrap();
    manager.register_chain(2, ChainType::SVM).unwrap();

    // Add some state
    for i in 0..100 {
        let nullifier = F::rand(&mut rng);
        let commitment = F::rand(&mut rng);
        let _ = manager.process_transfer(&[nullifier], &[commitment]);
    }

    group.bench_function("get_global_roots", |b| {
        b.iter(|| {
            manager.get_global_roots()
        });
    });

    group.bench_function("get_chain_roots", |b| {
        b.iter(|| {
            manager.get_chain_roots(black_box(1))
        });
    });

    group.finish();
}

/// Benchmark supply tracking operations
fn bench_supply_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("supply_operations");

    let mut rng = thread_rng();
    let mut manager = GlobalStateManager::new(20);
    manager.register_chain(1, ChainType::EVM).unwrap();
    manager.register_chain(2, ChainType::SVM).unwrap();

    // Add some mints to create supply
    for i in 0..50 {
        let receipt = IngressReceipt {
            source_chain: if i % 2 == 0 { 1 } else { 2 },
            asset_type: (i % 5) + 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: i as u64,
            aux: F::from(0u64),
        };
        let commitment = F::rand(&mut rng);
        let _ = manager.process_mint(receipt.source_chain, &receipt, &[commitment]);
    }

    group.bench_function("get_supply", |b| {
        b.iter(|| {
            manager.get_supply(black_box(1))
        });
    });

    group.bench_function("get_supply_info", |b| {
        b.iter(|| {
            manager.get_supply_info(black_box(1))
        });
    });

    group.bench_function("check_supply_invariant", |b| {
        b.iter(|| {
            manager.check_supply_invariant(black_box(1))
        });
    });

    group.bench_function("check_all_supply_invariants", |b| {
        b.iter(|| {
            manager.check_all_supply_invariants()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_state_manager_creation,
    bench_chain_registration,
    bench_commitment_additions,
    bench_process_transfer,
    bench_nullifier_lookup,
    bench_nullifier_non_membership_proof,
    bench_commitment_proof,
    bench_get_roots,
    bench_supply_operations,
);
criterion_main!(benches);
