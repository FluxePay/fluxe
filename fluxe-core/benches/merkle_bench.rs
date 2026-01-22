//! Performance benchmarks for FLUXE Merkle tree operations
//!
//! Benchmarks:
//! - IncrementalMerkleTree insertions (1, 10, 100, 1000 leaves)
//! - Merkle proof generation
//! - Merkle proof verification
//! - Batch append operations
//! - SortedTree operations (for nullifier tree)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fluxe_core::merkle::{IncrementalTree, SortedTree, TreeParams};
use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;

/// Benchmark IncrementalMerkleTree single insertions
fn bench_incremental_tree_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental_tree_insert");

    for count in [1, 10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            count,
            |b, &count| {
                let mut rng = thread_rng();
                let leaves: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();

                b.iter(|| {
                    let mut tree = IncrementalTree::new(20);
                    for leaf in &leaves {
                        tree.append(black_box(*leaf));
                    }
                    tree
                });
            },
        );
    }
    group.finish();
}

/// Benchmark IncrementalMerkleTree batch append
fn bench_incremental_tree_batch_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental_tree_batch_append");

    for count in [10, 100, 500].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            count,
            |b, &count| {
                let mut rng = thread_rng();
                let leaves: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();

                b.iter(|| {
                    let mut tree = IncrementalTree::new(20);
                    tree.append_batch(black_box(&leaves))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark Merkle proof generation
fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_generation");

    // Test with trees of different sizes
    for tree_size in [100, 1000, 10000].iter() {
        let mut rng = thread_rng();
        let mut tree = IncrementalTree::new(20);

        // Pre-populate tree
        for _ in 0..*tree_size {
            tree.append(F::rand(&mut rng));
        }

        group.bench_with_input(
            BenchmarkId::new("tree_size", tree_size),
            tree_size,
            |b, _| {
                let index = (rand::random::<usize>() % tree.num_leaves()).max(0);

                b.iter(|| {
                    tree.get_path(black_box(index))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark Merkle proof verification
fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_verification");

    for tree_height in [10, 15, 20, 25].iter() {
        let mut rng = thread_rng();
        let mut tree = IncrementalTree::new(*tree_height);

        // Add some leaves
        for _ in 0..100 {
            tree.append(F::rand(&mut rng));
        }

        let path = tree.get_path(50).expect("Path should exist");
        let root = tree.root();
        let params = TreeParams::new(*tree_height);

        group.bench_with_input(
            BenchmarkId::new("height", tree_height),
            tree_height,
            |b, _| {
                b.iter(|| {
                    path.verify(black_box(&root), black_box(&params))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark SortedTree (nullifier tree) insertions
fn bench_sorted_tree_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("sorted_tree_insert");

    for count in [1, 10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            count,
            |b, &count| {
                let mut rng = thread_rng();
                // Generate unique random keys
                let keys: Vec<F> = (0..count).map(|i| F::from(i as u64 * 1000 + 1)).collect();

                b.iter(|| {
                    let mut tree = SortedTree::new(20);
                    for key in &keys {
                        let _ = tree.insert(black_box(*key));
                    }
                    tree
                });
            },
        );
    }
    group.finish();
}

/// Benchmark SortedTree non-membership proof
fn bench_sorted_tree_non_membership_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("sorted_tree_non_membership_proof");

    for tree_size in [10, 50, 100].iter() {
        let mut tree = SortedTree::new(20);

        // Insert keys with gaps for testing non-membership
        for i in 0..*tree_size {
            let key = F::from((i as u64 + 1) * 100);
            let _ = tree.insert(key);
        }

        // Target for non-membership proof (in a gap)
        let target = F::from(50);

        group.bench_with_input(
            BenchmarkId::new("tree_size", tree_size),
            tree_size,
            |b, _| {
                b.iter(|| {
                    tree.prove_non_membership(black_box(target))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark SortedTree membership check (contains)
fn bench_sorted_tree_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("sorted_tree_contains");

    for tree_size in [100, 1000, 5000].iter() {
        let mut tree = SortedTree::new(20);

        // Insert keys
        for i in 0..*tree_size {
            let key = F::from((i as u64 + 1) * 10);
            let _ = tree.insert(key);
        }

        let existing_key = F::from(500 * 10);
        let non_existing_key = F::from(500 * 10 + 1);

        group.bench_with_input(
            BenchmarkId::new("existing/size", tree_size),
            tree_size,
            |b, _| {
                b.iter(|| {
                    tree.contains(black_box(&existing_key))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("non_existing/size", tree_size),
            tree_size,
            |b, _| {
                b.iter(|| {
                    tree.contains(black_box(&non_existing_key))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark TreeParams creation and hashing
fn bench_tree_params(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_params");

    // Benchmark TreeParams creation
    group.bench_function("new_height_20", |b| {
        b.iter(|| {
            TreeParams::new(black_box(20))
        });
    });

    group.bench_function("new_height_32", |b| {
        b.iter(|| {
            TreeParams::new(black_box(32))
        });
    });

    // Benchmark hash_pair
    let params = TreeParams::new(20);
    let left = F::from(12345u64);
    let right = F::from(67890u64);

    group.bench_function("hash_pair", |b| {
        b.iter(|| {
            params.hash_pair(black_box(&left), black_box(&right))
        });
    });

    group.finish();
}

/// Benchmark append witness generation
fn bench_append_witness(c: &mut Criterion) {
    let mut group = c.benchmark_group("append_witness");

    for tree_size in [100, 1000, 5000].iter() {
        let mut rng = thread_rng();
        let mut tree = IncrementalTree::new(20);

        // Pre-populate tree
        for _ in 0..*tree_size {
            tree.append(F::rand(&mut rng));
        }

        let mut rng2 = thread_rng();
        let new_leaf = F::rand(&mut rng2);

        group.bench_with_input(
            BenchmarkId::new("tree_size", tree_size),
            tree_size,
            |b, _| {
                b.iter(|| {
                    tree.generate_append_witness(black_box(new_leaf))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_incremental_tree_insert,
    bench_incremental_tree_batch_append,
    bench_proof_generation,
    bench_proof_verification,
    bench_sorted_tree_insert,
    bench_sorted_tree_non_membership_proof,
    bench_sorted_tree_contains,
    bench_tree_params,
    bench_append_witness,
);
criterion_main!(benches);
