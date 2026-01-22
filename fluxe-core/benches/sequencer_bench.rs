//! Performance benchmarks for FLUXE Sequencer operations
//!
//! Benchmarks:
//! - Batch creation
//! - Transaction ordering (priority queue operations)
//! - Transaction addition
//! - Should-create-batch decision
//! - Priority calculation

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fluxe_core::sequencer::ChainSequencer;
use fluxe_core::sequencer::config::ChainSequencerConfig;
use fluxe_core::server_verifier::{VerifiedTransaction, TransactionData};
use fluxe_core::types::{Amount, TransactionType, StateRoots};
use ark_bn254::Fr as F;
use ark_groth16::Proof;
use std::time::Duration;

/// Helper to create a mock verified transaction
fn create_mock_transaction(tx_type: TransactionType) -> VerifiedTransaction {
    VerifiedTransaction {
        tx_type,
        proof: Proof::default(),
        public_inputs: vec![],
        old_roots: StateRoots::default(),
        new_roots: StateRoots::default(),
        transaction_data: TransactionData::Transfer {
            nullifiers: vec![F::from(1u64)],
            notes_out: vec![],
        },
        chain_id: Some(1),
    }
}

/// Benchmark ChainSequencer creation
fn bench_sequencer_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequencer_creation");

    group.bench_function("new_default", |b| {
        b.iter(|| {
            let config = ChainSequencerConfig::new(black_box(1));
            ChainSequencer::new(config)
        });
    });

    group.bench_function("new_custom_config", |b| {
        b.iter(|| {
            let config = ChainSequencerConfig::new(black_box(1))
                .with_batch_interval(Duration::from_secs(5))
                .with_max_batch_size(500)
                .with_min_batch_size(50);
            ChainSequencer::new(config)
        });
    });

    group.finish();
}

/// Benchmark transaction addition to pending queue
fn bench_add_transaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_transaction");

    for initial_count in [0, 100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("queue_size", initial_count),
            initial_count,
            |b, &initial_count| {
                b.iter_with_setup(
                    || {
                        let config = ChainSequencerConfig::new(1).with_max_batch_size(5000);
                        let mut sequencer = ChainSequencer::new(config);

                        // Pre-fill with transactions
                        for i in 0..initial_count {
                            let tx = create_mock_transaction(TransactionType::Transfer);
                            let _ = sequencer.add_transaction(tx, Amount::from(i as u128));
                        }

                        sequencer
                    },
                    |mut sequencer| {
                        let tx = create_mock_transaction(TransactionType::Transfer);
                        sequencer.add_transaction(black_box(tx), Amount::from(1000u128)).unwrap();
                        sequencer
                    },
                );
            },
        );
    }
    group.finish();
}

/// Benchmark batch transactions addition
fn bench_add_batch_transactions(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_batch_transactions");

    for count in [10, 50, 100, 200].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            count,
            |b, &count| {
                let transactions: Vec<_> = (0..count)
                    .map(|_| create_mock_transaction(TransactionType::Transfer))
                    .collect();

                b.iter_with_setup(
                    || {
                        let config = ChainSequencerConfig::new(1).with_max_batch_size(5000);
                        ChainSequencer::new(config)
                    },
                    |mut sequencer| {
                        for (i, tx) in transactions.iter().enumerate() {
                            let _ = sequencer.add_transaction(black_box(tx.clone()), Amount::from(i as u128));
                        }
                        sequencer
                    },
                );
            },
        );
    }
    group.finish();
}

/// Benchmark batch creation
fn bench_create_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_batch");

    for pending_count in [10, 50, 100, 200, 500].iter() {
        group.throughput(Throughput::Elements(*pending_count as u64));
        group.bench_with_input(
            BenchmarkId::new("pending", pending_count),
            pending_count,
            |b, &pending_count| {
                b.iter_with_setup(
                    || {
                        let config = ChainSequencerConfig::new(1)
                            .with_max_batch_size(pending_count);
                        let mut sequencer = ChainSequencer::new(config);

                        // Fill with transactions
                        for i in 0..pending_count {
                            let tx = create_mock_transaction(TransactionType::Transfer);
                            let _ = sequencer.add_transaction(tx, Amount::from(i as u128));
                        }

                        sequencer
                    },
                    |mut sequencer| {
                        sequencer.create_batch()
                    },
                );
            },
        );
    }
    group.finish();
}

/// Benchmark priority ordering with mixed transaction types
fn bench_priority_ordering(c: &mut Criterion) {
    let mut group = c.benchmark_group("priority_ordering");

    group.bench_function("mixed_types_100", |b| {
        b.iter_with_setup(
            || {
                let config = ChainSequencerConfig::new(1).with_max_batch_size(100);
                let mut sequencer = ChainSequencer::new(config);

                // Add mixed transactions
                for i in 0..100 {
                    let tx_type = match i % 4 {
                        0 => TransactionType::Transfer,
                        1 => TransactionType::Mint,
                        2 => TransactionType::Burn,
                        _ => TransactionType::ObjectUpdate,
                    };
                    let tx = create_mock_transaction(tx_type);
                    let fee = Amount::from((i * 100) as u128);
                    let _ = sequencer.add_transaction(tx, fee);
                }

                sequencer
            },
            |mut sequencer| {
                // Create batch to extract in priority order
                sequencer.create_batch()
            },
        );
    });

    // Benchmark with high-priority burns
    group.bench_function("burns_priority", |b| {
        b.iter_with_setup(
            || {
                let config = ChainSequencerConfig::new(1).with_max_batch_size(100);
                let mut sequencer = ChainSequencer::new(config);

                // Add 50 transfers with high fees
                for i in 0..50 {
                    let tx = create_mock_transaction(TransactionType::Transfer);
                    let _ = sequencer.add_transaction(tx, Amount::from(1000u128 + i as u128));
                }

                // Add 50 burns with lower fees (but should get priority bonus)
                for i in 0..50 {
                    let tx = create_mock_transaction(TransactionType::Burn);
                    let _ = sequencer.add_transaction(tx, Amount::from(100u128 + i as u128));
                }

                sequencer
            },
            |mut sequencer| {
                sequencer.create_batch()
            },
        );
    });

    group.finish();
}

/// Benchmark should_create_batch decision
fn bench_should_create_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("should_create_batch");

    // Size threshold check
    group.bench_function("size_threshold_check", |b| {
        let config = ChainSequencerConfig::new(1)
            .with_max_batch_size(100)
            .with_min_batch_size(10);
        let mut sequencer = ChainSequencer::new(config);

        // Add exactly the threshold number of transactions
        for i in 0..100 {
            let tx = create_mock_transaction(TransactionType::Transfer);
            let _ = sequencer.add_transaction(tx, Amount::from(i as u128));
        }

        b.iter(|| {
            sequencer.should_create_batch()
        });
    });

    // Under threshold check
    group.bench_function("under_threshold_check", |b| {
        let config = ChainSequencerConfig::new(1)
            .with_max_batch_size(100)
            .with_min_batch_size(10)
            .with_batch_interval(Duration::from_secs(300)); // Long interval to avoid time trigger
        let mut sequencer = ChainSequencer::new(config);

        // Add fewer than min
        for i in 0..5 {
            let tx = create_mock_transaction(TransactionType::Transfer);
            let _ = sequencer.add_transaction(tx, Amount::from(i as u128));
        }

        b.iter(|| {
            sequencer.should_create_batch()
        });
    });

    group.finish();
}

/// Benchmark pending count queries
fn bench_pending_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("pending_queries");

    for pending_count in [100, 500, 1000, 2000].iter() {
        let config = ChainSequencerConfig::new(1).with_max_batch_size(5000);
        let mut sequencer = ChainSequencer::new(config);

        // Fill with transactions
        for i in 0..*pending_count {
            let tx = create_mock_transaction(TransactionType::Transfer);
            let _ = sequencer.add_transaction(tx, Amount::from(i as u128));
        }

        group.bench_with_input(
            BenchmarkId::new("pending_count", pending_count),
            pending_count,
            |b, _| {
                b.iter(|| {
                    black_box(sequencer.pending_count())
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("has_pending", pending_count),
            pending_count,
            |b, _| {
                b.iter(|| {
                    black_box(sequencer.has_pending())
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("stats", pending_count),
            pending_count,
            |b, _| {
                b.iter(|| {
                    black_box(sequencer.stats())
                });
            },
        );
    }
    group.finish();
}

/// Benchmark batch finalization
fn bench_batch_finalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_finalization");

    group.bench_function("finalize_batch", |b| {
        b.iter_with_setup(
            || {
                let config = ChainSequencerConfig::new(1);
                ChainSequencer::new(config)
            },
            |mut sequencer| {
                sequencer.finalize_batch(black_box(1)).unwrap();
                sequencer
            },
        );
    });

    // Sequential finalizations
    group.bench_function("finalize_10_batches", |b| {
        b.iter_with_setup(
            || {
                let config = ChainSequencerConfig::new(1);
                ChainSequencer::new(config)
            },
            |mut sequencer| {
                for i in 1..=10 {
                    sequencer.finalize_batch(i).unwrap();
                }
                sequencer
            },
        );
    });

    group.finish();
}

/// Benchmark clear pending operations
fn bench_clear_pending(c: &mut Criterion) {
    let mut group = c.benchmark_group("clear_pending");

    for pending_count in [100, 500, 1000, 2000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(pending_count),
            pending_count,
            |b, &pending_count| {
                b.iter_with_setup(
                    || {
                        let config = ChainSequencerConfig::new(1).with_max_batch_size(5000);
                        let mut sequencer = ChainSequencer::new(config);

                        for i in 0..pending_count {
                            let tx = create_mock_transaction(TransactionType::Transfer);
                            let _ = sequencer.add_transaction(tx, Amount::from(i as u128));
                        }

                        sequencer
                    },
                    |mut sequencer| {
                        sequencer.clear_pending();
                        sequencer
                    },
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sequencer_creation,
    bench_add_transaction,
    bench_add_batch_transactions,
    bench_create_batch,
    bench_priority_ordering,
    bench_should_create_batch,
    bench_pending_queries,
    bench_batch_finalization,
    bench_clear_pending,
);
criterion_main!(benches);
