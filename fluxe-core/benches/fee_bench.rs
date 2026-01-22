//! Performance benchmarks for FLUXE Fee operations
//!
//! Benchmarks:
//! - Fee calculation for different transaction types
//! - Congestion multiplier computation
//! - Fee collection and accumulation
//! - Fee withdrawal operations
//! - Dynamic pricing updates

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fluxe_core::fees::{FeeConfig, FeeCollector, TransactionFeeType};
use fluxe_core::types::Amount;

/// Benchmark FeeConfig creation
fn bench_fee_config_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_config_creation");

    group.bench_function("default", |b| {
        b.iter(|| {
            FeeConfig::default()
        });
    });

    group.bench_function("new_with_base_fee", |b| {
        b.iter(|| {
            FeeConfig::new(black_box(Amount::new(1000)))
        });
    });

    group.bench_function("full_builder_chain", |b| {
        b.iter(|| {
            FeeConfig::new(Amount::new(1000))
                .with_fee_per_byte(Amount::new(10))
                .with_dynamic_pricing(true)
                .with_min_fee(Amount::new(500))
                .with_max_fee(Amount::new(100_000))
                .with_target_batch_size(100)
        });
    });

    group.finish();
}

/// Benchmark fee calculation for different transaction types
fn bench_fee_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_calculation");

    let config = FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10));

    // Benchmark each transaction type
    for tx_type in [
        TransactionFeeType::Transfer,
        TransactionFeeType::Mint,
        TransactionFeeType::Burn,
        TransactionFeeType::ObjectUpdate,
        TransactionFeeType::Callback,
        TransactionFeeType::CrossChain,
    ].iter() {
        group.bench_with_input(
            BenchmarkId::new("type", format!("{:?}", tx_type)),
            tx_type,
            |b, &tx_type| {
                b.iter(|| {
                    config.calculate_fee(black_box(tx_type), black_box(256))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark fee calculation with varying transaction sizes
fn bench_fee_calculation_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_calculation_sizes");

    let config = FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10));

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                b.iter(|| {
                    config.calculate_fee(TransactionFeeType::Transfer, black_box(size))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark fee calculation with dynamic pricing enabled
fn bench_fee_calculation_dynamic(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_calculation_dynamic");

    let config_static = FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10))
        .with_dynamic_pricing(false);

    let mut config_dynamic = FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10))
        .with_dynamic_pricing(true)
        .with_target_batch_size(100);

    // Set different congestion levels
    config_dynamic.congestion_multiplier = 150; // 1.5x

    group.bench_function("static_pricing", |b| {
        b.iter(|| {
            config_static.calculate_fee(TransactionFeeType::Transfer, black_box(256))
        });
    });

    group.bench_function("dynamic_pricing_1.5x", |b| {
        b.iter(|| {
            config_dynamic.calculate_fee(TransactionFeeType::Transfer, black_box(256))
        });
    });

    group.finish();
}

/// Benchmark congestion multiplier updates
fn bench_congestion_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("congestion_update");

    // Single update
    group.bench_function("single_update", |b| {
        b.iter_with_setup(
            || {
                FeeConfig::new(Amount::new(1000))
                    .with_dynamic_pricing(true)
                    .with_target_batch_size(100)
            },
            |mut config| {
                config.update_congestion(black_box(150));
                config
            },
        );
    });

    // Multiple sequential updates (simulating batch processing)
    for num_updates in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*num_updates as u64));
        group.bench_with_input(
            BenchmarkId::new("sequential_updates", num_updates),
            num_updates,
            |b, &num_updates| {
                b.iter_with_setup(
                    || {
                        FeeConfig::new(Amount::new(1000))
                            .with_dynamic_pricing(true)
                            .with_target_batch_size(100)
                    },
                    |mut config| {
                        for i in 0..num_updates {
                            let batch_size = (i as u64 * 2) + 50; // Varying batch sizes
                            config.update_congestion(batch_size);
                        }
                        config
                    },
                );
            },
        );
    }

    // High congestion spike
    group.bench_function("high_congestion_spike", |b| {
        b.iter_with_setup(
            || {
                FeeConfig::new(Amount::new(1000))
                    .with_dynamic_pricing(true)
                    .with_target_batch_size(100)
            },
            |mut config| {
                // Simulate spike: 500% utilization
                config.update_congestion(black_box(500));
                config
            },
        );
    });

    group.finish();
}

/// Benchmark FeeCollector creation
fn bench_fee_collector_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_collector_creation");

    group.bench_function("new_default", |b| {
        b.iter(|| {
            FeeCollector::default()
        });
    });

    group.bench_function("new_with_address", |b| {
        let address = [0xABu8; 32];
        b.iter(|| {
            FeeCollector::new(black_box(address))
        });
    });

    group.finish();
}

/// Benchmark fee collection
fn bench_fee_collection(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_collection");

    // Single fee collection
    group.bench_function("single_fee", |b| {
        b.iter_with_setup(
            || FeeCollector::default(),
            |mut collector| {
                collector.collect_fee(black_box(1), black_box(1), Amount::new(1000));
                collector
            },
        );
    });

    // Batch fee collection
    for count in [10, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::new("batch", count),
            count,
            |b, &count| {
                b.iter_with_setup(
                    || FeeCollector::default(),
                    |mut collector| {
                        for i in 0..count {
                            let chain_id = (i % 5) + 1;
                            let asset_type = (i % 10) + 1;
                            collector.collect_fee(chain_id as u32, asset_type as u32, Amount::new(i as u128 * 100));
                        }
                        collector
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark fee lookups
fn bench_fee_lookups(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_lookups");

    // Pre-populate collector
    let mut collector = FeeCollector::default();
    for chain_id in 1..=10 {
        for asset_type in 1..=20 {
            collector.collect_fee(chain_id, asset_type, Amount::new((chain_id * asset_type * 100) as u128));
        }
    }

    group.bench_function("get_fees_existing", |b| {
        b.iter(|| {
            collector.get_fees(black_box(5), black_box(10))
        });
    });

    group.bench_function("get_fees_non_existing", |b| {
        b.iter(|| {
            collector.get_fees(black_box(99), black_box(99))
        });
    });

    group.bench_function("get_chain_fees", |b| {
        b.iter(|| {
            collector.get_chain_fees(black_box(5))
        });
    });

    group.bench_function("total_fees_for_asset", |b| {
        b.iter(|| {
            collector.total_fees_for_asset(black_box(10))
        });
    });

    group.bench_function("has_fees", |b| {
        b.iter(|| {
            collector.has_fees(black_box(5))
        });
    });

    group.bench_function("chains_with_fees", |b| {
        b.iter(|| {
            collector.chains_with_fees()
        });
    });

    group.finish();
}

/// Benchmark fee withdrawal creation
fn bench_fee_withdrawal(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_withdrawal");

    // Single asset withdrawal
    group.bench_function("single_asset_withdrawal", |b| {
        b.iter_with_setup(
            || {
                let mut collector = FeeCollector::new([0xABu8; 32]);
                collector.collect_fee(1, 1, Amount::new(10000));
                collector
            },
            |mut collector| {
                collector.create_asset_withdrawal(black_box(1), black_box(1))
            },
        );
    });

    // Full chain withdrawal with multiple assets
    for asset_count in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::new("chain_withdrawal_assets", asset_count),
            asset_count,
            |b, &asset_count| {
                b.iter_with_setup(
                    || {
                        let mut collector = FeeCollector::new([0xABu8; 32]);
                        for asset in 1..=asset_count {
                            collector.collect_fee(1, asset as u32, Amount::new(1000 * asset as u128));
                        }
                        collector
                    },
                    |mut collector| {
                        collector.create_fee_withdrawal(black_box(1))
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark fee estimate functions
fn bench_fee_estimates(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_estimates");

    let config = FeeConfig::new(Amount::new(1000))
        .with_fee_per_byte(Amount::new(10));

    group.bench_function("estimate_transfer_fee", |b| {
        b.iter(|| {
            config.estimate_transfer_fee()
        });
    });

    group.bench_function("estimate_mint_fee", |b| {
        b.iter(|| {
            config.estimate_mint_fee()
        });
    });

    group.bench_function("estimate_burn_fee", |b| {
        b.iter(|| {
            config.estimate_burn_fee()
        });
    });

    group.finish();
}

/// Benchmark fee reset operations
fn bench_fee_reset(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_reset");

    for fee_count in [10, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("reset_fees", fee_count),
            fee_count,
            |b, &fee_count| {
                b.iter_with_setup(
                    || {
                        let mut collector = FeeCollector::default();
                        for i in 0..fee_count {
                            collector.collect_fee(1, i as u32 + 1, Amount::new(1000));
                        }
                        collector
                    },
                    |mut collector| {
                        collector.reset_fees(black_box(1));
                        collector
                    },
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("clear_all_fees", fee_count),
            fee_count,
            |b, &fee_count| {
                b.iter_with_setup(
                    || {
                        let mut collector = FeeCollector::default();
                        for i in 0..fee_count {
                            let chain_id = (i % 10) + 1;
                            collector.collect_fee(chain_id as u32, i as u32 + 1, Amount::new(1000));
                        }
                        collector
                    },
                    |mut collector| {
                        collector.clear_all_fees();
                        collector
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark type multiplier lookups
fn bench_type_multipliers(c: &mut Criterion) {
    let mut group = c.benchmark_group("type_multipliers");

    for tx_type in [
        TransactionFeeType::Transfer,
        TransactionFeeType::Mint,
        TransactionFeeType::Burn,
        TransactionFeeType::ObjectUpdate,
        TransactionFeeType::Callback,
        TransactionFeeType::CrossChain,
    ].iter() {
        group.bench_with_input(
            BenchmarkId::new("multiplier", format!("{:?}", tx_type)),
            tx_type,
            |b, &tx_type| {
                b.iter(|| {
                    tx_type.multiplier()
                });
            },
        );
    }

    group.finish();
}

/// Benchmark fee summary generation
fn bench_fee_summary(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_summary");

    for (chains, assets) in [(5, 10), (10, 20), (20, 50)].iter() {
        let mut collector = FeeCollector::default();
        for chain in 1..=*chains {
            for asset in 1..=*assets {
                collector.collect_fee(chain, asset, Amount::new((chain * asset * 100) as u128));
            }
        }

        group.bench_with_input(
            BenchmarkId::new("chains_assets", format!("{}x{}", chains, assets)),
            &(),
            |b, _| {
                b.iter(|| {
                    collector.fee_summary()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_fee_config_creation,
    bench_fee_calculation,
    bench_fee_calculation_sizes,
    bench_fee_calculation_dynamic,
    bench_congestion_update,
    bench_fee_collector_creation,
    bench_fee_collection,
    bench_fee_lookups,
    bench_fee_withdrawal,
    bench_fee_estimates,
    bench_fee_reset,
    bench_type_multipliers,
    bench_fee_summary,
);
criterion_main!(benches);
