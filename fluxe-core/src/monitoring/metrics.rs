//! Prometheus-compatible metrics for FLUXE monitoring
//!
//! Provides Counter, Gauge, and Histogram types for tracking system metrics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::types::{AssetType, ChainId};

/// A monotonically increasing counter
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self { value: AtomicU64::new(0) }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A gauge that can go up and down
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self { value: AtomicU64::new(0) }
    }

    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A histogram for tracking value distributions
#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn with_default_buckets() -> Self {
        Self::new(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    }

    pub fn observe(&self, value: f64) {
        for (i, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum.fetch_add((value * 1_000_000.0) as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn get_sum(&self) -> f64 {
        self.sum.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::with_default_buckets()
    }
}

/// Labels for metrics
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Labels {
    pub chain_id: Option<ChainId>,
    pub asset_type: Option<AssetType>,
    pub tx_type: Option<String>,
}

impl Labels {
    pub fn new() -> Self {
        Self { chain_id: None, asset_type: None, tx_type: None }
    }

    pub fn with_chain(mut self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    pub fn with_asset(mut self, asset_type: AssetType) -> Self {
        self.asset_type = Some(asset_type);
        self
    }

    pub fn with_tx_type(mut self, tx_type: &str) -> Self {
        self.tx_type = Some(tx_type.to_string());
        self
    }
}

impl Default for Labels {
    fn default() -> Self {
        Self::new()
    }
}

/// Core FLUXE metrics
#[derive(Debug)]
pub struct Metrics {
    // Transaction metrics
    pub transactions_submitted: Counter,
    pub transactions_by_chain: RwLock<HashMap<ChainId, Counter>>,
    pub transactions_by_type: RwLock<HashMap<String, Counter>>,

    // Batch metrics
    pub batches_finalized: Counter,
    pub batches_by_chain: RwLock<HashMap<ChainId, Counter>>,
    pub batch_size: Histogram,

    // Deposit/Withdrawal metrics
    pub deposits_processed: Counter,
    pub deposits_by_chain: RwLock<HashMap<ChainId, Counter>>,
    pub withdrawals_processed: Counter,
    pub withdrawals_by_chain: RwLock<HashMap<ChainId, Counter>>,

    // Pool metrics
    pub pool_balance: RwLock<HashMap<(ChainId, AssetType), Gauge>>,

    // Performance metrics
    pub proof_verification_duration: Histogram,
    pub batch_creation_duration: Histogram,

    // Queue metrics
    pub pending_transactions: Gauge,
    pub pending_by_chain: RwLock<HashMap<ChainId, Gauge>>,

    // Uptime
    pub start_time: Instant,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            transactions_submitted: Counter::new(),
            transactions_by_chain: RwLock::new(HashMap::new()),
            transactions_by_type: RwLock::new(HashMap::new()),
            batches_finalized: Counter::new(),
            batches_by_chain: RwLock::new(HashMap::new()),
            batch_size: Histogram::with_default_buckets(),
            deposits_processed: Counter::new(),
            deposits_by_chain: RwLock::new(HashMap::new()),
            withdrawals_processed: Counter::new(),
            withdrawals_by_chain: RwLock::new(HashMap::new()),
            pool_balance: RwLock::new(HashMap::new()),
            proof_verification_duration: Histogram::new(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]),
            batch_creation_duration: Histogram::new(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]),
            pending_transactions: Gauge::new(),
            pending_by_chain: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }

    pub fn record_transaction(&self, chain_id: ChainId, tx_type: &str) {
        self.transactions_submitted.inc();
        
        {
            let mut by_chain = self.transactions_by_chain.write().unwrap();
            by_chain.entry(chain_id).or_insert_with(Counter::new).inc();
        }
        
        {
            let mut by_type = self.transactions_by_type.write().unwrap();
            by_type.entry(tx_type.to_string()).or_insert_with(Counter::new).inc();
        }
    }

    pub fn record_batch(&self, chain_id: ChainId, size: usize) {
        self.batches_finalized.inc();
        self.batch_size.observe(size as f64);
        
        let mut by_chain = self.batches_by_chain.write().unwrap();
        by_chain.entry(chain_id).or_insert_with(Counter::new).inc();
    }

    pub fn record_deposit(&self, chain_id: ChainId, asset_type: AssetType, amount: u64) {
        self.deposits_processed.inc();
        
        {
            let mut by_chain = self.deposits_by_chain.write().unwrap();
            by_chain.entry(chain_id).or_insert_with(Counter::new).inc();
        }
        
        self.update_pool_balance(chain_id, asset_type, amount as i64);
    }

    pub fn record_withdrawal(&self, chain_id: ChainId, asset_type: AssetType, amount: u64) {
        self.withdrawals_processed.inc();
        
        {
            let mut by_chain = self.withdrawals_by_chain.write().unwrap();
            by_chain.entry(chain_id).or_insert_with(Counter::new).inc();
        }
        
        self.update_pool_balance(chain_id, asset_type, -(amount as i64));
    }

    fn update_pool_balance(&self, chain_id: ChainId, asset_type: AssetType, delta: i64) {
        let mut pools = self.pool_balance.write().unwrap();
        let gauge = pools.entry((chain_id, asset_type)).or_insert_with(Gauge::new);
        let current = gauge.get() as i64;
        gauge.set((current + delta).max(0) as u64);
    }

    pub fn get_pool_balance(&self, chain_id: ChainId, asset_type: AssetType) -> u64 {
        let pools = self.pool_balance.read().unwrap();
        pools.get(&(chain_id, asset_type)).map(|g| g.get()).unwrap_or(0)
    }

    pub fn set_pending_transactions(&self, chain_id: ChainId, count: u64) {
        self.pending_transactions.set(count);
        
        let mut by_chain = self.pending_by_chain.write().unwrap();
        by_chain.entry(chain_id).or_insert_with(Gauge::new).set(count);
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Transaction metrics
        output.push_str(&format!("# HELP fluxe_transactions_total Total transactions submitted\n"));
        output.push_str(&format!("# TYPE fluxe_transactions_total counter\n"));
        output.push_str(&format!("fluxe_transactions_total {}\n", self.transactions_submitted.get()));

        // Batch metrics
        output.push_str(&format!("# HELP fluxe_batches_total Total batches finalized\n"));
        output.push_str(&format!("# TYPE fluxe_batches_total counter\n"));
        output.push_str(&format!("fluxe_batches_total {}\n", self.batches_finalized.get()));

        // Deposit metrics
        output.push_str(&format!("# HELP fluxe_deposits_total Total deposits processed\n"));
        output.push_str(&format!("# TYPE fluxe_deposits_total counter\n"));
        output.push_str(&format!("fluxe_deposits_total {}\n", self.deposits_processed.get()));

        // Withdrawal metrics
        output.push_str(&format!("# HELP fluxe_withdrawals_total Total withdrawals processed\n"));
        output.push_str(&format!("# TYPE fluxe_withdrawals_total counter\n"));
        output.push_str(&format!("fluxe_withdrawals_total {}\n", self.withdrawals_processed.get()));

        // Pending transactions
        output.push_str(&format!("# HELP fluxe_pending_transactions Current pending transactions\n"));
        output.push_str(&format!("# TYPE fluxe_pending_transactions gauge\n"));
        output.push_str(&format!("fluxe_pending_transactions {}\n", self.pending_transactions.get()));

        // Uptime
        output.push_str(&format!("# HELP fluxe_uptime_seconds Sequencer uptime\n"));
        output.push_str(&format!("# TYPE fluxe_uptime_seconds gauge\n"));
        output.push_str(&format!("fluxe_uptime_seconds {}\n", self.uptime_seconds()));

        output
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics registry
pub struct MetricsRegistry {
    metrics: Arc<Metrics>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self { metrics: Arc::new(Metrics::new()) }
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.inc_by(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);
        gauge.set(100);
        assert_eq!(gauge.get(), 100);
        gauge.inc();
        assert_eq!(gauge.get(), 101);
        gauge.dec();
        assert_eq!(gauge.get(), 100);
    }

    #[test]
    fn test_histogram() {
        let hist = Histogram::with_default_buckets();
        hist.observe(0.5);
        hist.observe(1.5);
        hist.observe(0.25);
        assert_eq!(hist.get_count(), 3);
    }

    #[test]
    fn test_metrics_transactions() {
        let metrics = Metrics::new();
        metrics.record_transaction(1, "mint");
        metrics.record_transaction(1, "burn");
        metrics.record_transaction(501, "transfer");
        
        assert_eq!(metrics.transactions_submitted.get(), 3);
    }

    #[test]
    fn test_metrics_batches() {
        let metrics = Metrics::new();
        metrics.record_batch(1, 50);
        metrics.record_batch(1, 75);
        
        assert_eq!(metrics.batches_finalized.get(), 2);
    }

    #[test]
    fn test_metrics_deposits_withdrawals() {
        let metrics = Metrics::new();
        metrics.record_deposit(1, 1, 1000);
        metrics.record_deposit(1, 1, 500);
        metrics.record_withdrawal(1, 1, 300);
        
        assert_eq!(metrics.deposits_processed.get(), 2);
        assert_eq!(metrics.withdrawals_processed.get(), 1);
        assert_eq!(metrics.get_pool_balance(1, 1), 1200);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = Metrics::new();
        metrics.record_transaction(1, "mint");
        metrics.record_batch(1, 10);
        
        let output = metrics.export_prometheus();
        assert!(output.contains("fluxe_transactions_total 1"));
        assert!(output.contains("fluxe_batches_total 1"));
    }
}
