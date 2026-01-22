//! Multi-chain deposit monitoring for FLUXE.
//!
//! This module provides the `DepositMonitor` which polls for deposit events
//! across multiple chains and creates ingress receipts for the FLUXE sequencer.
//!
//! # Architecture
//!
//! The `DepositMonitor` manages multiple `ChainMonitor` instances, one per chain.
//! Each monitor tracks its last processed block and periodically polls for new
//! deposit events. Events are deduplicated and converted to `IngressReceipt`s.
//!
//! # Example
//!
//! ```ignore
//! use fluxe_core::bridge::{DepositMonitor, EthereumRpcClient, MonitorConfig};
//! use fluxe_core::config::MultiChainConfig;
//!
//! // Create monitor
//! let mut monitor = DepositMonitor::new(MonitorConfig::default());
//!
//! // Add chains from config
//! for chain_config in multi_chain_config.enabled_chains() {
//!     let client = EthereumRpcClient::from_config(chain_config)?;
//!     monitor.add_chain(chain_config.chain_id, Box::new(client), chain_config.finality_blocks);
//! }
//!
//! // Start polling loop
//! monitor.poll_loop(|receipt| async {
//!     sequencer.add_ingress_receipt(receipt).await
//! }).await;
//! ```

use crate::bridge::events::{DepositEvent, EventId};
use crate::bridge::{ChainMonitorState, RpcClient};
use crate::data_structures::IngressReceipt;
use crate::errors::{FluxeError, FluxeResult};
use crate::types::ChainId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Errors specific to deposit monitoring
#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Chain {0} not found")]
    ChainNotFound(ChainId),

    #[error("Chain {0} already registered")]
    ChainAlreadyRegistered(ChainId),

    #[error("RPC error on chain {chain_id}: {message}")]
    RpcError { chain_id: ChainId, message: String },

    #[error("Event processing failed: {0}")]
    ProcessingError(String),

    #[error("Monitor not running")]
    NotRunning,

    #[error("Monitor already running")]
    AlreadyRunning,
}

impl From<MonitorError> for FluxeError {
    fn from(e: MonitorError) -> Self {
        FluxeError::Other(e.to_string())
    }
}

/// Configuration for the deposit monitor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Polling interval in milliseconds
    pub poll_interval_ms: u64,

    /// Maximum number of blocks to process in a single poll
    pub max_blocks_per_poll: u64,

    /// Number of retries for failed RPC requests
    pub max_retries: u32,

    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,

    /// Whether to enable event deduplication
    pub enable_deduplication: bool,

    /// Maximum number of event IDs to track for deduplication
    pub max_dedup_cache_size: usize,

    /// Whether to continue processing other chains if one fails
    pub continue_on_error: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 5_000,      // 5 seconds
            max_blocks_per_poll: 1000,    // Process up to 1000 blocks at a time
            max_retries: 3,               // Retry up to 3 times
            retry_delay_ms: 1_000,        // 1 second between retries
            enable_deduplication: true,
            max_dedup_cache_size: 10_000, // Track last 10k events
            continue_on_error: true,      // Don't stop all chains if one fails
        }
    }
}

/// A monitor for a single chain
pub struct ChainMonitor {
    /// RPC client for this chain
    pub client: Box<dyn RpcClient>,

    /// Monitor state (last processed block, etc.)
    pub state: ChainMonitorState,

    /// Number of consecutive errors
    pub consecutive_errors: u32,

    /// Whether the chain is currently being polled
    pub polling: bool,
}

impl ChainMonitor {
    /// Create a new chain monitor
    pub fn new(
        client: Box<dyn RpcClient>,
        finality_blocks: u64,
    ) -> Self {
        let chain_id = client.chain_id();
        Self {
            client,
            state: ChainMonitorState::new(chain_id, finality_blocks),
            consecutive_errors: 0,
            polling: false,
        }
    }

    /// Set the starting block for the monitor
    pub fn with_start_block(mut self, block: u64) -> Self {
        self.state.last_processed_block = block;
        self
    }
}

/// Multi-chain deposit monitor
///
/// Manages deposit event monitoring across multiple chains, handling:
/// - Polling coordination
/// - Event deduplication
/// - Retry logic
/// - IngressReceipt creation
pub struct DepositMonitor {
    /// Per-chain monitors
    chains: HashMap<ChainId, ChainMonitor>,

    /// Monitor configuration
    config: MonitorConfig,

    /// Processed event IDs for deduplication
    processed_events: HashSet<EventId>,

    /// Whether the monitor is currently running
    running: bool,

    /// Statistics
    stats: MonitorStats,
}

/// Statistics for the deposit monitor
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MonitorStats {
    /// Total deposits processed
    pub total_deposits: u64,

    /// Deposits per chain
    pub deposits_per_chain: HashMap<ChainId, u64>,

    /// Total blocks processed
    pub total_blocks_processed: u64,

    /// Number of duplicate events filtered
    pub duplicates_filtered: u64,

    /// Number of errors encountered
    pub total_errors: u64,

    /// Errors per chain
    pub errors_per_chain: HashMap<ChainId, u64>,
}

impl DepositMonitor {
    /// Create a new deposit monitor with the given configuration
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            chains: HashMap::new(),
            config,
            processed_events: HashSet::new(),
            running: false,
            stats: MonitorStats::default(),
        }
    }

    /// Create a new deposit monitor with default configuration
    pub fn with_defaults() -> Self {
        Self::new(MonitorConfig::default())
    }

    /// Add a chain to the monitor
    ///
    /// # Arguments
    /// * `chain_id` - The chain identifier
    /// * `client` - The RPC client for this chain
    /// * `finality_blocks` - Number of blocks for finality
    pub fn add_chain(
        &mut self,
        chain_id: ChainId,
        client: Box<dyn RpcClient>,
        finality_blocks: u64,
    ) -> Result<(), MonitorError> {
        if self.chains.contains_key(&chain_id) {
            return Err(MonitorError::ChainAlreadyRegistered(chain_id));
        }

        let monitor = ChainMonitor::new(client, finality_blocks);
        self.chains.insert(chain_id, monitor);
        self.stats.deposits_per_chain.insert(chain_id, 0);
        self.stats.errors_per_chain.insert(chain_id, 0);

        tracing::info!("Added chain {} to deposit monitor", chain_id);
        Ok(())
    }

    /// Add a chain with a specific starting block
    pub fn add_chain_from_block(
        &mut self,
        chain_id: ChainId,
        client: Box<dyn RpcClient>,
        finality_blocks: u64,
        start_block: u64,
    ) -> Result<(), MonitorError> {
        if self.chains.contains_key(&chain_id) {
            return Err(MonitorError::ChainAlreadyRegistered(chain_id));
        }

        let monitor = ChainMonitor::new(client, finality_blocks).with_start_block(start_block);
        self.chains.insert(chain_id, monitor);
        self.stats.deposits_per_chain.insert(chain_id, 0);
        self.stats.errors_per_chain.insert(chain_id, 0);

        tracing::info!(
            "Added chain {} to deposit monitor starting from block {}",
            chain_id,
            start_block
        );
        Ok(())
    }

    /// Remove a chain from the monitor
    pub fn remove_chain(&mut self, chain_id: ChainId) -> Result<(), MonitorError> {
        if self.chains.remove(&chain_id).is_none() {
            return Err(MonitorError::ChainNotFound(chain_id));
        }

        tracing::info!("Removed chain {} from deposit monitor", chain_id);
        Ok(())
    }

    /// Get the current state of a chain monitor
    pub fn get_chain_state(&self, chain_id: ChainId) -> Option<&ChainMonitorState> {
        self.chains.get(&chain_id).map(|m| &m.state)
    }

    /// Get monitor statistics
    pub fn stats(&self) -> &MonitorStats {
        &self.stats
    }

    /// Check if the monitor is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get the number of monitored chains
    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }

    /// Poll all chains once for new deposits
    ///
    /// Returns a vector of new deposits found across all chains.
    pub async fn poll_once(&mut self) -> FluxeResult<Vec<DepositEvent>> {
        let mut all_deposits = Vec::new();

        let chain_ids: Vec<ChainId> = self.chains.keys().copied().collect();

        for chain_id in chain_ids {
            match self.poll_chain(chain_id).await {
                Ok(deposits) => {
                    all_deposits.extend(deposits);
                }
                Err(e) => {
                    tracing::error!("Error polling chain {}: {}", chain_id, e);
                    *self.stats.errors_per_chain.entry(chain_id).or_insert(0) += 1;
                    self.stats.total_errors += 1;

                    if let Some(monitor) = self.chains.get_mut(&chain_id) {
                        monitor.consecutive_errors += 1;
                    }

                    if !self.config.continue_on_error {
                        return Err(e);
                    }
                }
            }
        }

        Ok(all_deposits)
    }

    /// Poll a single chain for new deposits
    async fn poll_chain(&mut self, chain_id: ChainId) -> FluxeResult<Vec<DepositEvent>> {
        let monitor = self.chains.get_mut(&chain_id)
            .ok_or(MonitorError::ChainNotFound(chain_id))?;

        if monitor.polling {
            tracing::debug!("Chain {} is already being polled, skipping", chain_id);
            return Ok(Vec::new());
        }

        monitor.polling = true;

        // Get latest block with retries
        let latest_block = self.get_latest_block_with_retry(chain_id).await?;

        let monitor = self.chains.get_mut(&chain_id).unwrap();

        // Check if there are new blocks to process
        if !monitor.state.has_new_blocks(latest_block) {
            monitor.polling = false;
            return Ok(Vec::new());
        }

        let from_block = monitor.state.last_processed_block + 1;
        let safe_to_block = monitor.state.safe_to_block(latest_block);

        // Limit the number of blocks processed at once
        let to_block = std::cmp::min(
            safe_to_block,
            from_block + self.config.max_blocks_per_poll - 1,
        );

        tracing::debug!(
            "Polling chain {} for deposits from block {} to {}",
            chain_id,
            from_block,
            to_block
        );

        // Get deposit events with retries
        let events = self.get_events_with_retry(chain_id, from_block, to_block).await?;

        // Filter duplicates if enabled
        let events = if self.config.enable_deduplication {
            self.filter_duplicates(events)
        } else {
            events
        };

        // Update state
        let monitor = self.chains.get_mut(&chain_id).unwrap();
        monitor.state.update_last_processed(to_block);
        monitor.consecutive_errors = 0;
        monitor.polling = false;

        // Update stats
        let event_count = events.len() as u64;
        self.stats.total_deposits += event_count;
        *self.stats.deposits_per_chain.entry(chain_id).or_insert(0) += event_count;
        self.stats.total_blocks_processed += to_block - from_block + 1;

        if !events.is_empty() {
            tracing::info!(
                "Found {} deposit(s) on chain {} (blocks {}-{})",
                events.len(),
                chain_id,
                from_block,
                to_block
            );
        }

        Ok(events)
    }

    /// Get the latest block with retry logic
    async fn get_latest_block_with_retry(&self, chain_id: ChainId) -> FluxeResult<u64> {
        let monitor = self.chains.get(&chain_id)
            .ok_or(MonitorError::ChainNotFound(chain_id))?;

        let mut last_error = None;

        for attempt in 0..self.config.max_retries {
            match monitor.client.get_latest_block().await {
                Ok(block) => return Ok(block),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.max_retries - 1 {
                        tracing::warn!(
                            "Retry {}/{} getting latest block for chain {}: {:?}",
                            attempt + 1,
                            self.config.max_retries,
                            chain_id,
                            last_error
                        );
                        sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| FluxeError::Other("Unknown error".to_string())))
    }

    /// Get deposit events with retry logic
    async fn get_events_with_retry(
        &self,
        chain_id: ChainId,
        from_block: u64,
        to_block: u64,
    ) -> FluxeResult<Vec<DepositEvent>> {
        let monitor = self.chains.get(&chain_id)
            .ok_or(MonitorError::ChainNotFound(chain_id))?;

        let mut last_error = None;

        for attempt in 0..self.config.max_retries {
            match monitor.client.get_deposit_events(from_block, to_block).await {
                Ok(events) => return Ok(events),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.max_retries - 1 {
                        tracing::warn!(
                            "Retry {}/{} getting events for chain {}: {:?}",
                            attempt + 1,
                            self.config.max_retries,
                            chain_id,
                            last_error
                        );
                        sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| FluxeError::Other("Unknown error".to_string())))
    }

    /// Filter out duplicate events
    fn filter_duplicates(&mut self, events: Vec<DepositEvent>) -> Vec<DepositEvent> {
        let mut unique_events = Vec::with_capacity(events.len());

        for event in events {
            let event_id = event.unique_id();

            if self.processed_events.contains(&event_id) {
                self.stats.duplicates_filtered += 1;
                tracing::debug!("Filtered duplicate event: {}", event_id.to_hex());
                continue;
            }

            // Add to processed set
            self.processed_events.insert(event_id);

            // Evict old entries if cache is full
            if self.processed_events.len() > self.config.max_dedup_cache_size {
                // Simple eviction: clear half the cache
                // In production, use LRU cache
                let to_remove: Vec<_> = self
                    .processed_events
                    .iter()
                    .take(self.config.max_dedup_cache_size / 2)
                    .cloned()
                    .collect();

                for id in to_remove {
                    self.processed_events.remove(&id);
                }
            }

            unique_events.push(event);
        }

        unique_events
    }

    /// Convert a deposit event to an ingress receipt
    ///
    /// # Arguments
    /// * `event` - The deposit event from the chain
    ///
    /// # Returns
    /// An `IngressReceipt` ready for the sequencer
    pub fn process_deposit(event: &DepositEvent) -> IngressReceipt {
        let mut receipt = IngressReceipt::new(
            event.source_chain,
            event.asset_type,
            event.amount,
            event.beneficiary_cm,
            event.block_number,
        );

        // Set auxiliary data from the ingress hash
        receipt.aux = event.ingress_hash;

        receipt
    }

    /// Run the polling loop
    ///
    /// This method runs continuously, polling for new deposits and calling
    /// the provided callback for each deposit found.
    ///
    /// # Arguments
    /// * `callback` - Async callback invoked for each new deposit event
    ///
    /// # Example
    ///
    /// ```ignore
    /// monitor.poll_loop(|event| async {
    ///     let receipt = DepositMonitor::process_deposit(&event);
    ///     sequencer.add_ingress_receipt(receipt).await
    /// }).await;
    /// ```
    pub async fn poll_loop<F, Fut>(&mut self, mut callback: F) -> FluxeResult<()>
    where
        F: FnMut(DepositEvent) -> Fut,
        Fut: std::future::Future<Output = FluxeResult<()>>,
    {
        if self.running {
            return Err(MonitorError::AlreadyRunning.into());
        }

        self.running = true;
        tracing::info!("Starting deposit monitor poll loop");

        while self.running {
            // Poll all chains
            match self.poll_once().await {
                Ok(deposits) => {
                    // Process each deposit
                    for deposit in deposits {
                        if let Err(e) = callback(deposit.clone()).await {
                            tracing::error!(
                                "Error processing deposit from chain {}: {}",
                                deposit.source_chain,
                                e
                            );

                            if !self.config.continue_on_error {
                                self.running = false;
                                return Err(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error in poll loop: {}", e);

                    if !self.config.continue_on_error {
                        self.running = false;
                        return Err(e);
                    }
                }
            }

            // Wait for next poll interval
            sleep(Duration::from_millis(self.config.poll_interval_ms)).await;
        }

        tracing::info!("Deposit monitor poll loop stopped");
        Ok(())
    }

    /// Stop the polling loop
    pub fn stop(&mut self) {
        self.running = false;
        tracing::info!("Stopping deposit monitor poll loop");
    }

    /// Perform a health check on all chains
    pub async fn health_check(&self) -> HashMap<ChainId, bool> {
        let mut results = HashMap::new();

        for (chain_id, monitor) in &self.chains {
            let healthy = monitor.client.health_check().await.unwrap_or(false);
            results.insert(*chain_id, healthy);
        }

        results
    }
}

/// Thread-safe deposit monitor wrapper
///
/// Wraps `DepositMonitor` in `Arc<RwLock<>>` for safe concurrent access.
pub struct SharedDepositMonitor {
    inner: Arc<RwLock<DepositMonitor>>,
}

impl SharedDepositMonitor {
    /// Create a new shared deposit monitor
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DepositMonitor::new(config))),
        }
    }

    /// Get a read lock on the monitor
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, DepositMonitor> {
        self.inner.read().await
    }

    /// Get a write lock on the monitor
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, DepositMonitor> {
        self.inner.write().await
    }

    /// Clone the inner Arc for sharing
    pub fn clone_inner(&self) -> Arc<RwLock<DepositMonitor>> {
        self.inner.clone()
    }
}

impl Clone for SharedDepositMonitor {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::events::DepositEvent;
    use crate::bridge::BoxFuture;
    use crate::types::Amount;
    use ark_bn254::Fr as F;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    /// Mock RPC client for testing
    struct MockRpcClient {
        chain_id: ChainId,
        bridge_address: String,
        latest_block: u64,
        events: Vec<DepositEvent>,
        healthy: bool,
    }

    impl MockRpcClient {
        fn new(chain_id: ChainId) -> Self {
            Self {
                chain_id,
                bridge_address: format!("0x{:040x}", chain_id),
                latest_block: 1000,
                events: Vec::new(),
                healthy: true,
            }
        }

        fn with_latest_block(mut self, block: u64) -> Self {
            self.latest_block = block;
            self
        }

        fn with_events(mut self, events: Vec<DepositEvent>) -> Self {
            self.events = events;
            self
        }
    }

    impl RpcClient for MockRpcClient {
        fn get_latest_block(&self) -> BoxFuture<'_, FluxeResult<u64>> {
            let block = self.latest_block;
            Box::pin(async move { Ok(block) })
        }

        fn get_deposit_events(
            &self,
            from_block: u64,
            to_block: u64,
        ) -> BoxFuture<'_, FluxeResult<Vec<DepositEvent>>> {
            let events = self.events.clone();
            Box::pin(async move {
                Ok(events
                    .into_iter()
                    .filter(|e| e.block_number >= from_block && e.block_number <= to_block)
                    .collect())
            })
        }

        fn chain_id(&self) -> ChainId {
            self.chain_id
        }

        fn health_check(&self) -> BoxFuture<'_, FluxeResult<bool>> {
            let healthy = self.healthy;
            Box::pin(async move { Ok(healthy) })
        }

        fn bridge_address(&self) -> &str {
            &self.bridge_address
        }
    }

    #[test]
    fn test_monitor_config_default() {
        let config = MonitorConfig::default();
        assert_eq!(config.poll_interval_ms, 5_000);
        assert_eq!(config.max_blocks_per_poll, 1000);
        assert_eq!(config.max_retries, 3);
        assert!(config.enable_deduplication);
    }

    #[test]
    fn test_add_chain() {
        let mut monitor = DepositMonitor::with_defaults();

        let client = Box::new(MockRpcClient::new(1));
        assert!(monitor.add_chain(1, client, 12).is_ok());

        // Adding same chain again should fail
        let client2 = Box::new(MockRpcClient::new(1));
        assert!(matches!(
            monitor.add_chain(1, client2, 12),
            Err(MonitorError::ChainAlreadyRegistered(1))
        ));
    }

    #[test]
    fn test_remove_chain() {
        let mut monitor = DepositMonitor::with_defaults();

        let client = Box::new(MockRpcClient::new(1));
        monitor.add_chain(1, client, 12).unwrap();

        assert!(monitor.remove_chain(1).is_ok());

        // Removing again should fail
        assert!(matches!(
            monitor.remove_chain(1),
            Err(MonitorError::ChainNotFound(1))
        ));
    }

    #[tokio::test]
    async fn test_poll_once_no_events() {
        let mut monitor = DepositMonitor::with_defaults();

        let client = Box::new(MockRpcClient::new(1).with_latest_block(100));
        monitor.add_chain(1, client, 12).unwrap();

        let events = monitor.poll_once().await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_poll_once_with_events() {
        let mut rng = thread_rng();
        let mut monitor = DepositMonitor::with_defaults();

        let events = vec![
            DepositEvent::new(
                1,
                1,
                Amount::from(1_000_000u128),
                F::rand(&mut rng),
                F::rand(&mut rng),
                50,
            ).with_tx_hash([1u8; 32]),
            DepositEvent::new(
                1,
                1,
                Amount::from(2_000_000u128),
                F::rand(&mut rng),
                F::rand(&mut rng),
                60,
            ).with_tx_hash([2u8; 32]),
        ];

        let client = Box::new(
            MockRpcClient::new(1)
                .with_latest_block(100)
                .with_events(events),
        );
        monitor.add_chain(1, client, 12).unwrap();

        let found_events = monitor.poll_once().await.unwrap();
        assert_eq!(found_events.len(), 2);

        // Second poll should find no new events (duplicates filtered)
        let found_events2 = monitor.poll_once().await.unwrap();
        assert!(found_events2.is_empty());

        assert_eq!(monitor.stats.duplicates_filtered, 0); // Events filtered on second poll
    }

    #[tokio::test]
    async fn test_process_deposit() {
        let mut rng = thread_rng();
        let beneficiary_cm = F::rand(&mut rng);
        let ingress_hash = F::rand(&mut rng);

        let event = DepositEvent::new(
            1,
            1,
            Amount::from(1_000_000u128),
            beneficiary_cm,
            ingress_hash,
            12345,
        );

        let receipt = DepositMonitor::process_deposit(&event);

        assert_eq!(receipt.source_chain, 1);
        assert_eq!(receipt.asset_type, 1);
        assert_eq!(receipt.amount, Amount::from(1_000_000u128));
        assert_eq!(receipt.beneficiary_cm, beneficiary_cm);
        assert_eq!(receipt.nonce, 12345);
        assert_eq!(receipt.aux, ingress_hash);
    }

    #[tokio::test]
    async fn test_health_check() {
        let mut monitor = DepositMonitor::with_defaults();

        let client1 = Box::new(MockRpcClient::new(1));
        let client2 = Box::new(MockRpcClient::new(2));

        monitor.add_chain(1, client1, 12).unwrap();
        monitor.add_chain(2, client2, 32).unwrap();

        let health = monitor.health_check().await;
        assert_eq!(health.len(), 2);
        assert!(health.get(&1).unwrap_or(&false));
        assert!(health.get(&2).unwrap_or(&false));
    }

    #[test]
    fn test_deduplication() {
        let mut rng = thread_rng();
        let mut monitor = DepositMonitor::with_defaults();

        let event1 = DepositEvent::new(
            1,
            1,
            Amount::from(1_000_000u128),
            F::rand(&mut rng),
            F::rand(&mut rng),
            100,
        ).with_tx_hash([1u8; 32]).with_log_index(0);

        let event1_duplicate = event1.clone();

        let event2 = DepositEvent::new(
            1,
            1,
            Amount::from(2_000_000u128),
            F::rand(&mut rng),
            F::rand(&mut rng),
            100,
        ).with_tx_hash([1u8; 32]).with_log_index(1);

        // First batch
        let filtered1 = monitor.filter_duplicates(vec![event1.clone(), event2.clone()]);
        assert_eq!(filtered1.len(), 2);

        // Second batch with duplicate
        let filtered2 = monitor.filter_duplicates(vec![event1_duplicate]);
        assert_eq!(filtered2.len(), 0);
        assert_eq!(monitor.stats.duplicates_filtered, 1);
    }

    #[test]
    fn test_chain_monitor_state() {
        let client = Box::new(MockRpcClient::new(1));
        let monitor = ChainMonitor::new(client, 12);

        assert_eq!(monitor.state.chain_id, 1);
        assert_eq!(monitor.state.finality_blocks, 12);
        assert_eq!(monitor.state.last_processed_block, 0);
        assert!(monitor.state.active);
    }

    #[test]
    fn test_chain_monitor_with_start_block() {
        let client = Box::new(MockRpcClient::new(1));
        let monitor = ChainMonitor::new(client, 12).with_start_block(500);

        assert_eq!(monitor.state.last_processed_block, 500);
    }
}
