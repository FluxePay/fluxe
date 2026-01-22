/// Multi-chain sequencer coordinator
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn, error};

use crate::errors::FluxeError;
use crate::server_verifier::VerifiedTransaction;
use crate::state_manager::GlobalStateManager;
use crate::types::*;
use super::chain_sequencer::ChainSequencer;
use super::config::{ChainSequencerConfig, SequencerConfig};

/// Global statistics for the multi-chain sequencer
#[derive(Debug, Clone, Default)]
pub struct MultiChainSequencerStats {
    /// Total transactions across all chains
    pub total_transactions: u64,
    /// Total batches across all chains
    pub total_batches: u64,
    /// Per-chain pending counts
    pub pending_by_chain: HashMap<ChainId, usize>,
    /// Active chain count
    pub active_chains: usize,
}

/// Status of a chain's sequencer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Sequencer is running normally
    Active,
    /// Sequencer is paused (manual pause)
    Paused,
    /// Sequencer is disabled (config)
    Disabled,
    /// Sequencer encountered an error
    Error(String),
}

/// Multi-chain sequencer that coordinates batch processing across chains
pub struct MultiChainSequencer {
    /// Global state manager (shared across chains)
    pub global_state: Arc<RwLock<GlobalStateManager>>,
    /// Per-chain sequencers
    chains: HashMap<ChainId, ChainSequencer>,
    /// Sequencer configuration
    pub config: SequencerConfig,
    /// Chain status tracking
    chain_status: HashMap<ChainId, ChainStatus>,
    /// Global statistics
    stats: MultiChainSequencerStats,
}

impl MultiChainSequencer {
    /// Create a new multi-chain sequencer
    pub fn new(global_state: GlobalStateManager, config: SequencerConfig) -> Self {
        let mut chains = HashMap::new();
        let mut chain_status = HashMap::new();

        // Initialize per-chain sequencers from config
        for chain_config in &config.chains {
            let chain_id = chain_config.chain_id;
            let sequencer = ChainSequencer::new(chain_config.clone());
            chains.insert(chain_id, sequencer);

            let status = if chain_config.enabled {
                ChainStatus::Active
            } else {
                ChainStatus::Disabled
            };
            chain_status.insert(chain_id, status);
        }

        Self {
            global_state: Arc::new(RwLock::new(global_state)),
            chains,
            config,
            chain_status,
            stats: MultiChainSequencerStats::default(),
        }
    }

    /// Register a new chain with the sequencer
    pub fn register_chain(&mut self, config: ChainSequencerConfig) -> Result<(), FluxeError> {
        let chain_id = config.chain_id;

        if self.chains.contains_key(&chain_id) {
            return Err(FluxeError::Other(format!(
                "Chain {} already registered",
                chain_id
            )));
        }

        // Also register with global state manager
        {
            let mut state = self.global_state.write().unwrap();
            state.register_chain(chain_id, ChainType::EVM)?;
        }

        let status = if config.enabled {
            ChainStatus::Active
        } else {
            ChainStatus::Disabled
        };

        let sequencer = ChainSequencer::new(config.clone());
        self.chains.insert(chain_id, sequencer);
        self.chain_status.insert(chain_id, status);
        self.config.add_chain(config);

        info!("Registered chain {} with sequencer", chain_id);
        Ok(())
    }

    /// Submit a transaction to the appropriate chain's queue
    pub fn submit_transaction(
        &mut self,
        chain_id: ChainId,
        tx: VerifiedTransaction,
        fee: Amount,
    ) -> Result<(), FluxeError> {
        // Check chain status
        match self.chain_status.get(&chain_id) {
            Some(ChainStatus::Active) => {}
            Some(ChainStatus::Paused) => {
                return Err(FluxeError::Other(format!(
                    "Chain {} is paused",
                    chain_id
                )));
            }
            Some(ChainStatus::Disabled) => {
                return Err(FluxeError::Other(format!(
                    "Chain {} is disabled",
                    chain_id
                )));
            }
            Some(ChainStatus::Error(msg)) => {
                return Err(FluxeError::Other(format!(
                    "Chain {} is in error state: {}",
                    chain_id, msg
                )));
            }
            None => {
                return Err(FluxeError::Other(format!(
                    "Chain {} not registered",
                    chain_id
                )));
            }
        }

        // Check global pending limit
        let total_pending: usize = self.chains.values().map(|s| s.pending_count()).sum();
        if total_pending >= self.config.global_max_pending {
            return Err(FluxeError::Other(
                "Global pending transaction limit reached".to_string()
            ));
        }

        // Add to chain's queue
        let sequencer = self.chains.get_mut(&chain_id).ok_or_else(|| {
            FluxeError::Other(format!("Chain {} sequencer not found", chain_id))
        })?;

        sequencer.add_transaction(tx, fee)?;
        self.update_stats();

        debug!("Transaction submitted to chain {} queue", chain_id);
        Ok(())
    }

    /// Process batches for all chains that are ready
    pub fn process_pending_batches(&mut self) -> Result<Vec<(ChainId, Vec<VerifiedTransaction>)>, FluxeError> {
        let mut processed_batches = Vec::new();

        for (chain_id, sequencer) in &mut self.chains {
            // Skip if chain is not active
            if self.chain_status.get(chain_id) != Some(&ChainStatus::Active) {
                continue;
            }

            if sequencer.should_create_batch() {
                if let Some(batch) = sequencer.create_batch() {
                    info!(
                        "Created batch for chain {} with {} transactions",
                        chain_id,
                        batch.len()
                    );
                    processed_batches.push((*chain_id, batch));
                }
            }
        }

        // Update global statistics
        if !processed_batches.is_empty() {
            self.stats.total_batches += processed_batches.len() as u64;
            let tx_count: usize = processed_batches.iter().map(|(_, b)| b.len()).sum();
            self.stats.total_transactions += tx_count as u64;
        }

        self.update_stats();
        Ok(processed_batches)
    }

    /// Process batch for a specific chain
    pub fn process_chain_batch(&mut self, chain_id: ChainId) -> Result<Option<Vec<VerifiedTransaction>>, FluxeError> {
        // Check chain status
        if self.chain_status.get(&chain_id) != Some(&ChainStatus::Active) {
            return Err(FluxeError::Other(format!(
                "Chain {} is not active",
                chain_id
            )));
        }

        let sequencer = self.chains.get_mut(&chain_id).ok_or_else(|| {
            FluxeError::Other(format!("Chain {} not registered", chain_id))
        })?;

        let batch = sequencer.create_batch();

        if batch.is_some() {
            self.stats.total_batches += 1;
            self.stats.total_transactions += batch.as_ref().map(|b| b.len()).unwrap_or(0) as u64;
            self.update_stats();
        }

        Ok(batch)
    }

    /// Pause a chain's sequencer
    pub fn pause_chain(&mut self, chain_id: ChainId) -> Result<(), FluxeError> {
        if !self.chains.contains_key(&chain_id) {
            return Err(FluxeError::Other(format!(
                "Chain {} not registered",
                chain_id
            )));
        }

        self.chain_status.insert(chain_id, ChainStatus::Paused);
        warn!("Chain {} sequencer paused", chain_id);
        Ok(())
    }

    /// Resume a paused chain's sequencer
    pub fn resume_chain(&mut self, chain_id: ChainId) -> Result<(), FluxeError> {
        let status = self.chain_status.get(&chain_id).ok_or_else(|| {
            FluxeError::Other(format!("Chain {} not registered", chain_id))
        })?;

        match status {
            ChainStatus::Paused => {
                self.chain_status.insert(chain_id, ChainStatus::Active);
                info!("Chain {} sequencer resumed", chain_id);
                Ok(())
            }
            ChainStatus::Disabled => {
                Err(FluxeError::Other(format!(
                    "Chain {} is disabled, cannot resume",
                    chain_id
                )))
            }
            _ => Ok(())
        }
    }

    /// Mark a chain as in error state
    pub fn set_chain_error(&mut self, chain_id: ChainId, error: String) {
        if self.chains.contains_key(&chain_id) {
            self.chain_status.insert(chain_id, ChainStatus::Error(error.clone()));
            error!("Chain {} entered error state: {}", chain_id, error);
        }
    }

    /// Clear error state and resume chain
    pub fn clear_chain_error(&mut self, chain_id: ChainId) -> Result<(), FluxeError> {
        let status = self.chain_status.get(&chain_id).ok_or_else(|| {
            FluxeError::Other(format!("Chain {} not registered", chain_id))
        })?;

        if matches!(status, ChainStatus::Error(_)) {
            self.chain_status.insert(chain_id, ChainStatus::Active);
            info!("Chain {} error cleared, resuming", chain_id);
        }

        Ok(())
    }

    /// Get chain status
    pub fn get_chain_status(&self, chain_id: ChainId) -> Option<&ChainStatus> {
        self.chain_status.get(&chain_id)
    }

    /// Get global statistics
    pub fn stats(&self) -> &MultiChainSequencerStats {
        &self.stats
    }

    /// Get chain-specific statistics
    pub fn chain_stats(&self, chain_id: ChainId) -> Option<&super::chain_sequencer::ChainSequencerStats> {
        self.chains.get(&chain_id).map(|s| s.stats())
    }

    /// Get pending transaction count for a chain
    pub fn pending_count(&self, chain_id: ChainId) -> Option<usize> {
        self.chains.get(&chain_id).map(|s| s.pending_count())
    }

    /// Get total pending count across all chains
    pub fn total_pending_count(&self) -> usize {
        self.chains.values().map(|s| s.pending_count()).sum()
    }

    /// Get list of registered chain IDs
    pub fn registered_chains(&self) -> Vec<ChainId> {
        self.chains.keys().copied().collect()
    }

    /// Check if sequencer has any pending transactions
    pub fn has_pending(&self) -> bool {
        self.chains.values().any(|s| s.has_pending())
    }

    /// Update global statistics
    fn update_stats(&mut self) {
        self.stats.pending_by_chain = self.chains
            .iter()
            .map(|(id, s)| (*id, s.pending_count()))
            .collect();

        self.stats.active_chains = self.chain_status
            .values()
            .filter(|s| **s == ChainStatus::Active)
            .count();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_verifier::TransactionData;
    use ark_bn254::Fr as F;
    use ark_groth16::Proof;

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

    #[test]
    fn test_multi_chain_sequencer_creation() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let sequencer = MultiChainSequencer::new(gsm, config);

        assert_eq!(sequencer.registered_chains().len(), 0);
        assert!(!sequencer.has_pending());
    }

    #[test]
    fn test_chain_registration() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let chain_config = ChainSequencerConfig::new(1);
        sequencer.register_chain(chain_config).unwrap();

        assert!(sequencer.registered_chains().contains(&1));
        assert_eq!(sequencer.get_chain_status(1), Some(&ChainStatus::Active));
    }

    #[test]
    fn test_transaction_submission() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let chain_config = ChainSequencerConfig::new(1);
        sequencer.register_chain(chain_config).unwrap();

        let tx = create_mock_transaction(TransactionType::Transfer);
        sequencer.submit_transaction(1, tx, Amount::from(100u128)).unwrap();

        assert_eq!(sequencer.pending_count(1), Some(1));
        assert_eq!(sequencer.total_pending_count(), 1);
    }

    #[test]
    fn test_unregistered_chain_submission() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let tx = create_mock_transaction(TransactionType::Transfer);
        let result = sequencer.submit_transaction(999, tx, Amount::from(100u128));

        assert!(result.is_err());
    }

    #[test]
    fn test_chain_pause_resume() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let chain_config = ChainSequencerConfig::new(1);
        sequencer.register_chain(chain_config).unwrap();

        // Pause chain
        sequencer.pause_chain(1).unwrap();
        assert_eq!(sequencer.get_chain_status(1), Some(&ChainStatus::Paused));

        // Try to submit - should fail
        let tx = create_mock_transaction(TransactionType::Transfer);
        let result = sequencer.submit_transaction(1, tx, Amount::from(100u128));
        assert!(result.is_err());

        // Resume chain
        sequencer.resume_chain(1).unwrap();
        assert_eq!(sequencer.get_chain_status(1), Some(&ChainStatus::Active));

        // Submit should work now
        let tx2 = create_mock_transaction(TransactionType::Transfer);
        sequencer.submit_transaction(1, tx2, Amount::from(100u128)).unwrap();
        assert_eq!(sequencer.pending_count(1), Some(1));
    }

    #[test]
    fn test_chain_error_state() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let chain_config = ChainSequencerConfig::new(1);
        sequencer.register_chain(chain_config).unwrap();

        // Set error
        sequencer.set_chain_error(1, "Test error".to_string());
        assert!(matches!(
            sequencer.get_chain_status(1),
            Some(ChainStatus::Error(_))
        ));

        // Try to submit - should fail
        let tx = create_mock_transaction(TransactionType::Transfer);
        let result = sequencer.submit_transaction(1, tx, Amount::from(100u128));
        assert!(result.is_err());

        // Clear error
        sequencer.clear_chain_error(1).unwrap();
        assert_eq!(sequencer.get_chain_status(1), Some(&ChainStatus::Active));
    }

    #[test]
    fn test_process_batch() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let chain_config = ChainSequencerConfig::new(1)
            .with_max_batch_size(5)
            .with_min_batch_size(2);
        sequencer.register_chain(chain_config).unwrap();

        // Add transactions
        for _ in 0..5 {
            let tx = create_mock_transaction(TransactionType::Transfer);
            sequencer.submit_transaction(1, tx, Amount::from(100u128)).unwrap();
        }

        // Process batch
        let batch = sequencer.process_chain_batch(1).unwrap();
        assert!(batch.is_some());
        assert_eq!(batch.unwrap().len(), 5);
        assert_eq!(sequencer.pending_count(1), Some(0));
    }

    #[test]
    fn test_global_pending_limit() {
        let gsm = GlobalStateManager::new(26);
        let mut config = SequencerConfig::new();
        config.global_max_pending = 5;
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let chain_config = ChainSequencerConfig::new(1);
        sequencer.register_chain(chain_config).unwrap();

        // Add transactions up to limit
        for i in 0..5 {
            let tx = create_mock_transaction(TransactionType::Transfer);
            sequencer.submit_transaction(1, tx, Amount::from(i as u128)).unwrap();
        }

        // Next should fail
        let tx = create_mock_transaction(TransactionType::Transfer);
        let result = sequencer.submit_transaction(1, tx, Amount::from(100u128));
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_chain_batching() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        // Register two chains
        let eth_config = ChainSequencerConfig::new(1)
            .with_max_batch_size(3)
            .with_min_batch_size(2);
        let sol_config = ChainSequencerConfig::new(501)
            .with_max_batch_size(3)
            .with_min_batch_size(2);

        sequencer.register_chain(eth_config).unwrap();
        sequencer.register_chain(sol_config).unwrap();

        // Add transactions to both chains
        for _ in 0..3 {
            let tx1 = create_mock_transaction(TransactionType::Transfer);
            let tx2 = create_mock_transaction(TransactionType::Transfer);
            sequencer.submit_transaction(1, tx1, Amount::from(100u128)).unwrap();
            sequencer.submit_transaction(501, tx2, Amount::from(100u128)).unwrap();
        }

        // Process all pending batches
        let batches = sequencer.process_pending_batches().unwrap();
        assert_eq!(batches.len(), 2); // One batch per chain

        assert_eq!(sequencer.stats().total_batches, 2);
        assert_eq!(sequencer.stats().total_transactions, 6);
    }

    #[test]
    fn test_statistics() {
        let gsm = GlobalStateManager::new(26);
        let config = SequencerConfig::new();
        let mut sequencer = MultiChainSequencer::new(gsm, config);

        let chain_config = ChainSequencerConfig::new(1);
        sequencer.register_chain(chain_config).unwrap();

        // Add transactions
        for _ in 0..5 {
            let tx = create_mock_transaction(TransactionType::Transfer);
            sequencer.submit_transaction(1, tx, Amount::from(100u128)).unwrap();
        }

        let stats = sequencer.stats();
        assert_eq!(stats.active_chains, 1);
        assert_eq!(stats.pending_by_chain.get(&1), Some(&5));
    }
}
