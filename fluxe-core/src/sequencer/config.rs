/// Sequencer configuration
use std::time::Duration;

use crate::types::ChainId;

/// Configuration for a single chain's sequencer
#[derive(Debug, Clone)]
pub struct ChainSequencerConfig {
    /// Chain identifier
    pub chain_id: ChainId,

    /// Minimum time between batches
    pub batch_interval: Duration,

    /// Maximum transactions per batch
    pub max_batch_size: usize,

    /// Minimum transactions to trigger batch (before timeout)
    pub min_batch_size: usize,

    /// Maximum time to wait for more transactions before forcing batch
    pub max_batch_delay: Duration,

    /// Whether this chain is enabled for sequencing
    pub enabled: bool,
}

impl Default for ChainSequencerConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            batch_interval: Duration::from_secs(10),
            max_batch_size: 100,
            min_batch_size: 10,
            max_batch_delay: Duration::from_secs(60),
            enabled: true,
        }
    }
}

impl ChainSequencerConfig {
    /// Create a new configuration for a specific chain
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            ..Default::default()
        }
    }

    /// Builder: Set batch interval
    pub fn with_batch_interval(mut self, interval: Duration) -> Self {
        self.batch_interval = interval;
        self
    }

    /// Builder: Set max batch size
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Builder: Set min batch size
    pub fn with_min_batch_size(mut self, size: usize) -> Self {
        self.min_batch_size = size;
        self
    }
}

/// Global sequencer configuration
#[derive(Debug, Clone)]
pub struct SequencerConfig {
    /// Per-chain configurations
    pub chains: Vec<ChainSequencerConfig>,

    /// Global batch coordination interval (for cross-chain syncing)
    pub coordination_interval: Duration,

    /// Number of confirmations required before finalizing
    pub finality_confirmations: u64,

    /// Whether to enable automatic batching
    pub auto_batch_enabled: bool,

    /// Maximum pending transactions across all chains
    pub global_max_pending: usize,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            chains: vec![],
            coordination_interval: Duration::from_secs(30),
            finality_confirmations: 32,
            auto_batch_enabled: true,
            global_max_pending: 10_000,
        }
    }
}

impl SequencerConfig {
    /// Create a new sequencer configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a chain configuration
    pub fn add_chain(&mut self, config: ChainSequencerConfig) {
        self.chains.push(config);
    }

    /// Get chain configuration by ID
    pub fn get_chain(&self, chain_id: ChainId) -> Option<&ChainSequencerConfig> {
        self.chains.iter().find(|c| c.chain_id == chain_id)
    }

    /// Check if a chain is configured
    pub fn has_chain(&self, chain_id: ChainId) -> bool {
        self.chains.iter().any(|c| c.chain_id == chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_config_default() {
        let config = ChainSequencerConfig::default();
        assert_eq!(config.chain_id, 1);
        assert_eq!(config.batch_interval, Duration::from_secs(10));
        assert_eq!(config.max_batch_size, 100);
        assert!(config.enabled);
    }

    #[test]
    fn test_chain_config_builder() {
        let config = ChainSequencerConfig::new(501)
            .with_batch_interval(Duration::from_secs(5))
            .with_max_batch_size(50);

        assert_eq!(config.chain_id, 501);
        assert_eq!(config.batch_interval, Duration::from_secs(5));
        assert_eq!(config.max_batch_size, 50);
    }

    #[test]
    fn test_sequencer_config() {
        let mut config = SequencerConfig::new();

        config.add_chain(ChainSequencerConfig::new(1));
        config.add_chain(ChainSequencerConfig::new(501));

        assert!(config.has_chain(1));
        assert!(config.has_chain(501));
        assert!(!config.has_chain(999));

        assert_eq!(config.get_chain(1).unwrap().chain_id, 1);
        assert_eq!(config.get_chain(501).unwrap().chain_id, 501);
    }
}
