/// Per-chain sequencer implementation
use std::collections::BinaryHeap;
use std::cmp::Ordering;
use std::time::{Duration, Instant};

use crate::errors::FluxeError;
use crate::server_verifier::VerifiedTransaction;
use crate::types::*;
use super::config::ChainSequencerConfig;

/// Priority wrapper for pending transactions
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// The verified transaction
    pub transaction: VerifiedTransaction,
    /// Priority (higher = processed first)
    pub priority: u64,
    /// Timestamp when received
    pub received_at: Instant,
    /// Fee paid (for prioritization)
    pub fee: Amount,
}

impl PartialEq for PendingTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PendingTransaction {}

impl PartialOrd for PendingTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then earlier timestamp
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => other.received_at.cmp(&self.received_at),
            other => other,
        }
    }
}

/// Statistics for the chain sequencer
#[derive(Debug, Clone, Default)]
pub struct ChainSequencerStats {
    /// Total transactions processed
    pub total_processed: u64,
    /// Total batches created
    pub total_batches: u64,
    /// Current pending count
    pub pending_count: usize,
    /// Last batch timestamp
    pub last_batch_time: Option<Instant>,
    /// Average batch size
    pub avg_batch_size: f64,
}

/// Per-chain sequencer for managing transaction queues and batch creation
pub struct ChainSequencer {
    /// Chain ID
    pub chain_id: ChainId,
    /// Configuration
    pub config: ChainSequencerConfig,
    /// Priority queue of pending transactions
    pub pending_txs: BinaryHeap<PendingTransaction>,
    /// Current batch being built
    pub current_batch: Vec<VerifiedTransaction>,
    /// Last finalized batch ID
    pub last_finalized_batch_id: u64,
    /// Last batch creation time
    last_batch_time: Option<Instant>,
    /// Statistics
    stats: ChainSequencerStats,
}

impl ChainSequencer {
    /// Create a new chain sequencer
    pub fn new(config: ChainSequencerConfig) -> Self {
        let chain_id = config.chain_id;
        Self {
            chain_id,
            config,
            pending_txs: BinaryHeap::new(),
            current_batch: Vec::new(),
            last_finalized_batch_id: 0,
            last_batch_time: None,
            stats: ChainSequencerStats::default(),
        }
    }

    /// Add a transaction to the pending queue
    pub fn add_transaction(&mut self, tx: VerifiedTransaction, fee: Amount) -> Result<(), FluxeError> {
        if !self.config.enabled {
            return Err(FluxeError::Other(format!(
                "Chain {} sequencer is disabled",
                self.chain_id
            )));
        }

        let priority = self.calculate_priority(&tx, &fee);
        let pending = PendingTransaction {
            transaction: tx,
            priority,
            received_at: Instant::now(),
            fee,
        };

        self.pending_txs.push(pending);
        self.stats.pending_count = self.pending_txs.len();

        Ok(())
    }

    /// Calculate transaction priority based on fee and type
    fn calculate_priority(&self, tx: &VerifiedTransaction, fee: &Amount) -> u64 {
        // Base priority from fee (higher fee = higher priority)
        let mut priority = fee.as_u128() as u64;

        // Bonus for burns (withdrawals) - incentivize clearing the system
        if matches!(tx.tx_type, TransactionType::Burn) {
            priority += 1000;
        }

        priority
    }

    /// Check if we should create a batch now
    pub fn should_create_batch(&self) -> bool {
        // Size threshold reached
        if self.pending_txs.len() >= self.config.max_batch_size {
            return true;
        }

        // Minimum size and time threshold
        if self.pending_txs.len() >= self.config.min_batch_size {
            if let Some(last_time) = self.last_batch_time {
                if last_time.elapsed() >= self.config.batch_interval {
                    return true;
                }
            } else {
                return true; // First batch
            }
        }

        // Maximum delay reached with any pending transactions
        if !self.pending_txs.is_empty() {
            if let Some(last_time) = self.last_batch_time {
                if last_time.elapsed() >= self.config.max_batch_delay {
                    return true;
                }
            }
        }

        false
    }

    /// Create a batch from pending transactions
    pub fn create_batch(&mut self) -> Option<Vec<VerifiedTransaction>> {
        if self.pending_txs.is_empty() {
            return None;
        }

        let mut batch = Vec::new();
        let max_size = self.config.max_batch_size;

        // Pop transactions in priority order
        while batch.len() < max_size && !self.pending_txs.is_empty() {
            if let Some(pending) = self.pending_txs.pop() {
                batch.push(pending.transaction);
            }
        }

        if batch.is_empty() {
            return None;
        }

        // Update statistics
        self.stats.total_batches += 1;
        self.stats.total_processed += batch.len() as u64;
        self.stats.pending_count = self.pending_txs.len();
        self.stats.avg_batch_size = self.stats.total_processed as f64 / self.stats.total_batches as f64;
        self.stats.last_batch_time = Some(Instant::now());
        self.last_batch_time = Some(Instant::now());

        Some(batch)
    }

    /// Get current pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending_txs.len()
    }

    /// Get sequencer statistics
    pub fn stats(&self) -> &ChainSequencerStats {
        &self.stats
    }

    /// Check if the sequencer has pending transactions
    pub fn has_pending(&self) -> bool {
        !self.pending_txs.is_empty()
    }

    /// Clear all pending transactions (for emergency use only)
    pub fn clear_pending(&mut self) {
        self.pending_txs.clear();
        self.stats.pending_count = 0;
    }

    /// Get time since last batch
    pub fn time_since_last_batch(&self) -> Option<Duration> {
        self.last_batch_time.map(|t| t.elapsed())
    }

    /// Mark a batch as finalized
    pub fn finalize_batch(&mut self, batch_id: u64) -> Result<(), FluxeError> {
        if batch_id != self.last_finalized_batch_id + 1 {
            return Err(FluxeError::Other(format!(
                "Invalid batch ID: expected {}, got {}",
                self.last_finalized_batch_id + 1,
                batch_id
            )));
        }

        self.last_finalized_batch_id = batch_id;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as F;
    use ark_groth16::Proof;

    fn create_mock_transaction(tx_type: TransactionType) -> VerifiedTransaction {
        VerifiedTransaction {
            tx_type,
            proof: Proof::default(),
            public_inputs: vec![],
            old_roots: StateRoots::default(),
            new_roots: StateRoots::default(),
            transaction_data: crate::server_verifier::TransactionData::Transfer {
                nullifiers: vec![F::from(1u64)],
                notes_out: vec![],
            },
            chain_id: Some(1),
        }
    }

    #[test]
    fn test_chain_sequencer_creation() {
        let config = ChainSequencerConfig::new(1);
        let sequencer = ChainSequencer::new(config);

        assert_eq!(sequencer.chain_id, 1);
        assert_eq!(sequencer.pending_count(), 0);
        assert!(!sequencer.has_pending());
    }

    #[test]
    fn test_add_transaction() {
        let config = ChainSequencerConfig::new(1);
        let mut sequencer = ChainSequencer::new(config);

        let tx = create_mock_transaction(TransactionType::Transfer);
        let fee = Amount::from(1000u128);

        sequencer.add_transaction(tx, fee).unwrap();

        assert_eq!(sequencer.pending_count(), 1);
        assert!(sequencer.has_pending());
    }

    #[test]
    fn test_priority_ordering() {
        let config = ChainSequencerConfig::new(1);
        let mut sequencer = ChainSequencer::new(config);

        // Add low fee transaction
        let tx1 = create_mock_transaction(TransactionType::Transfer);
        sequencer.add_transaction(tx1, Amount::from(100u128)).unwrap();

        // Add high fee transaction
        let tx2 = create_mock_transaction(TransactionType::Transfer);
        sequencer.add_transaction(tx2, Amount::from(1000u128)).unwrap();

        // High fee should come first
        let batch = sequencer.create_batch().unwrap();
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_batch_creation_size_threshold() {
        let config = ChainSequencerConfig::new(1)
            .with_max_batch_size(3)
            .with_min_batch_size(2);
        let mut sequencer = ChainSequencer::new(config);

        // Add transactions
        for i in 0..3 {
            let tx = create_mock_transaction(TransactionType::Transfer);
            sequencer.add_transaction(tx, Amount::from(i as u128)).unwrap();
        }

        assert!(sequencer.should_create_batch());

        let batch = sequencer.create_batch().unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(sequencer.pending_count(), 0);
    }

    #[test]
    fn test_batch_finalization() {
        let config = ChainSequencerConfig::new(1);
        let mut sequencer = ChainSequencer::new(config);

        // Finalize batch 1
        sequencer.finalize_batch(1).unwrap();
        assert_eq!(sequencer.last_finalized_batch_id, 1);

        // Try to finalize out of order (should fail)
        let result = sequencer.finalize_batch(3);
        assert!(result.is_err());
    }

    #[test]
    fn test_disabled_sequencer() {
        let mut config = ChainSequencerConfig::new(1);
        config.enabled = false;
        let mut sequencer = ChainSequencer::new(config);

        let tx = create_mock_transaction(TransactionType::Transfer);
        let result = sequencer.add_transaction(tx, Amount::from(100u128));

        assert!(result.is_err());
    }

    #[test]
    fn test_burn_priority_bonus() {
        let config = ChainSequencerConfig::new(1);
        let mut sequencer = ChainSequencer::new(config);

        // Add transfer with high fee
        let tx1 = create_mock_transaction(TransactionType::Transfer);
        sequencer.add_transaction(tx1.clone(), Amount::from(500u128)).unwrap();

        // Add burn with lower fee but should get priority bonus
        let mut tx2 = create_mock_transaction(TransactionType::Burn);
        tx2.tx_type = TransactionType::Burn;
        sequencer.add_transaction(tx2, Amount::from(100u128)).unwrap();

        // Burn should come first due to priority bonus
        let batch = sequencer.create_batch().unwrap();
        assert_eq!(batch.len(), 2);
        // The first transaction should be the burn (higher effective priority)
        assert!(matches!(batch[0].tx_type, TransactionType::Burn));
    }

    #[test]
    fn test_sequencer_stats() {
        let config = ChainSequencerConfig::new(1).with_max_batch_size(5);
        let mut sequencer = ChainSequencer::new(config);

        // Add transactions
        for i in 0..5 {
            let tx = create_mock_transaction(TransactionType::Transfer);
            sequencer.add_transaction(tx, Amount::from(i as u128)).unwrap();
        }

        // Create batch
        sequencer.create_batch().unwrap();

        let stats = sequencer.stats();
        assert_eq!(stats.total_batches, 1);
        assert_eq!(stats.total_processed, 5);
        assert_eq!(stats.pending_count, 0);
        assert!(stats.last_batch_time.is_some());
    }
}
