//! Withdrawal processor for cross-chain exits
//!
//! This module implements the withdrawal processing system that tracks exit receipts,
//! generates Merkle proofs after batch finalization, and enables users to claim
//! withdrawals on target chains.
//!
//! # Architecture
//!
//! The WithdrawalProcessor maintains per-chain handlers that track:
//! - Pending withdrawals (waiting for batch finalization)
//! - Ready withdrawals (can be claimed on L1)
//! - Claimed withdrawals (successfully claimed)
//!
//! # Flow
//!
//! 1. User submits burn transaction with exit receipt
//! 2. Exit receipt is added to pending withdrawals
//! 3. Batch is finalized, Merkle proofs are generated
//! 4. User requests withdrawal proof via API
//! 5. User claims on target chain with proof
//! 6. L1 bridge verifies proof and releases assets

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::data_structures::ExitReceipt;
use crate::errors::{FluxeError, FluxeResult, StateError};
use crate::merkle::{IncrementalTree, TreeParams};
use crate::types::{BlockHeader, ChainId, Time};
use ark_bn254::Fr as F;
use ark_serialize::CanonicalSerialize;

use super::types::{
    ChainWithdrawalSummary, PendingWithdrawal, WithdrawalEvent, WithdrawalFailureReason,
    WithdrawalProof, WithdrawalStatus,
};

/// Per-chain handler for managing withdrawals
///
/// Each chain has its own handler tracking withdrawals destined for that chain.
#[derive(Debug)]
pub struct ChainWithdrawalHandler {
    /// Chain ID this handler manages
    pub chain_id: ChainId,

    /// Tree parameters for proof verification
    pub params: TreeParams,

    /// Pending withdrawals indexed by exit hash
    pending_withdrawals: HashMap<[u8; 32], PendingWithdrawal>,

    /// Index: batch_id -> list of exit hashes in that batch
    batch_to_exits: HashMap<u64, Vec<[u8; 32]>>,

    /// Event log for audit trail
    events: Vec<WithdrawalEvent>,
}

impl ChainWithdrawalHandler {
    /// Create a new chain withdrawal handler
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID this handler manages
    /// * `tree_depth` - Depth of the Merkle tree for this chain
    pub fn new(chain_id: ChainId, tree_depth: usize) -> Self {
        Self {
            chain_id,
            params: TreeParams::new(tree_depth),
            pending_withdrawals: HashMap::new(),
            batch_to_exits: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Add a pending withdrawal
    ///
    /// Called when a burn transaction is processed and an exit receipt is created.
    ///
    /// # Arguments
    /// * `exit_receipt` - The exit receipt from the burn
    /// * `batch_id` - The batch ID where this exit is included
    /// * `timestamp` - Current timestamp
    pub fn add_pending_withdrawal(
        &mut self,
        exit_receipt: ExitReceipt,
        batch_id: u64,
        timestamp: Time,
    ) -> FluxeResult<[u8; 32]> {
        let withdrawal = PendingWithdrawal::new(exit_receipt.clone(), batch_id, timestamp);
        let exit_hash = self.field_to_bytes(&withdrawal.exit_hash);

        // Check for duplicate
        if self.pending_withdrawals.contains_key(&exit_hash) {
            return Err(FluxeError::StateManagement(StateError::InvalidTransition {
                from: "existing".to_string(),
                to: "duplicate withdrawal".to_string(),
            }));
        }

        // Add to batch index
        self.batch_to_exits
            .entry(batch_id)
            .or_default()
            .push(exit_hash);

        // Emit event
        self.events.push(WithdrawalEvent::Created {
            exit_hash: withdrawal.exit_hash,
            chain_id: self.chain_id,
            batch_id,
            amount: exit_receipt.amount.as_u128(),
            timestamp,
        });

        // Store the withdrawal
        self.pending_withdrawals.insert(exit_hash, withdrawal);

        Ok(exit_hash)
    }

    /// Process a finalized batch and mark withdrawals as ready
    ///
    /// Called when a batch is finalized on L1. This generates Merkle proofs
    /// for all exit receipts in the batch.
    ///
    /// # Arguments
    /// * `batch_id` - The finalized batch ID
    /// * `exit_tree` - The exit tree at finalization time (for proof generation)
    /// * `finalized_at` - Timestamp of finalization
    pub fn process_finalized_batch(
        &mut self,
        batch_id: u64,
        exit_tree: &IncrementalTree,
        finalized_at: Time,
    ) -> FluxeResult<Vec<[u8; 32]>> {
        let exit_hashes = self.batch_to_exits.get(&batch_id).cloned().unwrap_or_default();

        let mut processed = Vec::new();

        for exit_hash in exit_hashes {
            if let Some(withdrawal) = self.pending_withdrawals.get_mut(&exit_hash) {
                if !withdrawal.is_pending() {
                    continue; // Skip if already processed
                }

                // Generate Merkle proof for this exit receipt
                let receipt_hash = withdrawal.exit_receipt.hash();
                match exit_tree.get_proof(receipt_hash) {
                    Some(proof) => {
                        withdrawal.mark_ready(proof, finalized_at);

                        // Emit event
                        self.events.push(WithdrawalEvent::Ready {
                            exit_hash: withdrawal.exit_hash,
                            chain_id: self.chain_id,
                            batch_id,
                            timestamp: finalized_at,
                        });

                        processed.push(exit_hash);
                    }
                    None => {
                        // Proof generation failed - exit receipt not in tree
                        tracing::error!(
                            "Failed to generate Merkle proof for withdrawal {:?} on chain {} in batch {}. \
                             Exit receipt hash {:?} not found in exit tree.",
                            exit_hash,
                            self.chain_id,
                            batch_id,
                            receipt_hash
                        );

                        // Mark as failed so user knows something went wrong
                        let reason = WithdrawalFailureReason::ProofGenerationFailed;
                        withdrawal.mark_failed(reason);

                        // Emit failure event
                        self.events.push(WithdrawalEvent::Failed {
                            exit_hash: withdrawal.exit_hash,
                            chain_id: self.chain_id,
                            reason,
                            timestamp: finalized_at,
                        });
                    }
                }
            }
        }

        Ok(processed)
    }

    /// Get withdrawal proof for a specific exit hash
    ///
    /// Returns the proof if the withdrawal is ready, None otherwise.
    ///
    /// # Arguments
    /// * `exit_hash` - Hash of the exit receipt
    /// * `exit_root` - Current exit tree root
    pub fn get_withdrawal_proof(
        &self,
        exit_hash: &[u8; 32],
        exit_root: F,
    ) -> Option<WithdrawalProof> {
        let withdrawal = self.pending_withdrawals.get(exit_hash)?;

        if !withdrawal.is_ready() {
            return None;
        }

        let merkle_proof = withdrawal.merkle_proof.clone()?;

        Some(WithdrawalProof::new(
            withdrawal.exit_receipt.clone(),
            merkle_proof,
            withdrawal.batch_id,
            exit_root,
        ))
    }

    /// Mark a withdrawal as claimed
    ///
    /// Called when we receive confirmation that the user claimed on L1.
    ///
    /// # Arguments
    /// * `exit_hash` - Hash of the exit receipt
    /// * `claim_tx` - L1 transaction hash of the claim
    /// * `claimed_at` - Timestamp of claim
    pub fn mark_claimed(
        &mut self,
        exit_hash: &[u8; 32],
        claim_tx: [u8; 32],
        claimed_at: Time,
    ) -> FluxeResult<()> {
        let withdrawal = self.pending_withdrawals.get_mut(exit_hash).ok_or_else(|| {
            FluxeError::Other("Withdrawal not found".to_string())
        })?;

        if !withdrawal.is_ready() {
            return Err(FluxeError::Other(
                "Withdrawal is not ready to be claimed".to_string(),
            ));
        }

        // Emit event
        self.events.push(WithdrawalEvent::Claimed {
            exit_hash: withdrawal.exit_hash,
            chain_id: self.chain_id,
            claim_tx,
            timestamp: claimed_at,
        });

        withdrawal.mark_claimed(claimed_at, claim_tx);
        Ok(())
    }

    /// Mark a withdrawal as failed
    ///
    /// # Arguments
    /// * `exit_hash` - Hash of the exit receipt
    /// * `reason` - Reason for failure
    /// * `timestamp` - Timestamp of failure
    pub fn mark_failed(
        &mut self,
        exit_hash: &[u8; 32],
        reason: WithdrawalFailureReason,
        timestamp: Time,
    ) -> FluxeResult<()> {
        let withdrawal = self.pending_withdrawals.get_mut(exit_hash).ok_or_else(|| {
            FluxeError::Other("Withdrawal not found".to_string())
        })?;

        // Emit event
        self.events.push(WithdrawalEvent::Failed {
            exit_hash: withdrawal.exit_hash,
            chain_id: self.chain_id,
            reason,
            timestamp,
        });

        withdrawal.mark_failed(reason);
        Ok(())
    }

    /// Get status of a withdrawal
    pub fn get_status(&self, exit_hash: &[u8; 32]) -> Option<WithdrawalStatus> {
        self.pending_withdrawals.get(exit_hash).map(|w| w.status)
    }

    /// Get a pending withdrawal by hash
    pub fn get_withdrawal(&self, exit_hash: &[u8; 32]) -> Option<&PendingWithdrawal> {
        self.pending_withdrawals.get(exit_hash)
    }

    /// Get all pending (not yet ready) withdrawals
    pub fn get_pending_withdrawals(&self) -> Vec<&PendingWithdrawal> {
        self.pending_withdrawals
            .values()
            .filter(|w| w.is_pending())
            .collect()
    }

    /// Get all ready (claimable) withdrawals
    pub fn get_ready_withdrawals(&self) -> Vec<&PendingWithdrawal> {
        self.pending_withdrawals
            .values()
            .filter(|w| w.is_ready())
            .collect()
    }

    /// Get summary statistics for this chain
    pub fn get_summary(&self) -> ChainWithdrawalSummary {
        let mut summary = ChainWithdrawalSummary {
            chain_id: self.chain_id,
            ..Default::default()
        };

        for withdrawal in self.pending_withdrawals.values() {
            let amount = withdrawal.exit_receipt.amount.as_u128();

            match withdrawal.status {
                WithdrawalStatus::Pending => {
                    summary.pending_count += 1;
                    summary.pending_amount += amount;
                }
                WithdrawalStatus::Ready => {
                    summary.ready_count += 1;
                    summary.ready_amount += amount;
                }
                WithdrawalStatus::Claimed => {
                    summary.claimed_count += 1;
                }
                WithdrawalStatus::Failed(_) => {
                    summary.failed_count += 1;
                }
            }
        }

        summary
    }

    /// Get recent events
    pub fn get_events(&self, limit: usize) -> Vec<&WithdrawalEvent> {
        self.events.iter().rev().take(limit).collect()
    }

    /// Clear claimed and failed withdrawals older than given timestamp
    ///
    /// This is a garbage collection operation to prevent unbounded memory growth.
    ///
    /// # Arguments
    /// * `older_than` - Remove withdrawals finalized before this timestamp
    pub fn cleanup_old_withdrawals(&mut self, older_than: Time) -> usize {
        let to_remove: Vec<[u8; 32]> = self
            .pending_withdrawals
            .iter()
            .filter(|(_, w)| {
                (w.is_claimed() || w.is_failed())
                    && w.finalized_at.map(|t| t < older_than).unwrap_or(false)
            })
            .map(|(k, _)| *k)
            .collect();

        let count = to_remove.len();
        for hash in to_remove {
            self.pending_withdrawals.remove(&hash);
        }

        count
    }

    /// Convert field element to bytes for indexing
    fn field_to_bytes(&self, field: &F) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let mut cursor = std::io::Cursor::new(&mut bytes[..]);
        field.serialize_compressed(&mut cursor).unwrap_or_default();
        bytes
    }
}

/// Main withdrawal processor managing all chains
///
/// This is the primary interface for the withdrawal processing system.
/// It maintains handlers for each registered chain and provides a unified
/// API for withdrawal management.
#[derive(Debug)]
pub struct WithdrawalProcessor {
    /// Per-chain withdrawal handlers
    chains: HashMap<ChainId, ChainWithdrawalHandler>,

    /// Default tree depth for new chains
    default_tree_depth: usize,
}

impl WithdrawalProcessor {
    /// Create a new withdrawal processor
    ///
    /// # Arguments
    /// * `tree_depth` - Default depth for exit trees
    pub fn new(tree_depth: usize) -> Self {
        Self {
            chains: HashMap::new(),
            default_tree_depth: tree_depth,
        }
    }

    /// Register a chain for withdrawal processing
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID to register
    pub fn register_chain(&mut self, chain_id: ChainId) -> FluxeResult<()> {
        if self.chains.contains_key(&chain_id) {
            return Err(FluxeError::Configuration(format!(
                "Chain {} already registered",
                chain_id
            )));
        }

        let handler = ChainWithdrawalHandler::new(chain_id, self.default_tree_depth);
        self.chains.insert(chain_id, handler);
        Ok(())
    }

    /// Add a pending withdrawal for a chain
    ///
    /// # Arguments
    /// * `chain_id` - Destination chain
    /// * `exit_receipt` - The exit receipt
    /// * `batch_id` - Batch where exit is included
    /// * `timestamp` - Current timestamp
    pub fn add_withdrawal(
        &mut self,
        chain_id: ChainId,
        exit_receipt: ExitReceipt,
        batch_id: u64,
        timestamp: Time,
    ) -> FluxeResult<[u8; 32]> {
        let handler = self.chains.get_mut(&chain_id).ok_or_else(|| {
            FluxeError::Configuration(format!("Chain {} not registered", chain_id))
        })?;

        handler.add_pending_withdrawal(exit_receipt, batch_id, timestamp)
    }

    /// Process a finalized batch for all chains
    ///
    /// This is called when a batch is finalized on L1. It generates proofs
    /// for all exit receipts in the batch.
    ///
    /// # Arguments
    /// * `batch_id` - The finalized batch ID
    /// * `batch_header` - Block header containing state roots
    /// * `chain_exit_trees` - Map of chain_id -> exit tree at finalization
    /// * `finalized_at` - Timestamp of finalization
    pub fn process_finalized_batch(
        &mut self,
        batch_id: u64,
        _batch_header: &BlockHeader,
        chain_exit_trees: &HashMap<ChainId, IncrementalTree>,
        finalized_at: Time,
    ) -> FluxeResult<HashMap<ChainId, Vec<[u8; 32]>>> {
        let mut results = HashMap::new();

        for (chain_id, handler) in &mut self.chains {
            if let Some(exit_tree) = chain_exit_trees.get(chain_id) {
                let processed = handler.process_finalized_batch(batch_id, exit_tree, finalized_at)?;
                if !processed.is_empty() {
                    results.insert(*chain_id, processed);
                }
            }
        }

        Ok(results)
    }

    /// Get withdrawal proof for a specific exit
    ///
    /// # Arguments
    /// * `chain_id` - The destination chain
    /// * `exit_hash` - Hash of the exit receipt
    /// * `exit_root` - Current exit tree root for the chain
    pub fn get_withdrawal_proof(
        &self,
        chain_id: ChainId,
        exit_hash: &[u8; 32],
        exit_root: F,
    ) -> Option<WithdrawalProof> {
        self.chains
            .get(&chain_id)
            .and_then(|h| h.get_withdrawal_proof(exit_hash, exit_root))
    }

    /// Get withdrawal proof using field element hash
    ///
    /// Convenience method that accepts F directly.
    ///
    /// # Arguments
    /// * `chain_id` - The destination chain
    /// * `exit_hash` - Hash as field element
    /// * `exit_root` - Current exit tree root
    pub fn get_withdrawal_proof_by_field(
        &self,
        chain_id: ChainId,
        exit_hash: F,
        exit_root: F,
    ) -> Option<WithdrawalProof> {
        let mut bytes = [0u8; 32];
        let mut cursor = std::io::Cursor::new(&mut bytes[..]);
        exit_hash.serialize_compressed(&mut cursor).ok()?;
        self.get_withdrawal_proof(chain_id, &bytes, exit_root)
    }

    /// Mark a withdrawal as claimed
    pub fn mark_claimed(
        &mut self,
        chain_id: ChainId,
        exit_hash: &[u8; 32],
        claim_tx: [u8; 32],
        claimed_at: Time,
    ) -> FluxeResult<()> {
        let handler = self.chains.get_mut(&chain_id).ok_or_else(|| {
            FluxeError::Configuration(format!("Chain {} not registered", chain_id))
        })?;

        handler.mark_claimed(exit_hash, claim_tx, claimed_at)
    }

    /// Mark a withdrawal as failed
    pub fn mark_failed(
        &mut self,
        chain_id: ChainId,
        exit_hash: &[u8; 32],
        reason: WithdrawalFailureReason,
        timestamp: Time,
    ) -> FluxeResult<()> {
        let handler = self.chains.get_mut(&chain_id).ok_or_else(|| {
            FluxeError::Configuration(format!("Chain {} not registered", chain_id))
        })?;

        handler.mark_failed(exit_hash, reason, timestamp)
    }

    /// Get status of a withdrawal
    pub fn get_status(&self, chain_id: ChainId, exit_hash: &[u8; 32]) -> Option<WithdrawalStatus> {
        self.chains.get(&chain_id).and_then(|h| h.get_status(exit_hash))
    }

    /// Get withdrawal details
    pub fn get_withdrawal(
        &self,
        chain_id: ChainId,
        exit_hash: &[u8; 32],
    ) -> Option<&PendingWithdrawal> {
        self.chains.get(&chain_id).and_then(|h| h.get_withdrawal(exit_hash))
    }

    /// Get summary for all chains
    pub fn get_all_summaries(&self) -> Vec<ChainWithdrawalSummary> {
        self.chains.values().map(|h| h.get_summary()).collect()
    }

    /// Get summary for a specific chain
    pub fn get_chain_summary(&self, chain_id: ChainId) -> Option<ChainWithdrawalSummary> {
        self.chains.get(&chain_id).map(|h| h.get_summary())
    }

    /// Get all pending withdrawals for a chain
    pub fn get_pending_withdrawals(&self, chain_id: ChainId) -> Vec<&PendingWithdrawal> {
        self.chains
            .get(&chain_id)
            .map(|h| h.get_pending_withdrawals())
            .unwrap_or_default()
    }

    /// Get all ready withdrawals for a chain
    pub fn get_ready_withdrawals(&self, chain_id: ChainId) -> Vec<&PendingWithdrawal> {
        self.chains
            .get(&chain_id)
            .map(|h| h.get_ready_withdrawals())
            .unwrap_or_default()
    }

    /// Get registered chain IDs
    pub fn get_registered_chains(&self) -> Vec<ChainId> {
        let mut chains: Vec<ChainId> = self.chains.keys().copied().collect();
        chains.sort_unstable();
        chains
    }

    /// Cleanup old withdrawals across all chains
    ///
    /// # Arguments
    /// * `older_than` - Remove withdrawals finalized before this timestamp
    pub fn cleanup_all(&mut self, older_than: Time) -> usize {
        self.chains
            .values_mut()
            .map(|h| h.cleanup_old_withdrawals(older_than))
            .sum()
    }
}

/// Thread-safe handle to WithdrawalProcessor
///
/// This wrapper provides convenient thread-safe access to the withdrawal processor.
#[derive(Clone)]
pub struct WithdrawalProcessorHandle {
    inner: Arc<RwLock<WithdrawalProcessor>>,
}

impl WithdrawalProcessorHandle {
    /// Create a new handle wrapping a WithdrawalProcessor
    pub fn new(processor: WithdrawalProcessor) -> Self {
        Self {
            inner: Arc::new(RwLock::new(processor)),
        }
    }

    /// Get read access to the processor
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, WithdrawalProcessor> {
        self.inner.read().expect("RwLock poisoned")
    }

    /// Get write access to the processor
    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, WithdrawalProcessor> {
        self.inner.write().expect("RwLock poisoned")
    }
}

impl std::fmt::Debug for WithdrawalProcessorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithdrawalProcessorHandle")
            .field("inner", &"Arc<RwLock<WithdrawalProcessor>>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    use crate::types::Amount;

    fn create_test_exit_receipt(chain_id: ChainId, nonce: u64) -> ExitReceipt {
        let mut rng = thread_rng();
        ExitReceipt {
            destination_chain: chain_id,
            asset_type: 1,
            amount: Amount::from(1000u64),
            burned_nf: F::rand(&mut rng),
            nonce,
            aux: F::from(0),
        }
    }

    #[test]
    fn test_chain_handler_creation() {
        let handler = ChainWithdrawalHandler::new(1, 32);
        assert_eq!(handler.chain_id, 1);
        assert!(handler.pending_withdrawals.is_empty());
    }

    #[test]
    fn test_add_pending_withdrawal() {
        let mut handler = ChainWithdrawalHandler::new(1, 32);
        let receipt = create_test_exit_receipt(1, 1);

        let exit_hash = handler.add_pending_withdrawal(receipt, 5, 1000).unwrap();

        assert_eq!(handler.pending_withdrawals.len(), 1);
        let withdrawal = handler.get_withdrawal(&exit_hash).unwrap();
        assert!(withdrawal.is_pending());
        assert_eq!(withdrawal.batch_id, 5);
    }

    #[test]
    fn test_duplicate_withdrawal_rejected() {
        let mut handler = ChainWithdrawalHandler::new(1, 32);
        let receipt = create_test_exit_receipt(1, 1);

        let exit_hash = handler.add_pending_withdrawal(receipt.clone(), 5, 1000).unwrap();

        // Try to add same receipt again
        let result = handler.add_pending_withdrawal(receipt, 5, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_finalized_batch() {
        let mut handler = ChainWithdrawalHandler::new(1, 32);

        // Add some withdrawals
        let receipt1 = create_test_exit_receipt(1, 1);
        let receipt2 = create_test_exit_receipt(1, 2);

        let hash1 = handler.add_pending_withdrawal(receipt1.clone(), 5, 1000).unwrap();
        let hash2 = handler.add_pending_withdrawal(receipt2.clone(), 5, 1000).unwrap();

        // Create an exit tree with the receipts
        let mut exit_tree = IncrementalTree::new(32);
        exit_tree.append(receipt1.hash());
        exit_tree.append(receipt2.hash());

        // Process finalized batch
        let processed = handler.process_finalized_batch(5, &exit_tree, 2000).unwrap();

        assert_eq!(processed.len(), 2);
        assert!(handler.get_withdrawal(&hash1).unwrap().is_ready());
        assert!(handler.get_withdrawal(&hash2).unwrap().is_ready());
    }

    #[test]
    fn test_get_withdrawal_proof() {
        let mut handler = ChainWithdrawalHandler::new(1, 32);

        let receipt = create_test_exit_receipt(1, 1);
        let exit_hash = handler.add_pending_withdrawal(receipt.clone(), 5, 1000).unwrap();

        // Create exit tree
        let mut exit_tree = IncrementalTree::new(32);
        exit_tree.append(receipt.hash());

        // Finalize
        handler.process_finalized_batch(5, &exit_tree, 2000).unwrap();

        // Get proof
        let exit_root = exit_tree.root();
        let proof = handler.get_withdrawal_proof(&exit_hash, exit_root).unwrap();

        assert_eq!(proof.batch_id, 5);
        assert!(proof.verify(&handler.params));
    }

    #[test]
    fn test_mark_claimed() {
        let mut handler = ChainWithdrawalHandler::new(1, 32);

        let receipt = create_test_exit_receipt(1, 1);
        let exit_hash = handler.add_pending_withdrawal(receipt.clone(), 5, 1000).unwrap();

        // Create exit tree and finalize
        let mut exit_tree = IncrementalTree::new(32);
        exit_tree.append(receipt.hash());
        handler.process_finalized_batch(5, &exit_tree, 2000).unwrap();

        // Mark as claimed
        handler.mark_claimed(&exit_hash, [42u8; 32], 3000).unwrap();

        let withdrawal = handler.get_withdrawal(&exit_hash).unwrap();
        assert!(withdrawal.is_claimed());
        assert_eq!(withdrawal.claim_tx_hash, Some([42u8; 32]));
    }

    #[test]
    fn test_withdrawal_summary() {
        let mut handler = ChainWithdrawalHandler::new(1, 32);

        // Add some withdrawals with different statuses
        let receipt1 = create_test_exit_receipt(1, 1);
        let receipt2 = create_test_exit_receipt(1, 2);
        let receipt3 = create_test_exit_receipt(1, 3);

        let hash1 = handler.add_pending_withdrawal(receipt1.clone(), 5, 1000).unwrap();
        handler.add_pending_withdrawal(receipt2.clone(), 5, 1000).unwrap();
        handler.add_pending_withdrawal(receipt3.clone(), 6, 1000).unwrap(); // Different batch

        // Finalize batch 5 only
        let mut exit_tree = IncrementalTree::new(32);
        exit_tree.append(receipt1.hash());
        exit_tree.append(receipt2.hash());
        handler.process_finalized_batch(5, &exit_tree, 2000).unwrap();

        // Claim one
        handler.mark_claimed(&hash1, [1u8; 32], 3000).unwrap();

        let summary = handler.get_summary();
        assert_eq!(summary.pending_count, 1);  // receipt3
        assert_eq!(summary.ready_count, 1);    // receipt2
        assert_eq!(summary.claimed_count, 1);  // receipt1
    }

    #[test]
    fn test_processor_multi_chain() {
        let mut processor = WithdrawalProcessor::new(32);

        // Register two chains
        processor.register_chain(1).unwrap();  // Ethereum
        processor.register_chain(501).unwrap(); // Solana

        // Add withdrawals to each chain
        let eth_receipt = create_test_exit_receipt(1, 1);
        let sol_receipt = create_test_exit_receipt(501, 1);

        let eth_hash = processor.add_withdrawal(1, eth_receipt.clone(), 5, 1000).unwrap();
        let sol_hash = processor.add_withdrawal(501, sol_receipt.clone(), 5, 1000).unwrap();

        // Verify they're tracked separately
        assert!(processor.get_withdrawal(1, &eth_hash).is_some());
        assert!(processor.get_withdrawal(501, &sol_hash).is_some());
        assert!(processor.get_withdrawal(1, &sol_hash).is_none());
        assert!(processor.get_withdrawal(501, &eth_hash).is_none());
    }

    #[test]
    fn test_processor_batch_finalization() {
        let mut processor = WithdrawalProcessor::new(32);
        processor.register_chain(1).unwrap();

        // Add withdrawals
        let receipt1 = create_test_exit_receipt(1, 1);
        let receipt2 = create_test_exit_receipt(1, 2);

        processor.add_withdrawal(1, receipt1.clone(), 5, 1000).unwrap();
        processor.add_withdrawal(1, receipt2.clone(), 5, 1000).unwrap();

        // Create exit tree
        let mut exit_tree = IncrementalTree::new(32);
        exit_tree.append(receipt1.hash());
        exit_tree.append(receipt2.hash());

        let mut chain_exit_trees = HashMap::new();
        chain_exit_trees.insert(1 as ChainId, exit_tree);

        // Process batch
        let header = BlockHeader {
            prev_roots: crate::types::StateRoots::default(),
            new_roots: crate::types::StateRoots::default(),
            batch_id: 5,
            agg_proof: vec![],
            timestamp: 2000,
            total_fees: crate::types::Amount::zero(),
        };

        let results = processor.process_finalized_batch(5, &header, &chain_exit_trees, 2000).unwrap();

        assert_eq!(results.get(&1).unwrap().len(), 2);

        // All should be ready now
        let ready = processor.get_ready_withdrawals(1);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_cleanup_old_withdrawals() {
        let mut handler = ChainWithdrawalHandler::new(1, 32);

        // Add and claim a withdrawal
        let receipt = create_test_exit_receipt(1, 1);
        let exit_hash = handler.add_pending_withdrawal(receipt.clone(), 5, 1000).unwrap();

        // Create exit tree and finalize
        let mut exit_tree = IncrementalTree::new(32);
        exit_tree.append(receipt.hash());
        handler.process_finalized_batch(5, &exit_tree, 2000).unwrap();

        // Claim it
        handler.mark_claimed(&exit_hash, [1u8; 32], 3000).unwrap();

        // Cleanup (should remove it since it's claimed and older than 5000)
        let removed = handler.cleanup_old_withdrawals(5000);
        assert_eq!(removed, 1);
        assert!(handler.get_withdrawal(&exit_hash).is_none());
    }

    #[test]
    fn test_thread_safe_handle() {
        let processor = WithdrawalProcessor::new(32);
        let handle = WithdrawalProcessorHandle::new(processor);

        // Clone for another "thread"
        let handle_clone = handle.clone();

        // Write access
        {
            let mut proc = handle.write();
            proc.register_chain(1).unwrap();
        }

        // Read access from clone
        {
            let proc = handle_clone.read();
            assert_eq!(proc.get_registered_chains().len(), 1);
        }
    }
}
