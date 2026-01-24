use crate::config::SequencerConfig;
use crate::error::SequencerError;
use crate::types::*;
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Pending transaction in queue
#[derive(Debug, Clone)]
pub struct PendingTx {
    pub tx_hash: String,
    pub tx_type: String,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub chain_id: Option<u32>,
    pub submitted_at: i64,
    pub queue_position: u64,
}

/// Finalized batch/block
#[derive(Debug, Clone)]
pub struct FinalizedBatch {
    pub batch_id: u64,
    pub timestamp: i64,
    pub tx_count: u32,
    pub prev_roots_hash: [u8; 32],
    pub new_roots_hash: [u8; 32],
    pub proof_hash: [u8; 32],
    pub state_roots: StateRootsInternal,
    pub tx_hashes: Vec<String>,
}

/// Internal state roots representation
#[derive(Debug, Clone, Default)]
pub struct StateRootsInternal {
    pub cmt_root: [u8; 32],
    pub nft_root: [u8; 32],
    pub obj_root: [u8; 32],
    pub cb_root: [u8; 32],
    pub ingress_root: [u8; 32],
    pub exit_root: [u8; 32],
    pub sanctions_root: [u8; 32],
    pub pool_rules_root: [u8; 32],
}

impl StateRootsInternal {
    pub fn to_json(&self) -> StateRootsJson {
        StateRootsJson {
            cmt_root: hex::encode(self.cmt_root),
            nft_root: hex::encode(self.nft_root),
            obj_root: hex::encode(self.obj_root),
            cb_root: hex::encode(self.cb_root),
            ingress_root: hex::encode(self.ingress_root),
            exit_root: hex::encode(self.exit_root),
            sanctions_root: hex::encode(self.sanctions_root),
            pool_rules_root: hex::encode(self.pool_rules_root),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.cmt_root);
        hasher.update(self.nft_root);
        hasher.update(self.obj_root);
        hasher.update(self.cb_root);
        hasher.update(self.ingress_root);
        hasher.update(self.exit_root);
        hasher.update(self.sanctions_root);
        hasher.update(self.pool_rules_root);
        hasher.finalize().into()
    }
}

/// Historical roots circular buffer
pub struct HistoricalRoots {
    roots: [[u8; 32]; 64],
    next_index: u8,
}

impl Default for HistoricalRoots {
    fn default() -> Self {
        Self {
            roots: [[0u8; 32]; 64],
            next_index: 0,
        }
    }
}

impl HistoricalRoots {
    pub fn add(&mut self, root: [u8; 32]) {
        self.roots[self.next_index as usize] = root;
        self.next_index = (self.next_index + 1) % 64;
    }

    pub fn contains(&self, root: &[u8; 32]) -> bool {
        if root == &[0u8; 32] {
            return true;
        }
        self.roots.iter().any(|r| r == root)
    }

    pub fn to_response(&self) -> HistoricalRootsResponse {
        HistoricalRootsResponse {
            roots: self.roots.iter().map(hex::encode).collect(),
            current_index: self.next_index,
            size: 64,
        }
    }
}

/// Sequencer state - thread-safe
pub struct SequencerState {
    pub config: SequencerConfig,
    /// Pending transactions (FCFS queue)
    pending_queue: RwLock<VecDeque<PendingTx>>,
    /// Transaction status by hash
    tx_status: DashMap<String, TransactionStatusResponse>,
    /// Finalized batches by ID
    batches: DashMap<u64, FinalizedBatch>,
    /// Current state roots
    current_roots: RwLock<StateRootsInternal>,
    /// Historical roots buffer
    historical_roots: RwLock<HistoricalRoots>,
    /// Latest finalized batch ID
    latest_batch: AtomicU64,
    /// Total tx counter for queue position
    tx_counter: AtomicU64,
    /// Genesis finalized flag
    genesis_finalized: RwLock<bool>,
    /// Last batch creation time
    last_batch_time: RwLock<Option<Instant>>,
    /// Nullifiers (spent)
    nullifiers: DashMap<String, u64>, // nullifier -> batch_id
    /// Note commitments
    commitments: DashMap<String, u64>, // commitment -> leaf_index
}

impl SequencerState {
    pub fn new(config: SequencerConfig) -> Self {
        Self {
            config,
            pending_queue: RwLock::new(VecDeque::new()),
            tx_status: DashMap::new(),
            batches: DashMap::new(),
            current_roots: RwLock::new(StateRootsInternal::default()),
            historical_roots: RwLock::new(HistoricalRoots::default()),
            latest_batch: AtomicU64::new(0),
            tx_counter: AtomicU64::new(0),
            genesis_finalized: RwLock::new(false),
            last_batch_time: RwLock::new(None),
            nullifiers: DashMap::new(),
            commitments: DashMap::new(),
        }
    }

    /// Submit a new transaction (FCFS ordering)
    pub fn submit_transaction(
        &self,
        req: SubmitTransactionRequest,
    ) -> Result<SubmitTransactionResponse, SequencerError> {
        // Check capacity
        let queue_len = self.pending_queue.read().len();
        if queue_len >= self.config.max_pending_txs {
            return Err(SequencerError::SequencerBusy);
        }

        // Decode proof and inputs
        let proof = hex::decode(&req.proof)
            .map_err(|e| SequencerError::InvalidTransaction(format!("Invalid proof hex: {}", e)))?;
        let public_inputs = hex::decode(&req.public_inputs).map_err(|e| {
            SequencerError::InvalidTransaction(format!("Invalid public_inputs hex: {}", e))
        })?;

        // Compute tx hash
        let mut hasher = Sha256::new();
        hasher.update(&proof);
        hasher.update(&public_inputs);
        let tx_hash = hex::encode(hasher.finalize());

        // Check for duplicate
        if self.tx_status.contains_key(&tx_hash) {
            return Err(SequencerError::InvalidTransaction(
                "Transaction already submitted".to_string(),
            ));
        }

        let queue_position = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let submitted_at = Utc::now().timestamp();

        let pending_tx = PendingTx {
            tx_hash: tx_hash.clone(),
            tx_type: req.tx_type.clone(),
            proof,
            public_inputs,
            chain_id: req.chain_id,
            submitted_at,
            queue_position,
        };

        // Add to queue (FCFS - just append)
        self.pending_queue.write().push_back(pending_tx);

        // Record status
        self.tx_status.insert(
            tx_hash.clone(),
            TransactionStatusResponse {
                tx_hash: tx_hash.clone(),
                status: TransactionStatus::Pending {
                    queue_position: queue_position as u64,
                },
                submitted_at,
                tx_type: req.tx_type,
            },
        );

        let current_batch = self.latest_batch.load(Ordering::SeqCst);
        Ok(SubmitTransactionResponse {
            tx_hash,
            queue_position,
            estimated_batch: Some(current_batch + 1),
        })
    }

    /// Get transaction status
    pub fn get_transaction_status(
        &self,
        tx_hash: &str,
    ) -> Result<TransactionStatusResponse, SequencerError> {
        self.tx_status
            .get(tx_hash)
            .map(|v| v.clone())
            .ok_or_else(|| SequencerError::TransactionNotFound(tx_hash.to_string()))
    }

    /// Get latest block
    pub fn get_latest_block(&self) -> Result<Block, SequencerError> {
        let batch_id = self.latest_batch.load(Ordering::SeqCst);
        if batch_id == 0 {
            return Err(SequencerError::BlockNotFound(0));
        }
        self.get_block(batch_id)
    }

    /// Get block by ID
    pub fn get_block(&self, batch_id: u64) -> Result<Block, SequencerError> {
        let batch = self
            .batches
            .get(&batch_id)
            .ok_or(SequencerError::BlockNotFound(batch_id))?;

        Ok(Block {
            header: BlockHeader {
                batch_id: batch.batch_id,
                timestamp: batch.timestamp,
                tx_count: batch.tx_count,
                prev_roots_hash: hex::encode(batch.prev_roots_hash),
                new_roots_hash: hex::encode(batch.new_roots_hash),
                proof_hash: hex::encode(batch.proof_hash),
            },
            state_roots: batch.state_roots.to_json(),
            tx_hashes: batch.tx_hashes.clone(),
        })
    }

    /// Get current state roots
    pub fn get_state_roots(&self) -> StateRootsJson {
        self.current_roots.read().to_json()
    }

    /// Get historical roots
    pub fn get_historical_roots(&self) -> HistoricalRootsResponse {
        self.historical_roots.read().to_response()
    }

    /// Get chain info
    pub fn get_chain_info(&self) -> ChainInfoResponse {
        ChainInfoResponse {
            chain_id: self.config.chain_id,
            chain_name: format!("FLUXE Chain {}", self.config.chain_id),
            latest_batch: self.latest_batch.load(Ordering::SeqCst),
            pending_txs: self.pending_queue.read().len() as u64,
            genesis_finalized: *self.genesis_finalized.read(),
        }
    }

    /// Check if nullifier is spent
    pub fn check_nullifier(&self, nullifier: &str) -> NullifierStatus {
        match self.nullifiers.get(nullifier) {
            Some(batch_id) => NullifierStatus {
                spent: true,
                batch_id: Some(*batch_id),
            },
            None => NullifierStatus {
                spent: false,
                batch_id: None,
            },
        }
    }

    /// Check if commitment exists
    pub fn check_commitment(&self, commitment: &str) -> NoteProof {
        match self.commitments.get(commitment) {
            Some(leaf_index) => NoteProof {
                exists: true,
                root: hex::encode(self.current_roots.read().cmt_root),
                merkle_path: None, // Would need full tree for path
                leaf_index: Some(*leaf_index),
            },
            None => NoteProof {
                exists: false,
                root: hex::encode(self.current_roots.read().cmt_root),
                merkle_path: None,
                leaf_index: None,
            },
        }
    }

    /// Check if batch creation should be triggered
    pub fn should_create_batch(&self) -> bool {
        let queue_len = self.pending_queue.read().len();

        // Size threshold
        if queue_len >= self.config.max_batch_size {
            return true;
        }

        // Min size + time threshold
        if queue_len >= self.config.min_batch_size {
            if let Some(last_time) = *self.last_batch_time.read() {
                if last_time.elapsed() >= self.config.batch_interval() {
                    return true;
                }
            } else {
                return true;
            }
        }

        // Force batch on max delay
        if queue_len > 0 {
            if let Some(last_time) = *self.last_batch_time.read() {
                if last_time.elapsed() >= self.config.max_batch_delay() {
                    return true;
                }
            }
        }

        false
    }

    /// Create a batch from pending transactions
    pub fn create_batch(&self) -> Option<Vec<PendingTx>> {
        if !self.should_create_batch() {
            return None;
        }

        let mut queue = self.pending_queue.write();
        let batch_size = std::cmp::min(queue.len(), self.config.max_batch_size);

        if batch_size == 0 {
            return None;
        }

        let batch: Vec<PendingTx> = queue.drain(..batch_size).collect();
        *self.last_batch_time.write() = Some(Instant::now());

        Some(batch)
    }

    /// Finalize a batch after proof generation
    pub fn finalize_batch(&self, batch: FinalizedBatch) {
        let batch_id = batch.batch_id;

        // Update transaction statuses
        for tx_hash in &batch.tx_hashes {
            if let Some(mut status) = self.tx_status.get_mut(tx_hash) {
                status.status = TransactionStatus::Finalized {
                    batch_id,
                    l1_tx_hash: None,
                };
            }
        }

        // Update state
        *self.current_roots.write() = batch.state_roots.clone();
        self.historical_roots.write().add(batch.new_roots_hash);
        self.latest_batch.store(batch_id, Ordering::SeqCst);

        // Store batch
        self.batches.insert(batch_id, batch);
    }

    /// Finalize genesis
    pub fn finalize_genesis(&self, roots: StateRootsInternal) {
        *self.current_roots.write() = roots.clone();
        self.historical_roots.write().add(roots.hash());
        *self.genesis_finalized.write() = true;
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending_queue.read().len()
    }

    /// Get sync status
    pub fn get_sync_status(&self) -> SyncStatus {
        SyncStatus {
            is_syncing: false,
            current_batch: self.latest_batch.load(Ordering::SeqCst),
            highest_batch: self.latest_batch.load(Ordering::SeqCst),
            connected_chains: vec![ChainSyncInfo {
                chain_id: self.config.chain_id,
                chain_name: format!("FLUXE Chain {}", self.config.chain_id),
                l1_block: 0,
                finalized_batch: self.latest_batch.load(Ordering::SeqCst),
            }],
        }
    }

    /// Estimate fee for transaction type
    pub fn estimate_fee(&self, tx_type: &str, asset_type: u32) -> FeeEstimateResponse {
        // Base fee in smallest unit (e.g., 1000 = 0.001 USDC with 6 decimals)
        let base_fee = match tx_type {
            "transfer" => 1000u64,
            "mint" => 1500u64,
            "burn" => 1500u64,
            "object_update" => 1200u64,
            _ => 2000u64,
        };

        FeeEstimateResponse {
            base_fee: base_fee.to_string(),
            priority_fee: "0".to_string(),
            total_fee: base_fee.to_string(),
            asset_type,
        }
    }
}

/// Shared state handle
pub type SharedState = Arc<SequencerState>;
