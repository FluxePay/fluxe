use serde::{Deserialize, Serialize};

/// Transaction submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded transaction proof (Groth16)
    pub proof: String,
    /// Hex-encoded public inputs
    pub public_inputs: String,
    /// Transaction type: "mint", "burn", "transfer", "object_update"
    pub tx_type: String,
    /// Chain ID for cross-chain transactions (optional)
    pub chain_id: Option<u32>,
}

/// Transaction submission response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    /// Transaction hash (SHA256 of proof + inputs)
    pub tx_hash: String,
    /// Position in queue
    pub queue_position: u64,
    /// Estimated batch inclusion
    pub estimated_batch: Option<u64>,
}

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Pending { queue_position: u64 },
    Processing,
    Included { batch_id: u64, index: u32 },
    Finalized { batch_id: u64, l1_tx_hash: Option<String> },
    Failed { reason: String },
}

/// Transaction status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatusResponse {
    pub tx_hash: String,
    pub status: TransactionStatus,
    pub submitted_at: i64,
    pub tx_type: String,
}

/// Block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub batch_id: u64,
    pub timestamp: i64,
    pub tx_count: u32,
    pub prev_roots_hash: String,
    pub new_roots_hash: String,
    pub proof_hash: String,
}

/// Full block with transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub state_roots: StateRootsJson,
    pub tx_hashes: Vec<String>,
}

/// State roots in JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRootsJson {
    pub cmt_root: String,
    pub nft_root: String,
    pub obj_root: String,
    pub cb_root: String,
    pub ingress_root: String,
    pub exit_root: String,
    pub sanctions_root: String,
    pub pool_rules_root: String,
}

/// Historical roots response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalRootsResponse {
    pub roots: Vec<String>,
    pub current_index: u8,
    pub size: usize,
}

/// Chain info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfoResponse {
    pub chain_id: u32,
    pub chain_name: String,
    pub latest_batch: u64,
    pub pending_txs: u64,
    pub genesis_finalized: bool,
}

/// Account/Note balance query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteQuery {
    /// Hex-encoded commitment to search for
    pub commitment: String,
}

/// Note existence proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteProof {
    pub exists: bool,
    pub root: String,
    pub merkle_path: Option<Vec<String>>,
    pub leaf_index: Option<u64>,
}

/// Nullifier check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierQuery {
    pub nullifier: String,
}

/// Nullifier status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierStatus {
    pub spent: bool,
    pub batch_id: Option<u64>,
}

/// Bridge deposit info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositInfo {
    pub nonce: u64,
    pub asset_type: u32,
    pub amount: String,
    pub beneficiary_cm: String,
    pub source_chain: u32,
    pub ingress_hash: String,
    pub status: String,
}

/// Bridge withdrawal info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalInfo {
    pub exit_hash: String,
    pub asset_type: u32,
    pub amount: String,
    pub recipient: String,
    pub dest_chain: u32,
    pub batch_id: u64,
    pub processed: bool,
}

/// Exit proof for withdrawal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitProofResponse {
    pub exit_hash: String,
    pub merkle_proof: Vec<String>,
    pub leaf_index: u64,
    pub exit_root: String,
    pub batch_id: u64,
}

/// Pool balance info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolBalance {
    pub chain_id: u32,
    pub asset_type: u32,
    pub balance: String,
    pub pending_withdrawals: String,
}

/// Sync status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub is_syncing: bool,
    pub current_batch: u64,
    pub highest_batch: u64,
    pub connected_chains: Vec<ChainSyncInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSyncInfo {
    pub chain_id: u32,
    pub chain_name: String,
    pub l1_block: u64,
    pub finalized_batch: u64,
}

/// Fee estimate request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateRequest {
    pub tx_type: String,
    pub asset_type: u32,
}

/// Fee estimate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateResponse {
    pub base_fee: String,
    pub priority_fee: String,
    pub total_fee: String,
    pub asset_type: u32,
}
