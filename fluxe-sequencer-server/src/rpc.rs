use crate::error::SequencerError;
use crate::state::SharedState;
use crate::types::*;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

/// FLUXE JSON-RPC API
#[rpc(server)]
pub trait FluxeRpc {
    // ============ Transaction Methods ============

    /// Submit a signed transaction proof
    #[method(name = "fluxe_submitTransaction")]
    async fn submit_transaction(
        &self,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse>;

    /// Get transaction status by hash
    #[method(name = "fluxe_getTransactionStatus")]
    async fn get_transaction_status(&self, tx_hash: String) -> RpcResult<TransactionStatusResponse>;

    /// Get multiple transaction statuses
    #[method(name = "fluxe_getTransactionStatuses")]
    async fn get_transaction_statuses(
        &self,
        tx_hashes: Vec<String>,
    ) -> RpcResult<Vec<TransactionStatusResponse>>;

    // ============ Block Methods ============

    /// Get the latest finalized block
    #[method(name = "fluxe_getLatestBlock")]
    async fn get_latest_block(&self) -> RpcResult<Block>;

    /// Get block by batch ID
    #[method(name = "fluxe_getBlock")]
    async fn get_block(&self, batch_id: u64) -> RpcResult<Block>;

    /// Get block header only (lighter)
    #[method(name = "fluxe_getBlockHeader")]
    async fn get_block_header(&self, batch_id: u64) -> RpcResult<BlockHeader>;

    /// Get range of blocks
    #[method(name = "fluxe_getBlocks")]
    async fn get_blocks(&self, from_batch: u64, to_batch: u64) -> RpcResult<Vec<Block>>;

    // ============ State Methods ============

    /// Get current state roots
    #[method(name = "fluxe_getStateRoots")]
    async fn get_state_roots(&self) -> RpcResult<StateRootsJson>;

    /// Get historical roots buffer (64 recent roots)
    #[method(name = "fluxe_getHistoricalRoots")]
    async fn get_historical_roots(&self) -> RpcResult<HistoricalRootsResponse>;

    /// Check if a state root is valid (in historical buffer)
    #[method(name = "fluxe_isValidRoot")]
    async fn is_valid_root(&self, root: String) -> RpcResult<bool>;

    // ============ Account/Note Methods ============

    /// Check if a note commitment exists
    #[method(name = "fluxe_getNoteProof")]
    async fn get_note_proof(&self, commitment: String) -> RpcResult<NoteProof>;

    /// Check if a nullifier has been spent
    #[method(name = "fluxe_checkNullifier")]
    async fn check_nullifier(&self, nullifier: String) -> RpcResult<NullifierStatus>;

    /// Check multiple nullifiers
    #[method(name = "fluxe_checkNullifiers")]
    async fn check_nullifiers(&self, nullifiers: Vec<String>) -> RpcResult<Vec<NullifierStatus>>;

    // ============ Bridge Methods ============

    /// Get deposit info by nonce
    #[method(name = "fluxe_getDeposit")]
    async fn get_deposit(&self, chain_id: u32, nonce: u64) -> RpcResult<Option<DepositInfo>>;

    /// Get pending deposits for a chain
    #[method(name = "fluxe_getPendingDeposits")]
    async fn get_pending_deposits(&self, chain_id: u32) -> RpcResult<Vec<DepositInfo>>;

    /// Get exit proof for withdrawal
    #[method(name = "fluxe_getExitProof")]
    async fn get_exit_proof(&self, exit_hash: String) -> RpcResult<ExitProofResponse>;

    /// Get pool balances across chains
    #[method(name = "fluxe_getPoolBalances")]
    async fn get_pool_balances(&self) -> RpcResult<Vec<PoolBalance>>;

    // ============ Chain Info Methods ============

    /// Get chain info
    #[method(name = "fluxe_chainInfo")]
    async fn chain_info(&self) -> RpcResult<ChainInfoResponse>;

    /// Get sync status
    #[method(name = "fluxe_syncStatus")]
    async fn sync_status(&self) -> RpcResult<SyncStatus>;

    /// Estimate fee for transaction
    #[method(name = "fluxe_estimateFee")]
    async fn estimate_fee(&self, request: FeeEstimateRequest) -> RpcResult<FeeEstimateResponse>;

    /// Health check
    #[method(name = "fluxe_health")]
    async fn health(&self) -> RpcResult<bool>;

    // ============ Standard Ethereum-compatible Methods ============
    // (for wallet compatibility)

    /// Get chain ID (eth_chainId compatible)
    #[method(name = "eth_chainId")]
    async fn eth_chain_id(&self) -> RpcResult<String>;

    /// Get block number (eth_blockNumber compatible)
    #[method(name = "eth_blockNumber")]
    async fn eth_block_number(&self) -> RpcResult<String>;
}

/// RPC implementation
pub struct FluxeRpcImpl {
    state: SharedState,
}

impl FluxeRpcImpl {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

#[jsonrpsee::core::async_trait]
impl FluxeRpcServer for FluxeRpcImpl {
    async fn submit_transaction(
        &self,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse> {
        self.state
            .submit_transaction(request)
            .map_err(|e| e.into())
    }

    async fn get_transaction_status(&self, tx_hash: String) -> RpcResult<TransactionStatusResponse> {
        self.state
            .get_transaction_status(&tx_hash)
            .map_err(|e| e.into())
    }

    async fn get_transaction_statuses(
        &self,
        tx_hashes: Vec<String>,
    ) -> RpcResult<Vec<TransactionStatusResponse>> {
        let results: Vec<_> = tx_hashes
            .iter()
            .filter_map(|hash| self.state.get_transaction_status(hash).ok())
            .collect();
        Ok(results)
    }

    async fn get_latest_block(&self) -> RpcResult<Block> {
        self.state.get_latest_block().map_err(|e| e.into())
    }

    async fn get_block(&self, batch_id: u64) -> RpcResult<Block> {
        self.state.get_block(batch_id).map_err(|e| e.into())
    }

    async fn get_block_header(&self, batch_id: u64) -> RpcResult<BlockHeader> {
        let block = self.state.get_block(batch_id).map_err(|e| Into::<jsonrpsee::types::ErrorObjectOwned>::into(e))?;
        Ok(block.header)
    }

    async fn get_blocks(&self, from_batch: u64, to_batch: u64) -> RpcResult<Vec<Block>> {
        let mut blocks = Vec::new();
        for batch_id in from_batch..=to_batch {
            if let Ok(block) = self.state.get_block(batch_id) {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    async fn get_state_roots(&self) -> RpcResult<StateRootsJson> {
        Ok(self.state.get_state_roots())
    }

    async fn get_historical_roots(&self) -> RpcResult<HistoricalRootsResponse> {
        Ok(self.state.get_historical_roots())
    }

    async fn is_valid_root(&self, root: String) -> RpcResult<bool> {
        let root_bytes: [u8; 32] = hex::decode(&root)
            .map_err(|e| SequencerError::InvalidTransaction(format!("Invalid root hex: {}", e)))?
            .try_into()
            .map_err(|_| SequencerError::InvalidTransaction("Root must be 32 bytes".to_string()))?;

        Ok(self
            .state
            .get_historical_roots()
            .roots
            .iter()
            .any(|r| {
                hex::decode(r)
                    .map(|bytes| bytes == root_bytes)
                    .unwrap_or(false)
            }))
    }

    async fn get_note_proof(&self, commitment: String) -> RpcResult<NoteProof> {
        Ok(self.state.check_commitment(&commitment))
    }

    async fn check_nullifier(&self, nullifier: String) -> RpcResult<NullifierStatus> {
        Ok(self.state.check_nullifier(&nullifier))
    }

    async fn check_nullifiers(&self, nullifiers: Vec<String>) -> RpcResult<Vec<NullifierStatus>> {
        Ok(nullifiers
            .iter()
            .map(|n| self.state.check_nullifier(n))
            .collect())
    }

    async fn get_deposit(&self, _chain_id: u32, _nonce: u64) -> RpcResult<Option<DepositInfo>> {
        // TODO: Integrate with bridge state
        Ok(None)
    }

    async fn get_pending_deposits(&self, _chain_id: u32) -> RpcResult<Vec<DepositInfo>> {
        // TODO: Integrate with bridge state
        Ok(vec![])
    }

    async fn get_exit_proof(&self, _exit_hash: String) -> RpcResult<ExitProofResponse> {
        // TODO: Integrate with exit tree
        Err(SequencerError::StateError("Exit proof not found".to_string()).into())
    }

    async fn get_pool_balances(&self) -> RpcResult<Vec<PoolBalance>> {
        // TODO: Integrate with pool state
        Ok(vec![])
    }

    async fn chain_info(&self) -> RpcResult<ChainInfoResponse> {
        Ok(self.state.get_chain_info())
    }

    async fn sync_status(&self) -> RpcResult<SyncStatus> {
        Ok(self.state.get_sync_status())
    }

    async fn estimate_fee(&self, request: FeeEstimateRequest) -> RpcResult<FeeEstimateResponse> {
        Ok(self.state.estimate_fee(&request.tx_type, request.asset_type))
    }

    async fn health(&self) -> RpcResult<bool> {
        Ok(true)
    }

    async fn eth_chain_id(&self) -> RpcResult<String> {
        // Return as hex for Ethereum compatibility
        Ok(format!("0x{:x}", self.state.config.chain_id))
    }

    async fn eth_block_number(&self) -> RpcResult<String> {
        let batch = self.state.get_chain_info().latest_batch;
        Ok(format!("0x{:x}", batch))
    }
}
