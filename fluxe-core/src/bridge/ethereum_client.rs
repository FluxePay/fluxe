//! Ethereum RPC client for bridge event monitoring.
//!
//! This module provides an implementation of the `RpcClient` trait for Ethereum
//! using the ethers-rs library. It handles:
//! - Connecting to Ethereum nodes via HTTP or WebSocket
//! - Querying block numbers and block data
//! - Fetching and parsing deposit events from the FluxeBridge contract
//!
//! # Example
//!
//! ```ignore
//! use fluxe_core::bridge::{EthereumRpcClient, RpcClient};
//! use fluxe_core::config::ChainConfig;
//!
//! let client = EthereumRpcClient::new(
//!     "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY",
//!     "0x1234567890123456789012345678901234567890",
//!     1, // Ethereum mainnet
//! )?;
//!
//! let latest_block = client.get_latest_block().await?;
//! let deposits = client.get_deposit_events(latest_block - 100, latest_block).await?;
//! ```

use crate::bridge::events::DepositEvent;
use crate::bridge::{BoxFuture, RpcClient};
use crate::config::ChainConfig;
use crate::errors::{FluxeError, FluxeResult};
use crate::types::{Amount, ChainId};
use ark_bn254::Fr as F;
use ark_ff::PrimeField;
use ethers::prelude::*;
use ethers::providers::{Http, Middleware, Provider};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Errors specific to Ethereum RPC operations
#[derive(Error, Debug)]
pub enum EthereumRpcError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Contract error: {0}")]
    ContractError(String),

    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Timeout: operation took longer than {0:?}")]
    Timeout(Duration),

    #[error("Block not found: {0}")]
    BlockNotFound(u64),

    #[error("Invalid block range: from {from} to {to}")]
    InvalidBlockRange { from: u64, to: u64 },

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
}

impl From<EthereumRpcError> for FluxeError {
    fn from(e: EthereumRpcError) -> Self {
        FluxeError::Other(e.to_string())
    }
}

impl From<ethers::providers::ProviderError> for EthereumRpcError {
    fn from(e: ethers::providers::ProviderError) -> Self {
        EthereumRpcError::ProviderError(e.to_string())
    }
}

// ABI for the FluxeBridge contract events
// event Deposit(uint32 indexed assetType, uint256 amount, bytes32 beneficiaryCm, bytes32 ingressReceiptHash);
abigen!(
    FluxeBridgeContract,
    r#"[
        event Deposit(uint32 indexed assetType, uint256 amount, bytes32 beneficiaryCm, bytes32 ingressReceiptHash)
        event Withdrawal(uint32 indexed assetType, uint256 amount, address recipient, bytes32 exitReceiptHash)
        function processedDeposits(bytes32) external view returns (bool)
        function processedWithdrawals(bytes32) external view returns (bool)
        function poolBalances(uint32) external view returns (uint256)
    ]"#
);

/// Ethereum RPC client implementation using ethers-rs.
///
/// This client connects to an Ethereum node and monitors the FluxeBridge
/// contract for deposit events. It implements the unified `RpcClient` trait.
pub struct EthereumRpcClient {
    /// The ethers provider for making RPC calls
    provider: Arc<Provider<Http>>,

    /// The FluxeBridge contract instance
    bridge_contract: FluxeBridgeContract<Provider<Http>>,

    /// Chain ID this client is connected to
    chain_id: ChainId,

    /// Bridge contract address (stored as string for trait interface)
    bridge_address_str: String,

    /// Bridge contract address (parsed)
    bridge_address: Address,

    /// Number of confirmations required for finality
    finality_blocks: u64,

    /// Request timeout
    timeout: Duration,
}

impl EthereumRpcClient {
    /// Create a new Ethereum RPC client.
    ///
    /// # Arguments
    /// * `rpc_endpoint` - The Ethereum RPC endpoint URL
    /// * `bridge_address` - The FluxeBridge contract address (0x-prefixed hex)
    /// * `chain_id` - Chain identifier
    ///
    /// # Returns
    /// A new `EthereumRpcClient` instance or an error if initialization fails
    pub fn new(
        rpc_endpoint: &str,
        bridge_address: &str,
        chain_id: ChainId,
    ) -> FluxeResult<Self> {
        // Create the provider
        let provider = Provider::<Http>::try_from(rpc_endpoint)
            .map_err(|e| FluxeError::Configuration(format!("Invalid RPC endpoint: {}", e)))?;

        let provider = Arc::new(provider);

        // Parse the bridge contract address
        let bridge_addr: Address = bridge_address
            .parse()
            .map_err(|e| FluxeError::Configuration(format!("Invalid bridge address: {}", e)))?;

        // Create the contract instance
        let bridge_contract = FluxeBridgeContract::new(bridge_addr, provider.clone());

        Ok(Self {
            provider,
            bridge_contract,
            chain_id,
            bridge_address_str: bridge_address.to_string(),
            bridge_address: bridge_addr,
            finality_blocks: 12, // Default Ethereum finality (can be overridden)
            timeout: Duration::from_secs(30),
        })
    }

    /// Create a new Ethereum RPC client from chain configuration.
    ///
    /// # Arguments
    /// * `config` - The chain configuration
    ///
    /// # Returns
    /// A new `EthereumRpcClient` instance or an error if initialization fails
    pub fn from_config(config: &ChainConfig) -> FluxeResult<Self> {
        let mut client = Self::new(
            &config.rpc_endpoint,
            &config.bridge_address,
            config.chain_id,
        )?;

        client.finality_blocks = config.finality_blocks;

        // Set interval based on block time
        let provider = Provider::<Http>::try_from(&config.rpc_endpoint)
            .map_err(|e| FluxeError::Configuration(format!("Invalid RPC endpoint: {}", e)))?
            .interval(Duration::from_millis(config.block_time_ms / 2));

        client.provider = Arc::new(provider);
        client.bridge_contract = FluxeBridgeContract::new(client.bridge_address, client.provider.clone());

        Ok(client)
    }

    /// Set the number of finality blocks
    pub fn with_finality_blocks(mut self, blocks: u64) -> Self {
        self.finality_blocks = blocks;
        self
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get the provider for direct access (if needed)
    pub fn provider(&self) -> &Arc<Provider<Http>> {
        &self.provider
    }

    /// Get the bridge contract instance
    pub fn bridge_contract(&self) -> &FluxeBridgeContract<Provider<Http>> {
        &self.bridge_contract
    }

    /// Check if a deposit has been processed
    pub async fn is_deposit_processed(&self, deposit_hash: [u8; 32]) -> FluxeResult<bool> {
        self.bridge_contract
            .processed_deposits(deposit_hash)
            .call()
            .await
            .map_err(|e| FluxeError::Other(format!("Contract call failed: {}", e)))
    }

    /// Get the pool balance for an asset type
    pub async fn get_pool_balance(&self, asset_type: u32) -> FluxeResult<U256> {
        self.bridge_contract
            .pool_balances(asset_type)
            .call()
            .await
            .map_err(|e| FluxeError::Other(format!("Contract call failed: {}", e)))
    }

    /// Parse a bytes32 value into a field element
    fn bytes32_to_field(bytes: [u8; 32]) -> F {
        F::from_be_bytes_mod_order(&bytes)
    }

    /// Get block timestamp for a given block number
    async fn get_block_timestamp(&self, block_number: u64) -> FluxeResult<u64> {
        let block = self
            .provider
            .get_block(block_number)
            .await
            .map_err(|e| FluxeError::Other(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| FluxeError::Other(format!("Block {} not found", block_number)))?;

        Ok(block.timestamp.as_u64())
    }

    /// Internal implementation of get_latest_block
    async fn get_latest_block_impl(&self) -> FluxeResult<u64> {
        let block_number = self
            .provider
            .get_block_number()
            .await
            .map_err(|e| FluxeError::Other(format!("Failed to get block number: {}", e)))?;

        // Return the latest finalized block (accounting for confirmations)
        let finalized_block = block_number.as_u64().saturating_sub(self.finality_blocks);

        Ok(finalized_block)
    }

    /// Internal implementation of get_deposit_events
    async fn get_deposit_events_impl(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> FluxeResult<Vec<DepositEvent>> {
        // Validate block range
        if from_block > to_block {
            return Err(FluxeError::Other(format!(
                "Invalid block range: from {} to {}",
                from_block, to_block
            )));
        }

        // Create the event filter
        let filter = self
            .bridge_contract
            .deposit_filter()
            .from_block(from_block)
            .to_block(to_block);

        // Query the logs
        let logs = filter
            .query_with_meta()
            .await
            .map_err(|e| FluxeError::Other(format!("Failed to query events: {}", e)))?;

        // Parse the events
        let mut events = Vec::with_capacity(logs.len());

        for (log, meta) in logs {
            // Get the block timestamp
            let timestamp = self.get_block_timestamp(meta.block_number.as_u64()).await?;

            // Convert bytes32 fields to field elements
            let beneficiary_cm = Self::bytes32_to_field(log.beneficiary_cm);
            let ingress_hash = Self::bytes32_to_field(log.ingress_receipt_hash);

            // Convert amount to our Amount type
            let amount = Amount::from(log.amount.as_u128());

            // Create tx_hash array
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(meta.transaction_hash.as_bytes());

            let event = DepositEvent::new(
                self.chain_id,
                log.asset_type,
                amount,
                beneficiary_cm,
                ingress_hash,
                meta.block_number.as_u64(),
            )
            .with_tx_hash(tx_hash)
            .with_log_index(meta.log_index.as_u64())
            .with_timestamp(timestamp);

            // Validate the event
            event.validate().map_err(|e| FluxeError::Other(e.to_string()))?;

            events.push(event);
        }

        Ok(events)
    }

    /// Internal implementation of health_check
    async fn health_check_impl(&self) -> FluxeResult<bool> {
        match self.provider.get_block_number().await {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::warn!("Health check failed for chain {}: {}", self.chain_id, e);
                Ok(false)
            }
        }
    }
}

impl RpcClient for EthereumRpcClient {
    fn get_latest_block(&self) -> BoxFuture<'_, FluxeResult<u64>> {
        Box::pin(self.get_latest_block_impl())
    }

    fn get_deposit_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> BoxFuture<'_, FluxeResult<Vec<DepositEvent>>> {
        Box::pin(self.get_deposit_events_impl(from_block, to_block))
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn health_check(&self) -> BoxFuture<'_, FluxeResult<bool>> {
        Box::pin(self.health_check_impl())
    }

    fn bridge_address(&self) -> &str {
        &self.bridge_address_str
    }
}

/// Mock Ethereum RPC client for testing
#[cfg(test)]
pub struct MockEthereumRpcClient {
    chain_id: ChainId,
    bridge_address: String,
    latest_block: u64,
    events: Vec<DepositEvent>,
    healthy: bool,
}

#[cfg(test)]
impl MockEthereumRpcClient {
    pub fn new(chain_id: ChainId, bridge_address: &str) -> Self {
        Self {
            chain_id,
            bridge_address: bridge_address.to_string(),
            latest_block: 1000,
            events: Vec::new(),
            healthy: true,
        }
    }

    pub fn with_latest_block(mut self, block: u64) -> Self {
        self.latest_block = block;
        self
    }

    pub fn with_events(mut self, events: Vec<DepositEvent>) -> Self {
        self.events = events;
        self
    }

    pub fn with_health(mut self, healthy: bool) -> Self {
        self.healthy = healthy;
        self
    }
}

#[cfg(test)]
impl RpcClient for MockEthereumRpcClient {
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
            if from_block > to_block {
                return Err(FluxeError::Other(format!(
                    "Invalid block range: from {} to {}",
                    from_block, to_block
                )));
            }

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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[tokio::test]
    async fn test_mock_ethereum_client_basic() {
        let client = MockEthereumRpcClient::new(1, "0x1234567890123456789012345678901234567890")
            .with_latest_block(5000);

        assert_eq!(client.chain_id(), 1);
        assert_eq!(client.get_latest_block().await.unwrap(), 5000);
        assert!(client.health_check().await.unwrap());
        assert_eq!(
            client.bridge_address(),
            "0x1234567890123456789012345678901234567890"
        );
    }

    #[tokio::test]
    async fn test_mock_ethereum_client_events() {
        let mut rng = thread_rng();

        let events = vec![
            DepositEvent::new(
                1,
                1,
                Amount::from(1_000_000u128),
                F::rand(&mut rng),
                F::rand(&mut rng),
                100,
            ),
            DepositEvent::new(
                1,
                1,
                Amount::from(2_000_000u128),
                F::rand(&mut rng),
                F::rand(&mut rng),
                150,
            ),
            DepositEvent::new(
                1,
                1,
                Amount::from(3_000_000u128),
                F::rand(&mut rng),
                F::rand(&mut rng),
                200,
            ),
        ];

        let client = MockEthereumRpcClient::new(1, "0x1234567890123456789012345678901234567890")
            .with_latest_block(500)
            .with_events(events);

        // Get all events
        let all_events = client.get_deposit_events(0, 500).await.unwrap();
        assert_eq!(all_events.len(), 3);

        // Get events in a range
        let range_events = client.get_deposit_events(100, 150).await.unwrap();
        assert_eq!(range_events.len(), 2);

        // Get events from specific block
        let single_block_events = client.get_deposit_events(100, 100).await.unwrap();
        assert_eq!(single_block_events.len(), 1);
    }

    #[tokio::test]
    async fn test_mock_ethereum_client_invalid_range() {
        let client = MockEthereumRpcClient::new(1, "0x1234567890123456789012345678901234567890");

        let result = client.get_deposit_events(500, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_ethereum_client_unhealthy() {
        let client = MockEthereumRpcClient::new(1, "0x1234567890123456789012345678901234567890")
            .with_health(false);

        assert!(!client.health_check().await.unwrap());
    }

    #[test]
    fn test_bytes32_to_field() {
        // Test with a known value
        let mut bytes = [0u8; 32];
        bytes[31] = 1;

        let field = EthereumRpcClient::bytes32_to_field(bytes);
        assert_ne!(field, F::from(0));
    }
}
