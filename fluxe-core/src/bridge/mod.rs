//! Bridge module for cross-chain deposit monitoring and withdrawal processing.
//!
//! This module implements Phase 3.1 and 3.2 of the deployment roadmap:
//! - Phase 3.1: Multi-chain deposit monitoring and ingress receipt creation
//! - Phase 3.2: Withdrawal processing with Merkle proofs and claim tracking
//!
//! # Architecture
//!
//! The bridge module uses a trait-based design where `EthereumRpcClient` implements
//! the unified `RpcClient` trait. This enables the `DepositMonitor` to handle
//! deposits from any supported chain type uniformly.
//!
//! For withdrawals, the `WithdrawalProcessor` manages per-chain handlers that track:
//! - Pending withdrawals (waiting for batch finalization)
//! - Ready withdrawals (can be claimed on L1 with Merkle proof)
//! - Claimed withdrawals (successfully claimed on target chain)
//!
//! ## Components
//!
//! - `events`: Data structures for deposit and withdrawal events from L1
//! - `types`: Withdrawal processing types (PendingWithdrawal, WithdrawalProof, WithdrawalStatus)
//! - `ethereum_client`: Ethereum RPC client for EVM deposit monitoring
//! - `deposit_monitor`: Multi-chain deposit monitoring with polling
//! - `withdrawal_processor`: Multi-chain withdrawal tracking and proof generation
//!
//! # Deposit Monitoring Example
//!
//! ```ignore
//! use fluxe_core::bridge::{DepositMonitor, EthereumRpcClient, MonitorConfig, RpcClient};
//!
//! // Create Ethereum client
//! let client = EthereumRpcClient::new(
//!     "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY",
//!     "0x1234567890123456789012345678901234567890",
//!     1, // Ethereum mainnet
//! )?;
//!
//! // Create monitor
//! let mut monitor = DepositMonitor::new(MonitorConfig::default());
//! monitor.add_chain(1, Box::new(client), 12)?;
//!
//! // Poll for deposits
//! let deposits = monitor.poll_once().await?;
//! for deposit in deposits {
//!     let receipt = DepositMonitor::process_deposit(&deposit);
//!     sequencer.add_ingress_receipt(receipt).await?;
//! }
//! ```
//!
//! # Withdrawal Processing Example
//!
//! ```ignore
//! use fluxe_core::bridge::{WithdrawalProcessor, WithdrawalStatus, WithdrawalProof};
//!
//! // Create processor
//! let mut processor = WithdrawalProcessor::new(32);
//!
//! // Register chains
//! processor.register_chain(1)?;   // Ethereum
//! processor.register_chain(501)?; // Solana
//!
//! // Add a withdrawal from a burn transaction
//! let exit_hash = processor.add_withdrawal(
//!     1,              // chain_id (destination)
//!     exit_receipt,   // from burn tx
//!     batch_id,       // current batch
//!     timestamp,      // current time
//! )?;
//!
//! // After batch finalization, process and generate proofs
//! processor.process_finalized_batch(batch_id, &header, &chain_exit_trees, finalized_at)?;
//!
//! // Get proof for user to claim on L1
//! let proof = processor.get_withdrawal_proof(1, &exit_hash, exit_root)?;
//! ```
//!
//! # Thread Safety
//!
//! The `WithdrawalProcessorHandle` wrapper provides thread-safe access:
//!
//! ```ignore
//! use fluxe_core::bridge::WithdrawalProcessorHandle;
//!
//! let handle = WithdrawalProcessorHandle::new(processor);
//!
//! // Read access (multiple threads can read concurrently)
//! let status = {
//!     let proc = handle.read();
//!     proc.get_status(chain_id, &exit_hash)
//! };
//!
//! // Write access (exclusive)
//! {
//!     let mut proc = handle.write();
//!     proc.mark_claimed(chain_id, &exit_hash, claim_tx, timestamp)?;
//! }
//! ```

// Core submodules
pub mod events;
pub mod types;
pub mod withdrawal_processor;

// Phase 3.1: Ethereum deposit monitoring (requires "ethereum" feature)
#[cfg(feature = "ethereum")]
pub mod ethereum_client;

#[cfg(feature = "ethereum")]
pub mod deposit_monitor;

// Phase 3.1: Solana deposit monitoring (requires "solana" feature)
#[cfg(feature = "solana")]
pub mod solana_client;

// Re-export deposit event types
pub use events::{BridgeEventError, DepositEvent, EventId, WithdrawalEvent as L1WithdrawalEvent};

// Re-export Solana-specific event types (always available for parsing)
pub use events::{
    parse_solana_deposit_event, SolanaDepositEventData, SOLANA_DEPOSIT_EVENT_DISCRIMINATOR,
    SOLANA_DEPOSIT_EVENT_SIZE,
};

// Re-export withdrawal processing types (Phase 3.2)
pub use types::{
    ChainWithdrawalSummary, PendingWithdrawal, WithdrawalEvent, WithdrawalFailureReason,
    WithdrawalProof, WithdrawalStatus,
};

pub use withdrawal_processor::{
    ChainWithdrawalHandler, WithdrawalProcessor, WithdrawalProcessorHandle,
};

// Ethereum RPC client exports (requires "ethereum" feature)
#[cfg(feature = "ethereum")]
pub use ethereum_client::{EthereumRpcClient, EthereumRpcError};

// Deposit monitor exports (requires "ethereum" feature)
#[cfg(feature = "ethereum")]
pub use deposit_monitor::{
    ChainMonitor, DepositMonitor, MonitorConfig, MonitorError, MonitorStats,
    SharedDepositMonitor,
};

// Solana RPC client exports (requires "solana" feature)
#[cfg(feature = "solana")]
pub use solana_client::{SolanaRpcClient, SolanaRpcError};

use crate::config::{ChainConfig, ChainType};
use crate::errors::{FluxeError, FluxeResult};
use crate::types::ChainId;
use std::future::Future;
use std::pin::Pin;

/// Type alias for boxed futures used in async trait methods.
/// This avoids requiring the async_trait crate while maintaining Send + Sync bounds.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Unified RPC client trait for cross-chain deposit monitoring.
///
/// This trait abstracts over the differences between EVM and SVM chains,
/// providing a common interface for deposit event retrieval.
///
/// # Semantics
///
/// - For EVM chains: "block" refers to Ethereum block numbers
/// - For SVM chains: "block" refers to Solana slots
///
/// The trait uses `u64` for both to maintain a simple, unified interface.
///
/// # Implementation Notes
///
/// Implementations must be `Send + Sync` to support concurrent access from
/// multiple async tasks. The `BoxFuture` type alias is used to avoid requiring
/// the `async_trait` crate while still supporting async methods.
pub trait RpcClient: Send + Sync {
    /// Get the latest finalized block number (EVM) or slot (SVM).
    ///
    /// Returns the most recent block/slot that can be safely considered finalized
    /// according to the chain's finality rules.
    fn get_latest_block(&self) -> BoxFuture<'_, FluxeResult<u64>>;

    /// Get deposit events within a block/slot range.
    ///
    /// # Arguments
    ///
    /// * `from_block` - Start of the range (inclusive)
    /// * `to_block` - End of the range (inclusive)
    ///
    /// # Returns
    ///
    /// A vector of `DepositEvent`s found within the specified range.
    /// Returns an empty vector if no deposits occurred in the range.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The RPC connection fails
    /// - The block range is invalid (from > to)
    /// - Event parsing fails
    fn get_deposit_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> BoxFuture<'_, FluxeResult<Vec<DepositEvent>>>;

    /// Get the chain ID this client is connected to.
    fn chain_id(&self) -> ChainId;

    /// Check if the RPC connection is healthy.
    ///
    /// Implementations should perform a lightweight check (e.g., get_health or get_slot)
    /// to verify the connection is working.
    fn health_check(&self) -> BoxFuture<'_, FluxeResult<bool>>;

    /// Get the bridge contract/program address being monitored.
    fn bridge_address(&self) -> &str;
}

/// Monitor state for tracking processed blocks per chain.
#[derive(Debug, Clone)]
pub struct ChainMonitorState {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Last processed block/slot number
    pub last_processed_block: u64,
    /// Number of confirmations required for finality
    pub finality_blocks: u64,
    /// Whether the monitor is currently active
    pub active: bool,
}

impl ChainMonitorState {
    /// Create a new chain monitor state.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The chain identifier
    /// * `finality_blocks` - Number of blocks/slots for finality
    pub fn new(chain_id: ChainId, finality_blocks: u64) -> Self {
        Self {
            chain_id,
            last_processed_block: 0,
            finality_blocks,
            active: true,
        }
    }

    /// Create from chain configuration.
    pub fn from_config(config: &ChainConfig) -> Self {
        Self {
            chain_id: config.chain_id,
            last_processed_block: 0,
            finality_blocks: config.finality_blocks,
            active: config.enabled,
        }
    }

    /// Calculate the safe block to process (accounting for finality).
    ///
    /// Returns the latest block that has achieved finality by subtracting
    /// the required confirmation blocks from the chain head.
    pub fn safe_to_block(&self, latest_block: u64) -> u64 {
        latest_block.saturating_sub(self.finality_blocks)
    }

    /// Check if there are new blocks to process.
    pub fn has_new_blocks(&self, latest_block: u64) -> bool {
        let safe_block = self.safe_to_block(latest_block);
        safe_block > self.last_processed_block
    }

    /// Update the last processed block.
    pub fn update_last_processed(&mut self, block: u64) {
        self.last_processed_block = block;
    }
}

/// Factory function to create an RPC client based on chain configuration.
///
/// This function examines the chain configuration and creates the appropriate
/// client type (Ethereum or Solana).
///
/// # Arguments
///
/// * `config` - Chain configuration specifying RPC endpoint and chain type
///
/// # Returns
///
/// A boxed `RpcClient` implementation appropriate for the chain type.
///
/// # Errors
///
/// Returns an error if:
/// - The chain type is not supported
/// - Client initialization fails (e.g., invalid contract address)
/// Factory function to create an RPC client based on chain configuration.
///
/// Requires either "ethereum" or "solana" feature to be enabled.
#[cfg(all(feature = "ethereum", feature = "solana"))]
pub fn create_rpc_client(config: &ChainConfig) -> FluxeResult<Box<dyn RpcClient>> {
    match config.chain_type {
        ChainType::EVM => {
            let client = EthereumRpcClient::from_config(config)?;
            Ok(Box::new(client))
        }
        ChainType::SVM => {
            let client = SolanaRpcClient::new(
                &config.rpc_endpoint,
                &config.bridge_address,
                config.chain_id,
            )?;
            Ok(Box::new(client))
        }
    }
}

/// Factory function when only ethereum feature is enabled.
#[cfg(all(feature = "ethereum", not(feature = "solana")))]
pub fn create_rpc_client(config: &ChainConfig) -> FluxeResult<Box<dyn RpcClient>> {
    match config.chain_type {
        ChainType::EVM => {
            let client = EthereumRpcClient::from_config(config)?;
            Ok(Box::new(client))
        }
        ChainType::SVM => Err(FluxeError::Configuration(
            "SVM RPC client requires the 'solana' feature. \
             Enable it in Cargo.toml: fluxe-core = { features = [\"solana\"] }"
                .to_string(),
        )),
    }
}

/// Factory function when only solana feature is enabled.
#[cfg(all(feature = "solana", not(feature = "ethereum")))]
pub fn create_rpc_client(config: &ChainConfig) -> FluxeResult<Box<dyn RpcClient>> {
    match config.chain_type {
        ChainType::EVM => Err(FluxeError::Configuration(
            "EVM RPC client requires the 'ethereum' feature. \
             Enable it in Cargo.toml: fluxe-core = { features = [\"ethereum\"] }"
                .to_string(),
        )),
        ChainType::SVM => {
            let client = SolanaRpcClient::new(
                &config.rpc_endpoint,
                &config.bridge_address,
                config.chain_id,
            )?;
            Ok(Box::new(client))
        }
    }
}

/// Factory function when neither ethereum nor solana feature is enabled.
#[cfg(not(any(feature = "ethereum", feature = "solana")))]
pub fn create_rpc_client(config: &ChainConfig) -> FluxeResult<Box<dyn RpcClient>> {
    match config.chain_type {
        ChainType::EVM => Err(FluxeError::Configuration(
            "EVM RPC client requires the 'ethereum' feature. \
             Enable it in Cargo.toml: fluxe-core = { features = [\"ethereum\"] }"
                .to_string(),
        )),
        ChainType::SVM => Err(FluxeError::Configuration(
            "SVM RPC client requires the 'solana' feature. \
             Enable it in Cargo.toml: fluxe-core = { features = [\"solana\"] }"
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_monitor_state_new() {
        let state = ChainMonitorState::new(1, 12);
        assert_eq!(state.chain_id, 1);
        assert_eq!(state.last_processed_block, 0);
        assert_eq!(state.finality_blocks, 12);
        assert!(state.active);
    }

    #[test]
    fn test_safe_to_block() {
        let state = ChainMonitorState::new(1, 12);
        assert_eq!(state.safe_to_block(100), 88);
        assert_eq!(state.safe_to_block(12), 0);
        assert_eq!(state.safe_to_block(5), 0); // saturating_sub prevents underflow
    }

    #[test]
    fn test_has_new_blocks() {
        let mut state = ChainMonitorState::new(1, 12);

        // Initial state: no blocks processed
        assert!(state.has_new_blocks(100)); // safe_block = 88 > 0

        // After processing some blocks
        state.update_last_processed(50);
        assert!(state.has_new_blocks(100)); // safe_block = 88 > 50

        // Caught up
        state.update_last_processed(88);
        assert!(!state.has_new_blocks(100)); // safe_block = 88 == 88

        // Ahead of safe block (edge case)
        state.update_last_processed(95);
        assert!(!state.has_new_blocks(100)); // safe_block = 88 < 95
    }

    #[test]
    fn test_update_last_processed() {
        let mut state = ChainMonitorState::new(1, 12);
        assert_eq!(state.last_processed_block, 0);

        state.update_last_processed(100);
        assert_eq!(state.last_processed_block, 100);

        state.update_last_processed(200);
        assert_eq!(state.last_processed_block, 200);
    }

    #[test]
    fn test_module_exports() {
        // Verify that all public types are accessible
        let _ = std::any::type_name::<WithdrawalProcessor>();
        let _ = std::any::type_name::<WithdrawalProcessorHandle>();
        let _ = std::any::type_name::<ChainWithdrawalHandler>();
        let _ = std::any::type_name::<PendingWithdrawal>();
        let _ = std::any::type_name::<WithdrawalProof>();
        let _ = std::any::type_name::<WithdrawalStatus>();
        let _ = std::any::type_name::<WithdrawalFailureReason>();
        let _ = std::any::type_name::<ChainWithdrawalSummary>();
        let _ = std::any::type_name::<WithdrawalEvent>();
        let _ = std::any::type_name::<DepositEvent>();
        let _ = std::any::type_name::<BridgeEventError>();
        let _ = std::any::type_name::<EventId>();
        let _ = std::any::type_name::<ChainMonitorState>();
        let _ = std::any::type_name::<SolanaDepositEventData>();
    }

    #[cfg(feature = "solana")]
    #[test]
    fn test_solana_exports() {
        // Verify Solana-specific types when feature is enabled
        let _ = std::any::type_name::<SolanaRpcClient>();
        let _ = std::any::type_name::<SolanaRpcError>();
    }
}
