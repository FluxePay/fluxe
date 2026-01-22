//! Solana RPC client for deposit monitoring.
//!
//! This module provides the `SolanaRpcClient` implementation for monitoring deposits
//! on Solana. It connects to a Solana RPC endpoint and queries for deposit events
//! from the FLUXE bridge program.
//!
//! # Architecture
//!
//! The client uses Solana's RPC API to:
//! 1. Query for transactions involving the bridge program
//! 2. Parse transaction logs to extract deposit events
//! 3. Convert events to the unified `DepositEvent` format
//!
//! # Event Detection
//!
//! Solana programs emit events through the Anchor framework's `emit!` macro.
//! These events are logged in transaction metadata and can be retrieved by
//! querying transaction logs. The client parses these logs to extract deposit
//! events in the `DepositEvent` format.
//!
//! # Example
//!
//! ```ignore
//! use fluxe_core::bridge::{SolanaRpcClient, RpcClient};
//!
//! let client = SolanaRpcClient::new(
//!     "https://api.mainnet-beta.solana.com",
//!     "FLUXEBridgeXXXXXXXXXXXXXXXXXXXXXXXXXXX",
//!     501,
//! )?;
//!
//! // Check health
//! let healthy = client.health_check().await?;
//!
//! // Get latest slot
//! let latest = client.get_latest_slot().await?;
//!
//! // Get deposits
//! let events = client.get_deposit_events(latest - 100, latest).await?;
//! ```

use crate::bridge::events::{
    parse_solana_deposit_event, BridgeEventError, DepositEvent,
    SOLANA_DEPOSIT_EVENT_DISCRIMINATOR,
};
use crate::bridge::{BoxFuture, RpcClient};
use crate::errors::{FluxeError, FluxeResult};
use crate::types::ChainId;

use solana_client::nonblocking::rpc_client::RpcClient as SolanaRpc;
use solana_client::rpc_config::RpcBlockConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::{
    EncodedTransaction, UiTransactionEncoding,
    option_serializer::OptionSerializer,
};

use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// Errors specific to Solana RPC operations.
#[derive(Error, Debug)]
pub enum SolanaRpcError {
    /// Failed to connect to RPC endpoint
    #[error("RPC connection failed: {0}")]
    ConnectionFailed(String),

    /// Invalid bridge program ID
    #[error("Invalid program ID: {0}")]
    InvalidProgramId(String),

    /// RPC request failed
    #[error("RPC request failed: {0}")]
    RequestFailed(String),

    /// Failed to parse transaction data
    #[error("Transaction parse error: {0}")]
    ParseError(String),

    /// Event parsing failed
    #[error("Event parsing failed: {0}")]
    EventParseError(#[from] BridgeEventError),

    /// Invalid slot range
    #[error("Invalid slot range: from {from} > to {to}")]
    InvalidSlotRange { from: u64, to: u64 },

    /// Rate limited by RPC
    #[error("Rate limited by RPC endpoint")]
    RateLimited,

    /// Block not found
    #[error("Block not found for slot {0}")]
    BlockNotFound(u64),
}

impl From<SolanaRpcError> for FluxeError {
    fn from(err: SolanaRpcError) -> Self {
        FluxeError::Configuration(err.to_string())
    }
}

/// Solana RPC client for deposit monitoring.
///
/// This client implements the `RpcClient` trait for Solana, allowing the
/// deposit monitor to query for deposits on the Solana network.
pub struct SolanaRpcClient {
    /// The underlying Solana RPC client
    client: Arc<SolanaRpc>,
    /// Bridge program ID to monitor
    bridge_program_id: Pubkey,
    /// Chain ID for this client (typically 501 for Solana mainnet)
    chain_id: ChainId,
    /// Bridge program ID as string (for `bridge_address()` method)
    bridge_address_str: String,
}

impl SolanaRpcClient {
    /// Create a new Solana RPC client.
    ///
    /// # Arguments
    ///
    /// * `rpc_endpoint` - URL of the Solana RPC endpoint
    /// * `bridge_program_id` - Base58-encoded bridge program ID
    /// * `chain_id` - Chain ID for this network (e.g., 501 for mainnet)
    ///
    /// # Returns
    ///
    /// A new `SolanaRpcClient` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge program ID is invalid.
    pub fn new(
        rpc_endpoint: &str,
        bridge_program_id: &str,
        chain_id: ChainId,
    ) -> FluxeResult<Self> {
        let program_id = Pubkey::from_str(bridge_program_id).map_err(|e| {
            SolanaRpcError::InvalidProgramId(format!(
                "Failed to parse bridge program ID '{}': {}",
                bridge_program_id, e
            ))
        })?;

        let client = SolanaRpc::new_with_commitment(
            rpc_endpoint.to_string(),
            CommitmentConfig::finalized(),
        );

        info!(
            "Created SolanaRpcClient for chain {} with program {}",
            chain_id, bridge_program_id
        );

        Ok(Self {
            client: Arc::new(client),
            bridge_program_id: program_id,
            chain_id,
            bridge_address_str: bridge_program_id.to_string(),
        })
    }

    /// Get the latest confirmed slot.
    ///
    /// Uses finalized commitment to ensure the slot won't be rolled back.
    pub async fn get_latest_slot(&self) -> FluxeResult<u64> {
        let slot = self.client.get_slot().await.map_err(|e| {
            SolanaRpcError::RequestFailed(format!("Failed to get latest slot: {}", e))
        })?;

        trace!("Latest slot: {}", slot);
        Ok(slot)
    }

    /// Get deposit events from transaction signatures.
    ///
    /// This method queries transactions for the bridge program and parses
    /// their logs to extract deposit events.
    async fn get_deposit_events_impl(
        &self,
        from_slot: u64,
        to_slot: u64,
    ) -> FluxeResult<Vec<DepositEvent>> {
        if from_slot > to_slot {
            return Err(SolanaRpcError::InvalidSlotRange {
                from: from_slot,
                to: to_slot,
            }
            .into());
        }

        debug!(
            "Querying deposit events from slot {} to {}",
            from_slot, to_slot
        );

        let mut all_events = Vec::new();

        // Query blocks in the range
        for slot in from_slot..=to_slot {
            match self.get_deposit_events_for_slot(slot).await {
                Ok(events) => {
                    if !events.is_empty() {
                        debug!("Found {} deposit events in slot {}", events.len(), slot);
                    }
                    all_events.extend(events);
                }
                Err(e) => {
                    // Log but continue - slot might be skipped
                    trace!("Error getting events for slot {}: {}", slot, e);
                }
            }
        }

        info!(
            "Found {} total deposit events in slots {}-{}",
            all_events.len(),
            from_slot,
            to_slot
        );

        Ok(all_events)
    }

    /// Get deposit events from a specific slot.
    async fn get_deposit_events_for_slot(&self, slot: u64) -> FluxeResult<Vec<DepositEvent>> {
        // Configure block query to include transactions and metadata
        let config = RpcBlockConfig {
            encoding: Some(UiTransactionEncoding::Base64),
            transaction_details: Some(solana_transaction_status::TransactionDetails::Full),
            rewards: Some(false),
            commitment: Some(CommitmentConfig::finalized()),
            max_supported_transaction_version: Some(0),
        };

        // Get the block
        let block = match self.client.get_block_with_config(slot, config).await {
            Ok(block) => block,
            Err(e) => {
                // Block might not exist (skipped slot)
                trace!("Block not found for slot {}: {}", slot, e);
                return Ok(Vec::new());
            }
        };

        let mut events = Vec::new();

        // Process each transaction in the block
        if let Some(transactions) = block.transactions {
            for tx_with_meta in transactions {
                // Check if this transaction involves our bridge program
                if let Some(meta) = &tx_with_meta.meta {
                    // Check for errors - skip failed transactions
                    if meta.err.is_some() {
                        continue;
                    }

                    // Parse log messages for deposit events
                    if let OptionSerializer::Some(logs) = &meta.log_messages {
                        if let Some(deposit_events) =
                            self.parse_deposit_events_from_logs(logs, slot, &tx_with_meta.transaction)
                        {
                            events.extend(deposit_events);
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    /// Parse deposit events from transaction log messages.
    ///
    /// Anchor events are emitted as base64-encoded data in log messages
    /// with the format: "Program data: <base64>"
    fn parse_deposit_events_from_logs(
        &self,
        logs: &[String],
        slot: u64,
        transaction: &EncodedTransaction,
    ) -> Option<Vec<DepositEvent>> {
        let mut events = Vec::new();

        // Check if this transaction involves our bridge program
        let involves_bridge = logs.iter().any(|log| {
            log.contains(&self.bridge_program_id.to_string())
        });

        if !involves_bridge {
            return None;
        }

        // Extract transaction signature for reference
        let signature = self.extract_signature(transaction);

        // Look for "Program data:" log entries which contain Anchor events
        for log in logs {
            if let Some(data_str) = log.strip_prefix("Program data: ") {
                // Decode base64 data
                if let Ok(data) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    data_str,
                ) {
                    // Check if this is a deposit event by discriminator
                    if data.len() >= 8 {
                        let discriminator: [u8; 8] = data[..8].try_into().unwrap();

                        if discriminator == SOLANA_DEPOSIT_EVENT_DISCRIMINATOR {
                            // Parse the event data (skip discriminator)
                            match parse_solana_deposit_event(&data[8..]) {
                                Ok(event_data) => {
                                    let deposit_event = event_data.to_deposit_event(
                                        self.chain_id,
                                        slot,
                                        signature,
                                    );
                                    events.push(deposit_event);
                                }
                                Err(e) => {
                                    warn!("Failed to parse deposit event: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Extract transaction signature from encoded transaction.
    fn extract_signature(&self, transaction: &EncodedTransaction) -> [u8; 32] {
        match transaction {
            EncodedTransaction::LegacyBinary(_) => [0u8; 32],
            EncodedTransaction::Binary(data, _encoding) => {
                // Try to decode and extract signature
                if let Ok(decoded) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    data,
                ) {
                    // First 64 bytes are typically the signature
                    if decoded.len() >= 64 {
                        let mut sig = [0u8; 32];
                        sig.copy_from_slice(&decoded[..32]);
                        return sig;
                    }
                }
                [0u8; 32]
            }
            EncodedTransaction::Json(ui_tx) => {
                // Extract from signatures field
                if let Some(first_sig) = ui_tx.signatures.first() {
                    if let Ok(sig) = Signature::from_str(first_sig) {
                        let bytes = sig.as_ref();
                        if bytes.len() >= 32 {
                            let mut result = [0u8; 32];
                            result.copy_from_slice(&bytes[..32]);
                            return result;
                        }
                    }
                }
                [0u8; 32]
            }
            EncodedTransaction::Accounts(_) => [0u8; 32],
        }
    }

    /// Check if RPC endpoint is healthy.
    async fn health_check_impl(&self) -> FluxeResult<bool> {
        match self.client.get_health().await {
            Ok(()) => {
                trace!("RPC health check passed");
                Ok(true)
            }
            Err(e) => {
                warn!("RPC health check failed: {}", e);
                Ok(false)
            }
        }
    }
}

impl RpcClient for SolanaRpcClient {
    fn get_latest_block(&self) -> BoxFuture<'_, FluxeResult<u64>> {
        Box::pin(self.get_latest_slot())
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

// Implement Debug manually since SolanaRpc doesn't implement Debug
impl std::fmt::Debug for SolanaRpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaRpcClient")
            .field("bridge_program_id", &self.bridge_program_id.to_string())
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_rpc_client_creation() {
        // Valid creation
        let result = SolanaRpcClient::new(
            "https://api.mainnet-beta.solana.com",
            "11111111111111111111111111111111", // System program as placeholder
            501,
        );
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.chain_id(), 501);
        assert_eq!(client.bridge_address(), "11111111111111111111111111111111");
    }

    #[test]
    fn test_solana_rpc_client_invalid_program_id() {
        let result = SolanaRpcClient::new(
            "https://api.mainnet-beta.solana.com",
            "invalid_program_id!!!",
            501,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_solana_rpc_error_display() {
        let err = SolanaRpcError::InvalidProgramId("bad pubkey".to_string());
        assert!(err.to_string().contains("bad pubkey"));

        let err = SolanaRpcError::InvalidSlotRange { from: 100, to: 50 };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));
    }

    #[test]
    fn test_solana_rpc_client_debug() {
        let client = SolanaRpcClient::new(
            "https://api.mainnet-beta.solana.com",
            "11111111111111111111111111111111",
            501,
        )
        .unwrap();

        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("SolanaRpcClient"));
        assert!(debug_str.contains("501"));
    }

    // Integration tests (require network access, so gated behind feature flag)
    #[cfg(feature = "integration-tests")]
    mod integration {
        use super::*;

        #[tokio::test]
        async fn test_get_latest_slot() {
            let client = SolanaRpcClient::new(
                "https://api.devnet.solana.com",
                "11111111111111111111111111111111",
                501,
            )
            .unwrap();

            let slot = client.get_latest_slot().await;
            assert!(slot.is_ok());
            assert!(slot.unwrap() > 0);
        }

        #[tokio::test]
        async fn test_health_check() {
            let client = SolanaRpcClient::new(
                "https://api.devnet.solana.com",
                "11111111111111111111111111111111",
                501,
            )
            .unwrap();

            let health = client.health_check_impl().await;
            assert!(health.is_ok());
        }
    }
}
