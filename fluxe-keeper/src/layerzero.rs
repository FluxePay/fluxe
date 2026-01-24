//! LayerZero USDT0 Integration
//!
//! Handles cross-chain USDT transfers using LayerZero OFT standard.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// LayerZero OFT API client
pub struct LayerZeroClient {
    api_url: String,
    http_client: reqwest::Client,
}

/// LayerZero endpoint IDs for supported chains
pub mod endpoints {
    pub const ETHEREUM: u32 = 30101;
    pub const ARBITRUM: u32 = 30110;
    pub const OPTIMISM: u32 = 30111;
    pub const BASE: u32 = 30184;
    pub const POLYGON: u32 = 30109;
    pub const SOLANA: u32 = 30168;
}

/// USDT0 contract addresses (mainnet)
pub mod usdt0_addresses {
    pub const ETHEREUM: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7"; // Native USDT
    pub const ARBITRUM: &str = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9";
    pub const OPTIMISM: &str = "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58";
    pub const BASE: &str = "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2";
}

/// OFT transfer parameters
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequest {
    pub src_chain_name: String,
    pub dst_chain_name: String,
    pub src_address: String,
    pub amount: String,
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validate: Option<bool>,
}

/// OFT transfer response
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResponse {
    pub transaction_data: TransactionData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionData {
    pub populated_transaction: serde_json::Value,
    #[serde(default)]
    pub approval_transaction: Option<serde_json::Value>,
}

/// Token list response
#[derive(Debug, Clone, Deserialize)]
pub struct TokenListResponse {
    pub tokens: Vec<TokenInfo>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    pub chain_name: String,
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
}

/// Rebalance status for LayerZero transfers
#[derive(Debug, Clone)]
pub struct LzRebalanceStatus {
    pub tx_hash: String,
    pub source_chain: String,
    pub dest_chain: String,
    pub amount: u64,
    pub status: LzRebalanceState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LzRebalanceState {
    Pending,
    Inflight,
    Delivered,
    Failed(String),
}

impl LayerZeroClient {
    pub fn new(api_url: &str) -> Self {
        Self {
            api_url: api_url.to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Get available OFT tokens
    pub async fn list_tokens(&self, chain: &str) -> Result<Vec<TokenInfo>> {
        let url = format!("{}/list?chainName={}", self.api_url, chain);

        info!("Fetching LayerZero token list for {}", chain);

        let response = self.http_client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch token list")?;

        if response.status().is_success() {
            let data: TokenListResponse = response.json().await?;
            Ok(data.tokens)
        } else {
            let error = response.text().await?;
            anyhow::bail!("LayerZero API error: {}", error);
        }
    }

    /// Build transfer transaction
    pub async fn build_transfer(
        &self,
        src_chain: &str,
        dst_chain: &str,
        token_address: &str,
        amount: u64,
        from: &str,
        to: &str,
    ) -> Result<TransferResponse> {
        let url = format!("{}/transfer", self.api_url);

        let request = TransferRequest {
            src_chain_name: src_chain.to_string(),
            dst_chain_name: dst_chain.to_string(),
            src_address: token_address.to_string(),
            amount: amount.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            validate: Some(true),
        };

        info!(
            "Building LayerZero transfer: {} -> {} ({} USDT)",
            src_chain, dst_chain, amount / 1_000_000
        );

        let response = self.http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to build transfer")?;

        if response.status().is_success() {
            let data: TransferResponse = response.json().await?;
            Ok(data)
        } else {
            let error = response.text().await?;
            anyhow::bail!("LayerZero API error: {}", error);
        }
    }

    /// Get message status from LayerZero scan
    pub async fn get_message_status(&self, tx_hash: &str, chain: &str) -> Result<LzRebalanceState> {
        // Query LayerZero Scan API for message status
        let url = format!(
            "https://api-mainnet.layerzero-scan.com/tx/{}?chain={}",
            tx_hash, chain
        );

        info!("Checking LayerZero message status: {}", tx_hash);

        let response = self.http_client
            .get(&url)
            .send()
            .await
            .context("Failed to check message status")?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;

            if let Some(status) = data.get("status").and_then(|s| s.as_str()) {
                match status {
                    "INFLIGHT" => Ok(LzRebalanceState::Inflight),
                    "DELIVERED" => Ok(LzRebalanceState::Delivered),
                    "FAILED" => Ok(LzRebalanceState::Failed("Message delivery failed".to_string())),
                    _ => Ok(LzRebalanceState::Pending),
                }
            } else {
                Ok(LzRebalanceState::Pending)
            }
        } else if response.status().as_u16() == 404 {
            // Transaction not yet indexed
            Ok(LzRebalanceState::Pending)
        } else {
            let error = response.text().await?;
            warn!("LayerZero scan API error: {}", error);
            Ok(LzRebalanceState::Pending)
        }
    }
}

/// Get LayerZero endpoint ID for a chain name
pub fn chain_to_endpoint(chain: &str) -> Option<u32> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => Some(endpoints::ETHEREUM),
        "arbitrum" | "arb" => Some(endpoints::ARBITRUM),
        "optimism" | "op" => Some(endpoints::OPTIMISM),
        "base" => Some(endpoints::BASE),
        "polygon" | "matic" => Some(endpoints::POLYGON),
        "solana" | "sol" => Some(endpoints::SOLANA),
        _ => None,
    }
}

/// Get USDT0 address for a chain
pub fn chain_to_usdt_address(chain: &str) -> Option<&'static str> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => Some(usdt0_addresses::ETHEREUM),
        "arbitrum" | "arb" => Some(usdt0_addresses::ARBITRUM),
        "optimism" | "op" => Some(usdt0_addresses::OPTIMISM),
        "base" => Some(usdt0_addresses::BASE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_to_endpoint() {
        assert_eq!(chain_to_endpoint("ethereum"), Some(30101));
        assert_eq!(chain_to_endpoint("Arbitrum"), Some(30110));
        assert_eq!(chain_to_endpoint("solana"), Some(30168));
        assert_eq!(chain_to_endpoint("unknown"), None);
    }
}
