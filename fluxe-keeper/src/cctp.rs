//! Circle CCTP Integration
//!
//! Handles Cross-Chain Transfer Protocol for USDC rebalancing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// CCTP Attestation API client
pub struct CctpClient {
    api_url: String,
    http_client: reqwest::Client,
}

/// CCTP message attestation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub status: String, // "pending_confirmations", "complete"
    pub attestation: Option<String>,
}

/// CCTP message details
#[derive(Debug, Clone)]
pub struct CctpMessage {
    pub message_hash: String,
    pub source_domain: u32,
    pub dest_domain: u32,
    pub nonce: u64,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub message_bytes: Vec<u8>,
}

/// Rebalance status
#[derive(Debug, Clone)]
pub struct RebalanceStatus {
    pub message_hash: String,
    pub source_chain: u32,
    pub dest_chain: u32,
    pub amount: u64,
    pub status: RebalanceState,
    pub attestation: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RebalanceState {
    Initiated,
    PendingAttestation,
    AttestationReady,
    Completed,
    Failed(String),
}

impl CctpClient {
    pub fn new(api_url: &str) -> Self {
        Self {
            api_url: api_url.to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Get attestation for a CCTP message
    pub async fn get_attestation(&self, message_hash: &str) -> Result<AttestationResponse> {
        let url = format!(
            "{}/attestations/{}",
            self.api_url,
            message_hash.trim_start_matches("0x")
        );

        info!("Fetching CCTP attestation for: {}", message_hash);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch attestation")?;

        if response.status().is_success() {
            let data: AttestationResponse = response.json().await?;
            Ok(data)
        } else if response.status().as_u16() == 404 {
            // Message not yet indexed
            Ok(AttestationResponse {
                status: "pending_confirmations".to_string(),
                attestation: None,
            })
        } else {
            let error = response.text().await?;
            anyhow::bail!("CCTP API error: {}", error);
        }
    }

    /// Wait for attestation to be ready (with timeout)
    pub async fn wait_for_attestation(
        &self,
        message_hash: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("Attestation timeout");
            }

            let response = self.get_attestation(message_hash).await?;

            if response.status == "complete" {
                if let Some(attestation) = response.attestation {
                    info!("Attestation ready for {}", message_hash);
                    return Ok(attestation);
                }
            }

            info!(
                "Waiting for attestation... status: {} (elapsed: {:?})",
                response.status,
                start.elapsed()
            );

            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }
}

/// Compute CCTP message hash from message bytes
pub fn compute_message_hash(message_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(message_bytes);
    format!("0x{}", hex::encode(hash))
}

/// Encode CCTP burn message for Ethereum
pub fn encode_cctp_burn_message(
    amount: u64,
    dest_domain: u32,
    mint_recipient: &[u8; 32],
    destination_caller: &[u8; 32],
) -> Vec<u8> {
    // Simplified encoding - actual CCTP uses specific message format
    // See: https://developers.circle.com/stablecoin/cctp-message-format
    let mut message = Vec::new();
    message.extend_from_slice(&dest_domain.to_be_bytes());
    message.extend_from_slice(&amount.to_be_bytes());
    message.extend_from_slice(mint_recipient);
    message.extend_from_slice(destination_caller);
    message
}

/// Parse CCTP burn event from Ethereum logs
pub fn parse_cctp_burn_event(_log_data: &[u8]) -> Result<CctpMessage> {
    // Simplified parsing - actual implementation would decode the log
    // according to CCTP event ABI
    warn!("CCTP event parsing not fully implemented");
    Ok(CctpMessage {
        message_hash: String::new(),
        source_domain: 0,
        dest_domain: 5,
        nonce: 0,
        sender: String::new(),
        recipient: String::new(),
        amount: 0,
        message_bytes: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_message_hash() {
        let message = b"test message";
        let hash = compute_message_hash(message);
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66); // 0x + 64 hex chars
    }
}
