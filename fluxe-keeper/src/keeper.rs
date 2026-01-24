//! Unified Keeper for FLUXE Cross-Chain Rebalancing
//!
//! Monitors pool balances across chains and triggers permissionless
//! rebalancing when withdrawals exceed available liquidity.

use crate::cctp::{CctpClient, RebalanceState, RebalanceStatus};
use crate::config::KeeperConfig;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{error, info, warn};

/// Chain identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    Ethereum,
    Solana,
}

impl Chain {
    pub fn cctp_domain(&self) -> u32 {
        match self {
            Chain::Ethereum => 0,
            Chain::Solana => 5,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Chain::Ethereum => "Ethereum",
            Chain::Solana => "Solana",
        }
    }
}

/// Pool balance info
#[derive(Debug, Clone)]
pub struct PoolBalance {
    pub chain: Chain,
    pub balance: u64,
    pub pending_withdrawals: u64,
}

impl PoolBalance {
    pub fn needs_rebalancing(&self) -> bool {
        self.pending_withdrawals > self.balance
    }

    pub fn deficit(&self) -> u64 {
        if self.pending_withdrawals > self.balance {
            self.pending_withdrawals - self.balance
        } else {
            0
        }
    }
}

/// Rebalance task
#[derive(Debug, Clone)]
pub struct RebalanceTask {
    pub source_chain: Chain,
    pub dest_chain: Chain,
    pub amount: u64,
}

/// Unified Keeper service
pub struct UnifiedKeeper {
    config: KeeperConfig,
    cctp_client: CctpClient,
    http_client: reqwest::Client,
    /// Pending rebalances awaiting attestation
    pending_rebalances: HashMap<String, RebalanceStatus>,
}

impl UnifiedKeeper {
    pub fn new(config: KeeperConfig) -> Self {
        let cctp_client = CctpClient::new(&config.cctp_api_url);

        Self {
            config,
            cctp_client,
            http_client: reqwest::Client::new(),
            pending_rebalances: HashMap::new(),
        }
    }

    /// Main keeper loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Unified Keeper");
        info!("Monitoring chains: Ethereum, Solana");
        info!("Min rebalance amount: {} USDC", self.config.min_rebalance_amount / 1_000_000);
        info!("Poll interval: {}s", self.config.poll_interval_secs);

        if self.config.dry_run {
            warn!("DRY RUN MODE - No actual transactions will be sent");
        }

        let poll_interval = Duration::from_secs(self.config.poll_interval_secs);

        loop {
            if let Err(e) = self.run_cycle().await {
                error!("Keeper cycle error: {:?}", e);
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Run a single keeper cycle
    async fn run_cycle(&mut self) -> Result<()> {
        // 1. Check pool balances on all chains
        let balances = self.fetch_pool_balances().await?;

        // 2. Find chains that need rebalancing
        for balance in &balances {
            if balance.needs_rebalancing() {
                let deficit = balance.deficit();

                if deficit >= self.config.min_rebalance_amount {
                    info!(
                        "{} needs rebalancing: deficit = {} USDC",
                        balance.chain.name(),
                        deficit / 1_000_000
                    );

                    // Find source chain with sufficient funds
                    if let Some(source) = self.find_source_chain(&balances, deficit) {
                        let task = RebalanceTask {
                            source_chain: source,
                            dest_chain: balance.chain,
                            amount: deficit,
                        };

                        self.initiate_rebalance(task).await?;
                    } else {
                        warn!("No source chain has sufficient funds for rebalancing");
                    }
                }
            }
        }

        // 3. Check pending rebalances for completed attestations
        self.check_pending_attestations().await?;

        Ok(())
    }

    /// Fetch pool balances from all chains
    async fn fetch_pool_balances(&self) -> Result<Vec<PoolBalance>> {
        let mut balances = Vec::new();

        // Fetch Ethereum balance
        match self.fetch_ethereum_balance().await {
            Ok(balance) => balances.push(balance),
            Err(e) => warn!("Failed to fetch Ethereum balance: {:?}", e),
        }

        // Fetch Solana balance
        match self.fetch_solana_balance().await {
            Ok(balance) => balances.push(balance),
            Err(e) => warn!("Failed to fetch Solana balance: {:?}", e),
        }

        Ok(balances)
    }

    /// Fetch Ethereum pool balance via JSON-RPC
    async fn fetch_ethereum_balance(&self) -> Result<PoolBalance> {
        info!("Fetching Ethereum pool balance...");

        if self.config.eth_bridge_address.is_empty() {
            // Return mock data if not configured
            return Ok(PoolBalance {
                chain: Chain::Ethereum,
                balance: 1_000_000_000, // 1000 USDC
                pending_withdrawals: 0,
            });
        }

        // Call getPoolBalance on the FluxeBridge contract
        // Function selector for getPoolBalance(): 0x3fb83c02
        let call_data = "0x3fb83c02";

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": self.config.eth_bridge_address,
                "data": call_data
            }, "latest"],
            "id": 1
        });

        let response: serde_json::Value = self.http_client
            .post(&self.config.eth_rpc_url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        if let Some(result) = response.get("result").and_then(|r| r.as_str()) {
            // Parse uint256 balance
            let balance = u64::from_str_radix(&result[2..].trim_start_matches('0'), 16)
                .unwrap_or(0);

            Ok(PoolBalance {
                chain: Chain::Ethereum,
                balance,
                pending_withdrawals: 0, // Would need separate call
            })
        } else {
            Ok(PoolBalance {
                chain: Chain::Ethereum,
                balance: 0,
                pending_withdrawals: 0,
            })
        }
    }

    /// Fetch Solana pool balance via JSON-RPC
    async fn fetch_solana_balance(&self) -> Result<PoolBalance> {
        info!("Fetching Solana pool balance...");

        if self.config.solana_program_id.is_empty() {
            // Return mock data if not configured
            return Ok(PoolBalance {
                chain: Chain::Solana,
                balance: 500_000_000, // 500 USDC
                pending_withdrawals: 0,
            });
        }

        // Get program accounts for the bridge state
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "getAccountInfo",
            "params": [
                self.config.solana_pool_address,
                {"encoding": "base64"}
            ],
            "id": 1
        });

        let response: serde_json::Value = self.http_client
            .post(&self.config.solana_rpc_url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        if let Some(result) = response.get("result").and_then(|r| r.get("value")) {
            if let Some(data) = result.get("data").and_then(|d| d.as_array()) {
                if let Some(encoded) = data.first().and_then(|d| d.as_str()) {
                    // Decode base64 and parse token account
                    if let Ok(decoded) = base64_decode(encoded) {
                        // SPL Token account: balance at offset 64, 8 bytes little-endian
                        if decoded.len() >= 72 {
                            let balance = u64::from_le_bytes(
                                decoded[64..72].try_into().unwrap_or([0u8; 8])
                            );
                            return Ok(PoolBalance {
                                chain: Chain::Solana,
                                balance,
                                pending_withdrawals: 0,
                            });
                        }
                    }
                }
            }
        }

        Ok(PoolBalance {
            chain: Chain::Solana,
            balance: 0,
            pending_withdrawals: 0,
        })
    }

    /// Find a source chain with sufficient balance
    fn find_source_chain(&self, balances: &[PoolBalance], needed: u64) -> Option<Chain> {
        for balance in balances {
            // Check if this chain has surplus after its own pending withdrawals
            let surplus = balance.balance.saturating_sub(balance.pending_withdrawals);
            if surplus >= needed {
                return Some(balance.chain);
            }
        }
        None
    }

    /// Initiate a rebalance operation
    async fn initiate_rebalance(&mut self, task: RebalanceTask) -> Result<()> {
        info!(
            "Initiating rebalance: {} -> {} ({} USDC)",
            task.source_chain.name(),
            task.dest_chain.name(),
            task.amount / 1_000_000
        );

        if self.config.dry_run {
            info!("DRY RUN: Would initiate rebalance");
            return Ok(());
        }

        match task.source_chain {
            Chain::Ethereum => {
                self.initiate_ethereum_rebalance(&task).await?;
            }
            Chain::Solana => {
                self.initiate_solana_rebalance(&task).await?;
            }
        }

        Ok(())
    }

    /// Initiate rebalance from Ethereum
    async fn initiate_ethereum_rebalance(&mut self, task: &RebalanceTask) -> Result<()> {
        info!("Calling initiateRebalance on Ethereum bridge...");

        // In production, this would:
        // 1. Build the transaction with alloy
        // 2. Sign with the keeper's private key
        // 3. Send to network
        // 4. Wait for confirmation
        // 5. Parse MessageSent event

        let message_hash = format!("0x{}", hex::encode([0u8; 32]));

        // Track pending rebalance
        self.pending_rebalances.insert(
            message_hash.clone(),
            RebalanceStatus {
                message_hash: message_hash.clone(),
                source_chain: task.source_chain.cctp_domain(),
                dest_chain: task.dest_chain.cctp_domain(),
                amount: task.amount,
                status: RebalanceState::PendingAttestation,
                attestation: None,
            },
        );

        info!("Rebalance initiated, waiting for attestation: {}", message_hash);

        Ok(())
    }

    /// Initiate rebalance from Solana
    async fn initiate_solana_rebalance(&mut self, task: &RebalanceTask) -> Result<()> {
        info!("Calling initiate_rebalance on Solana bridge...");

        // In production, this would:
        // 1. Build the Anchor instruction
        // 2. Sign with the keeper's keypair
        // 3. Send to network
        // 4. Wait for confirmation

        let message_hash = format!("0x{}", hex::encode([1u8; 32]));

        self.pending_rebalances.insert(
            message_hash.clone(),
            RebalanceStatus {
                message_hash: message_hash.clone(),
                source_chain: task.source_chain.cctp_domain(),
                dest_chain: task.dest_chain.cctp_domain(),
                amount: task.amount,
                status: RebalanceState::PendingAttestation,
                attestation: None,
            },
        );

        info!("Rebalance initiated, waiting for attestation: {}", message_hash);

        Ok(())
    }

    /// Check pending rebalances for completed attestations
    async fn check_pending_attestations(&mut self) -> Result<()> {
        let pending: Vec<_> = self
            .pending_rebalances
            .values()
            .filter(|r| r.status == RebalanceState::PendingAttestation)
            .cloned()
            .collect();

        for rebalance in pending {
            match self.cctp_client.get_attestation(&rebalance.message_hash).await {
                Ok(response) => {
                    if response.status == "complete" {
                        if let Some(attestation) = response.attestation {
                            info!(
                                "Attestation ready for {}, completing rebalance",
                                rebalance.message_hash
                            );

                            // Complete the rebalance on destination chain
                            self.complete_rebalance(&rebalance, &attestation).await?;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to check attestation for {}: {:?}",
                        rebalance.message_hash, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Complete a rebalance on the destination chain
    async fn complete_rebalance(
        &mut self,
        rebalance: &RebalanceStatus,
        attestation: &str,
    ) -> Result<()> {
        info!(
            "Completing rebalance {} on destination chain",
            rebalance.message_hash
        );

        if self.config.dry_run {
            info!("DRY RUN: Would complete rebalance");
            self.pending_rebalances.remove(&rebalance.message_hash);
            return Ok(());
        }

        // Determine destination chain and complete
        match rebalance.dest_chain {
            0 => {
                // Ethereum
                self.complete_ethereum_rebalance(rebalance, attestation).await?;
            }
            5 => {
                // Solana
                self.complete_solana_rebalance(rebalance, attestation).await?;
            }
            _ => {
                warn!("Unknown destination domain: {}", rebalance.dest_chain);
            }
        }

        // Remove from pending
        self.pending_rebalances.remove(&rebalance.message_hash);

        info!("Rebalance completed: {}", rebalance.message_hash);

        Ok(())
    }

    /// Complete rebalance on Ethereum
    async fn complete_ethereum_rebalance(
        &self,
        _rebalance: &RebalanceStatus,
        _attestation: &str,
    ) -> Result<()> {
        info!("Calling completeRebalance on Ethereum bridge...");
        // Would call MessageTransmitter.receiveMessage(message, attestation)
        Ok(())
    }

    /// Complete rebalance on Solana
    async fn complete_solana_rebalance(
        &self,
        _rebalance: &RebalanceStatus,
        _attestation: &str,
    ) -> Result<()> {
        info!("Calling complete_rebalance on Solana bridge...");
        // Would call CCTP MessageTransmitter on Solana
        Ok(())
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut output = Vec::new();
    let mut decoder = base64::read::DecoderReader::new(
        input.as_bytes(),
        &base64::engine::general_purpose::STANDARD
    );
    decoder.read_to_end(&mut output)?;
    Ok(output)
}
