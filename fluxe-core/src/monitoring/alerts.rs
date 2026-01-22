//! Alerting system for FLUXE monitoring
//!
//! Provides alert types, thresholds, and handlers for critical events.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::types::{AssetType, ChainId};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "INFO",
            AlertSeverity::Warning => "WARNING",
            AlertSeverity::Critical => "CRITICAL",
        }
    }
}

/// Types of alerts
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertType {
    /// Too many pending transactions
    HighPendingTransactions { chain_id: ChainId, count: u64, threshold: u64 },
    /// Pool balance below threshold
    LowPoolBalance { chain_id: ChainId, asset_type: AssetType, balance: u64, threshold: u64 },
    /// Proof verification failed
    ProofVerificationFailure { batch_id: u64, error: String },
    /// Sequencer behind L1
    SequencerBehind { chain_id: ChainId, blocks_behind: u64 },
    /// Chain disconnected
    ChainDisconnected { chain_id: ChainId },
    /// No batches produced
    NoBatchesProduced { duration_secs: u64 },
    /// High RPC latency
    HighRpcLatency { chain_id: ChainId, latency_ms: u64, threshold_ms: u64 },
    /// Storage near capacity
    StorageNearCapacity { used_bytes: u64, total_bytes: u64, percent: u8 },
    /// Reorg detected
    ReorgDetected { chain_id: ChainId, depth: u64 },
    /// Supply imbalance
    SupplyImbalance { asset_type: AssetType, imbalance: i64 },
}

impl AlertType {
    pub fn default_severity(&self) -> AlertSeverity {
        match self {
            AlertType::ProofVerificationFailure { .. } => AlertSeverity::Critical,
            AlertType::ChainDisconnected { .. } => AlertSeverity::Critical,
            AlertType::SupplyImbalance { .. } => AlertSeverity::Critical,
            AlertType::HighPendingTransactions { .. } => AlertSeverity::Warning,
            AlertType::LowPoolBalance { .. } => AlertSeverity::Warning,
            AlertType::SequencerBehind { .. } => AlertSeverity::Warning,
            AlertType::NoBatchesProduced { .. } => AlertSeverity::Warning,
            AlertType::ReorgDetected { .. } => AlertSeverity::Warning,
            AlertType::HighRpcLatency { .. } => AlertSeverity::Info,
            AlertType::StorageNearCapacity { .. } => AlertSeverity::Info,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AlertType::HighPendingTransactions { .. } => "HighPendingTransactions",
            AlertType::LowPoolBalance { .. } => "LowPoolBalance",
            AlertType::ProofVerificationFailure { .. } => "ProofVerificationFailure",
            AlertType::SequencerBehind { .. } => "SequencerBehind",
            AlertType::ChainDisconnected { .. } => "ChainDisconnected",
            AlertType::NoBatchesProduced { .. } => "NoBatchesProduced",
            AlertType::HighRpcLatency { .. } => "HighRpcLatency",
            AlertType::StorageNearCapacity { .. } => "StorageNearCapacity",
            AlertType::ReorgDetected { .. } => "ReorgDetected",
            AlertType::SupplyImbalance { .. } => "SupplyImbalance",
        }
    }
}

/// An alert instance
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: u64,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub created_at: Instant,
    pub resolved_at: Option<Instant>,
}

impl Alert {
    pub fn new(id: u64, alert_type: AlertType, message: String) -> Self {
        Self {
            id,
            severity: alert_type.default_severity(),
            alert_type,
            message,
            created_at: Instant::now(),
            resolved_at: None,
        }
    }

    pub fn with_severity(mut self, severity: AlertSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn resolve(&mut self) {
        self.resolved_at = Some(Instant::now());
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved_at.is_some()
    }

    pub fn duration(&self) -> Duration {
        match self.resolved_at {
            Some(resolved) => resolved.duration_since(self.created_at),
            None => self.created_at.elapsed(),
        }
    }
}

/// Alert thresholds configuration
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub pending_transactions_warning: u64,
    pub pending_transactions_critical: u64,
    pub pool_balance_warning: u64,
    pub sequencer_behind_warning: u64,
    pub rpc_latency_warning_ms: u64,
    pub storage_capacity_warning_percent: u8,
    pub no_batches_warning_secs: u64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            pending_transactions_warning: 1000,
            pending_transactions_critical: 5000,
            pool_balance_warning: 1_000_000, // 1M units
            sequencer_behind_warning: 100,
            rpc_latency_warning_ms: 5000,
            storage_capacity_warning_percent: 80,
            no_batches_warning_secs: 300,
        }
    }
}

/// Trait for handling alerts (send to Discord, PagerDuty, etc.)
pub trait AlertHandler: Send + Sync {
    fn handle(&self, alert: &Alert);
    fn name(&self) -> &str;
}

/// Console alert handler (for testing/debugging)
pub struct ConsoleAlertHandler;

impl AlertHandler for ConsoleAlertHandler {
    fn handle(&self, alert: &Alert) {
        println!(
            "[{}] {}: {} - {}",
            alert.severity.as_str(),
            alert.alert_type.name(),
            alert.message,
            if alert.is_resolved() { "RESOLVED" } else { "ACTIVE" }
        );
    }

    fn name(&self) -> &str {
        "console"
    }
}

/// Webhook alert handler
pub struct WebhookAlertHandler {
    pub url: String,
    pub name: String,
}

impl WebhookAlertHandler {
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
        }
    }
}

impl AlertHandler for WebhookAlertHandler {
    fn handle(&self, alert: &Alert) {
        // In production, would send HTTP POST to webhook URL
        // For now, just log
        tracing::info!(
            handler = %self.name,
            severity = %alert.severity.as_str(),
            alert_type = %alert.alert_type.name(),
            message = %alert.message,
            "Alert sent to webhook"
        );
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Alert manager for tracking and dispatching alerts
pub struct AlertManager {
    thresholds: AlertThresholds,
    handlers: Vec<Arc<dyn AlertHandler>>,
    active_alerts: Arc<RwLock<Vec<Alert>>>,
    alert_history: Arc<RwLock<VecDeque<Alert>>>,
    next_id: Arc<RwLock<u64>>,
    max_history: usize,
}

impl AlertManager {
    pub fn new(thresholds: AlertThresholds) -> Self {
        Self {
            thresholds,
            handlers: Vec::new(),
            active_alerts: Arc::new(RwLock::new(Vec::new())),
            alert_history: Arc::new(RwLock::new(VecDeque::new())),
            next_id: Arc::new(RwLock::new(1)),
            max_history: 1000,
        }
    }

    pub fn add_handler(&mut self, handler: Arc<dyn AlertHandler>) {
        self.handlers.push(handler);
    }

    fn next_alert_id(&self) -> u64 {
        let mut id = self.next_id.write().unwrap();
        let current = *id;
        *id += 1;
        current
    }

    pub fn fire(&self, alert_type: AlertType, message: String) -> u64 {
        let id = self.next_alert_id();
        let alert = Alert::new(id, alert_type, message);

        // Dispatch to handlers
        for handler in &self.handlers {
            handler.handle(&alert);
        }

        // Add to active alerts
        self.active_alerts.write().unwrap().push(alert.clone());

        id
    }

    pub fn resolve(&self, alert_id: u64) {
        let mut active = self.active_alerts.write().unwrap();
        
        if let Some(pos) = active.iter().position(|a| a.id == alert_id) {
            let mut alert = active.remove(pos);
            alert.resolve();

            // Notify handlers of resolution
            for handler in &self.handlers {
                handler.handle(&alert);
            }

            // Add to history
            let mut history = self.alert_history.write().unwrap();
            history.push_back(alert);
            while history.len() > self.max_history {
                history.pop_front();
            }
        }
    }

    pub fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().unwrap().clone()
    }

    pub fn get_alert_history(&self, limit: usize) -> Vec<Alert> {
        let history = self.alert_history.read().unwrap();
        history.iter().rev().take(limit).cloned().collect()
    }

    pub fn thresholds(&self) -> &AlertThresholds {
        &self.thresholds
    }

    // Convenience methods for common alerts

    pub fn check_pending_transactions(&self, chain_id: ChainId, count: u64) {
        if count >= self.thresholds.pending_transactions_critical {
            self.fire(
                AlertType::HighPendingTransactions {
                    chain_id,
                    count,
                    threshold: self.thresholds.pending_transactions_critical,
                },
                format!("Critical: {} pending transactions on chain {}", count, chain_id),
            );
        } else if count >= self.thresholds.pending_transactions_warning {
            self.fire(
                AlertType::HighPendingTransactions {
                    chain_id,
                    count,
                    threshold: self.thresholds.pending_transactions_warning,
                },
                format!("Warning: {} pending transactions on chain {}", count, chain_id),
            );
        }
    }

    pub fn check_pool_balance(&self, chain_id: ChainId, asset_type: AssetType, balance: u64) {
        if balance < self.thresholds.pool_balance_warning {
            self.fire(
                AlertType::LowPoolBalance {
                    chain_id,
                    asset_type,
                    balance,
                    threshold: self.thresholds.pool_balance_warning,
                },
                format!("Low pool balance: {} for asset {} on chain {}", balance, asset_type, chain_id),
            );
        }
    }

    pub fn report_chain_disconnect(&self, chain_id: ChainId) {
        self.fire(
            AlertType::ChainDisconnected { chain_id },
            format!("Chain {} disconnected", chain_id),
        );
    }

    pub fn report_proof_failure(&self, batch_id: u64, error: &str) {
        self.fire(
            AlertType::ProofVerificationFailure {
                batch_id,
                error: error.to_string(),
            },
            format!("Proof verification failed for batch {}: {}", batch_id, error),
        );
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new(AlertThresholds::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_severity() {
        assert!(AlertSeverity::Critical > AlertSeverity::Warning);
        assert!(AlertSeverity::Warning > AlertSeverity::Info);
    }

    #[test]
    fn test_alert_type_severity() {
        let critical = AlertType::ProofVerificationFailure {
            batch_id: 1,
            error: "test".to_string(),
        };
        assert_eq!(critical.default_severity(), AlertSeverity::Critical);

        let warning = AlertType::HighPendingTransactions {
            chain_id: 1,
            count: 1000,
            threshold: 500,
        };
        assert_eq!(warning.default_severity(), AlertSeverity::Warning);
    }

    #[test]
    fn test_alert_lifecycle() {
        let alert_type = AlertType::ChainDisconnected { chain_id: 1 };
        let mut alert = Alert::new(1, alert_type, "Test alert".to_string());

        assert!(!alert.is_resolved());
        
        alert.resolve();
        assert!(alert.is_resolved());
    }

    #[test]
    fn test_alert_manager() {
        let mut manager = AlertManager::default();
        manager.add_handler(Arc::new(ConsoleAlertHandler));

        let id = manager.fire(
            AlertType::ChainDisconnected { chain_id: 1 },
            "Test disconnect".to_string(),
        );

        let active = manager.get_active_alerts();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id);

        manager.resolve(id);
        
        let active = manager.get_active_alerts();
        assert!(active.is_empty());

        let history = manager.get_alert_history(10);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_pending_transactions_check() {
        let mut manager = AlertManager::new(AlertThresholds {
            pending_transactions_warning: 100,
            pending_transactions_critical: 500,
            ..Default::default()
        });
        manager.add_handler(Arc::new(ConsoleAlertHandler));

        // Below threshold - no alert
        manager.check_pending_transactions(1, 50);
        assert!(manager.get_active_alerts().is_empty());

        // Warning threshold
        manager.check_pending_transactions(1, 150);
        assert_eq!(manager.get_active_alerts().len(), 1);
    }

    #[test]
    fn test_pool_balance_check() {
        let mut manager = AlertManager::new(AlertThresholds {
            pool_balance_warning: 1000,
            ..Default::default()
        });
        manager.add_handler(Arc::new(ConsoleAlertHandler));

        // Above threshold - no alert
        manager.check_pool_balance(1, 1, 5000);
        assert!(manager.get_active_alerts().is_empty());

        // Below threshold - alert
        manager.check_pool_balance(1, 1, 500);
        assert_eq!(manager.get_active_alerts().len(), 1);
    }

    #[test]
    fn test_webhook_handler() {
        let handler = WebhookAlertHandler::new("discord", "https://discord.webhook");
        assert_eq!(handler.name(), "discord");
    }
}
