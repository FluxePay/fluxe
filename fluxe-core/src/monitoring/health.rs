//! Health checking for FLUXE components
//!
//! Provides liveness and readiness checks for the sequencer and bridges.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::types::ChainId;

/// Overall system health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// System is healthy and operational
    Healthy,
    /// System is degraded but operational
    Degraded,
    /// System is unhealthy and may not be operational
    Unhealthy,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }

    pub fn is_operational(&self) -> bool {
        !matches!(self, HealthStatus::Unhealthy)
    }
}

/// Health status for a single component
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub last_check: Instant,
    pub details: HashMap<String, String>,
}

impl ComponentHealth {
    pub fn healthy(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Healthy,
            message: None,
            last_check: Instant::now(),
            details: HashMap::new(),
        }
    }

    pub fn degraded(name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Degraded,
            message: Some(message.to_string()),
            last_check: Instant::now(),
            details: HashMap::new(),
        }
    }

    pub fn unhealthy(name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Unhealthy,
            message: Some(message.to_string()),
            last_check: Instant::now(),
            details: HashMap::new(),
        }
    }

    pub fn with_detail(mut self, key: &str, value: &str) -> Self {
        self.details.insert(key.to_string(), value.to_string());
        self
    }
}

/// Chain connection health
#[derive(Debug, Clone)]
pub struct ChainHealth {
    pub chain_id: ChainId,
    pub connected: bool,
    pub last_block: u64,
    pub last_check: Instant,
    pub rpc_latency_ms: Option<u64>,
}

impl ChainHealth {
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            connected: false,
            last_block: 0,
            last_check: Instant::now(),
            rpc_latency_ms: None,
        }
    }

    pub fn update(&mut self, connected: bool, last_block: u64, latency_ms: Option<u64>) {
        self.connected = connected;
        self.last_block = last_block;
        self.rpc_latency_ms = latency_ms;
        self.last_check = Instant::now();
    }

    pub fn to_component_health(&self) -> ComponentHealth {
        let name = format!("chain_{}", self.chain_id);
        
        if !self.connected {
            return ComponentHealth::unhealthy(&name, "Chain disconnected");
        }

        if self.last_check.elapsed() > Duration::from_secs(60) {
            return ComponentHealth::degraded(&name, "Stale health check");
        }

        ComponentHealth::healthy(&name)
            .with_detail("last_block", &self.last_block.to_string())
            .with_detail("latency_ms", &self.rpc_latency_ms.map(|l| l.to_string()).unwrap_or_default())
    }
}

/// Sequencer health status
#[derive(Debug, Clone)]
pub struct SequencerHealth {
    pub running: bool,
    pub paused: bool,
    pub last_batch_time: Option<Instant>,
    pub pending_transactions: u64,
    pub chains_active: usize,
}

impl SequencerHealth {
    pub fn new() -> Self {
        Self {
            running: false,
            paused: false,
            last_batch_time: None,
            pending_transactions: 0,
            chains_active: 0,
        }
    }

    pub fn to_component_health(&self) -> ComponentHealth {
        if !self.running {
            return ComponentHealth::unhealthy("sequencer", "Sequencer not running");
        }

        if self.paused {
            return ComponentHealth::degraded("sequencer", "Sequencer paused");
        }

        if let Some(last_batch) = self.last_batch_time {
            if last_batch.elapsed() > Duration::from_secs(300) {
                return ComponentHealth::degraded("sequencer", "No batches in 5 minutes");
            }
        }

        ComponentHealth::healthy("sequencer")
            .with_detail("pending_transactions", &self.pending_transactions.to_string())
            .with_detail("chains_active", &self.chains_active.to_string())
    }
}

impl Default for SequencerHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Storage health status
#[derive(Debug, Clone)]
pub struct StorageHealth {
    pub available: bool,
    pub size_bytes: u64,
    pub last_write: Option<Instant>,
}

impl StorageHealth {
    pub fn new() -> Self {
        Self {
            available: false,
            size_bytes: 0,
            last_write: None,
        }
    }

    pub fn to_component_health(&self) -> ComponentHealth {
        if !self.available {
            return ComponentHealth::unhealthy("storage", "Storage unavailable");
        }

        ComponentHealth::healthy("storage")
            .with_detail("size_bytes", &self.size_bytes.to_string())
    }
}

impl Default for StorageHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Main health checker for FLUXE system
pub struct HealthChecker {
    sequencer: Arc<RwLock<SequencerHealth>>,
    chains: Arc<RwLock<HashMap<ChainId, ChainHealth>>>,
    storage: Arc<RwLock<StorageHealth>>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            sequencer: Arc::new(RwLock::new(SequencerHealth::new())),
            chains: Arc::new(RwLock::new(HashMap::new())),
            storage: Arc::new(RwLock::new(StorageHealth::new())),
        }
    }

    pub fn update_sequencer(&self, health: SequencerHealth) {
        *self.sequencer.write().unwrap() = health;
    }

    pub fn update_chain(&self, health: ChainHealth) {
        self.chains.write().unwrap().insert(health.chain_id, health);
    }

    pub fn update_storage(&self, health: StorageHealth) {
        *self.storage.write().unwrap() = health;
    }

    /// Check if system is live (basic process health)
    pub fn liveness(&self) -> bool {
        true // If this code runs, the process is alive
    }

    /// Check if system is ready to serve requests
    pub fn readiness(&self) -> bool {
        let sequencer = self.sequencer.read().unwrap();
        if !sequencer.running || sequencer.paused {
            return false;
        }

        let storage = self.storage.read().unwrap();
        if !storage.available {
            return false;
        }

        let chains = self.chains.read().unwrap();
        if chains.is_empty() {
            return false;
        }

        // At least one chain must be connected
        chains.values().any(|c| c.connected)
    }

    /// Get overall system health
    pub fn overall_status(&self) -> HealthStatus {
        let components = self.get_all_components();
        
        if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            return HealthStatus::Unhealthy;
        }

        if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            return HealthStatus::Degraded;
        }

        HealthStatus::Healthy
    }

    /// Get health status for all components
    pub fn get_all_components(&self) -> Vec<ComponentHealth> {
        let mut components = Vec::new();

        // Sequencer health
        components.push(self.sequencer.read().unwrap().to_component_health());

        // Storage health
        components.push(self.storage.read().unwrap().to_component_health());

        // Chain health
        for chain in self.chains.read().unwrap().values() {
            components.push(chain.to_component_health());
        }

        components
    }

    /// Export health as JSON-compatible structure
    pub fn export_health(&self) -> HealthReport {
        HealthReport {
            status: self.overall_status(),
            live: self.liveness(),
            ready: self.readiness(),
            components: self.get_all_components(),
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Health report for API responses
#[derive(Debug)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub live: bool,
    pub ready: bool,
    pub components: Vec<ComponentHealth>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(HealthStatus::Healthy.is_operational());
        assert!(!HealthStatus::Degraded.is_healthy());
        assert!(HealthStatus::Degraded.is_operational());
        assert!(!HealthStatus::Unhealthy.is_operational());
    }

    #[test]
    fn test_component_health() {
        let healthy = ComponentHealth::healthy("test");
        assert_eq!(healthy.status, HealthStatus::Healthy);

        let degraded = ComponentHealth::degraded("test", "slow");
        assert_eq!(degraded.status, HealthStatus::Degraded);
        assert_eq!(degraded.message, Some("slow".to_string()));

        let unhealthy = ComponentHealth::unhealthy("test", "down");
        assert_eq!(unhealthy.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_chain_health() {
        let mut chain = ChainHealth::new(1);
        assert!(!chain.connected);

        chain.update(true, 1000, Some(50));
        assert!(chain.connected);
        assert_eq!(chain.last_block, 1000);
    }

    #[test]
    fn test_sequencer_health() {
        let mut seq = SequencerHealth::new();
        assert!(!seq.running);

        let health = seq.to_component_health();
        assert_eq!(health.status, HealthStatus::Unhealthy);

        seq.running = true;
        let health = seq.to_component_health();
        assert_eq!(health.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_health_checker() {
        let checker = HealthChecker::new();
        
        // Initially not ready
        assert!(!checker.readiness());
        assert!(checker.liveness());

        // Update sequencer
        checker.update_sequencer(SequencerHealth {
            running: true,
            paused: false,
            last_batch_time: Some(Instant::now()),
            pending_transactions: 10,
            chains_active: 1,
        });

        // Update storage
        checker.update_storage(StorageHealth {
            available: true,
            size_bytes: 1024,
            last_write: Some(Instant::now()),
        });

        // Update chain
        let mut chain = ChainHealth::new(1);
        chain.update(true, 1000, Some(50));
        checker.update_chain(chain);

        // Now should be ready
        assert!(checker.readiness());
        assert_eq!(checker.overall_status(), HealthStatus::Healthy);
    }

    #[test]
    fn test_health_report() {
        let checker = HealthChecker::new();
        checker.update_sequencer(SequencerHealth {
            running: true,
            paused: false,
            last_batch_time: Some(Instant::now()),
            pending_transactions: 0,
            chains_active: 1,
        });
        checker.update_storage(StorageHealth {
            available: true,
            size_bytes: 0,
            last_write: None,
        });

        let report = checker.export_health();
        assert!(report.live);
        assert!(!report.components.is_empty());
    }
}
