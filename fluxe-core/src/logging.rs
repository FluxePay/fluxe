/// Logging and tracing infrastructure for Fluxe protocol
use serde::Serialize;
use std::sync::Once;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static INIT: Once = Once::new();

/// Initialize the logging system with environment-based configuration
pub fn init_logging() {
    INIT.call_once(|| {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| {
                EnvFilter::new("info")
                    .add_directive("fluxe_core=debug".parse().unwrap())
                    .add_directive("fluxe_circuits=debug".parse().unwrap())
                    .add_directive("fluxe_api=debug".parse().unwrap())
            });

        tracing_subscriber::registry()
            .with(fmt::layer().with_target(true).with_thread_ids(true))
            .with(env_filter)
            .init();

        info!("Fluxe logging initialized");
    });
}

/// Initialize test logging (more verbose, single-threaded)
#[cfg(test)]
pub fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .with_test_writer()
        .with_target(true)
        .try_init();
}

/// Log circuit generation metrics
#[derive(Debug, Serialize)]
pub struct CircuitMetrics {
    pub circuit_type: String,
    pub constraint_count: usize,
    pub public_input_count: usize,
    pub witness_count: usize,
    pub setup_time_ms: u64,
    pub proof_time_ms: u64,
    pub verify_time_ms: u64,
}

impl CircuitMetrics {
    pub fn log(&self) {
        info!(
            circuit_type = %self.circuit_type,
            constraints = self.constraint_count,
            public_inputs = self.public_input_count,
            witnesses = self.witness_count,
            setup_ms = self.setup_time_ms,
            proof_ms = self.proof_time_ms,
            verify_ms = self.verify_time_ms,
            "Circuit metrics"
        );
    }
}

/// Log Merkle tree operations
#[derive(Debug, Serialize)]
pub struct MerkleOpLog {
    pub op_type: MerkleOperation,
    pub tree_type: String,
    pub old_root: String,
    pub new_root: String,
    pub leaf_count: usize,
    pub duration_us: u64,
}

#[derive(Debug, Serialize)]
pub enum MerkleOperation {
    Append,
    BatchAppend,
    Insert,
    BatchInsert,
}

impl MerkleOpLog {
    pub fn log(&self) {
        debug!(
            op = ?self.op_type,
            tree = %self.tree_type,
            old_root = %self.old_root,
            new_root = %self.new_root,
            leaves = self.leaf_count,
            duration_us = self.duration_us,
            "Merkle operation"
        );
    }
}

/// Log transaction processing
#[derive(Debug, Serialize)]
pub struct TransactionLog {
    pub tx_type: TransactionType,
    pub tx_id: String,
    pub status: TransactionStatus,
    pub nullifiers: Vec<String>,
    pub commitments: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum TransactionType {
    Mint,
    Burn,
    Transfer,
    ObjectUpdate,
}

#[derive(Debug, Serialize)]
pub enum TransactionStatus {
    Pending,
    Verifying,
    Accepted,
    Rejected,
}

impl TransactionLog {
    pub fn log(&self) {
        match self.status {
            TransactionStatus::Accepted => {
                info!(
                    tx_type = ?self.tx_type,
                    tx_id = %self.tx_id,
                    nullifiers = self.nullifiers.len(),
                    commitments = self.commitments.len(),
                    "Transaction accepted"
                );
            }
            TransactionStatus::Rejected => {
                warn!(
                    tx_type = ?self.tx_type,
                    tx_id = %self.tx_id,
                    error = %self.error.as_ref().unwrap_or(&"Unknown".to_string()),
                    "Transaction rejected"
                );
            }
            _ => {
                debug!(
                    tx_type = ?self.tx_type,
                    tx_id = %self.tx_id,
                    status = ?self.status,
                    "Transaction status update"
                );
            }
        }
    }
}

/// Log compliance checks
#[derive(Debug, Serialize)]
pub struct ComplianceLog {
    pub check_type: ComplianceCheckType,
    pub user_id: String,
    pub result: bool,
    pub reason: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub enum ComplianceCheckType {
    Sanctions,
    DailyLimit,
    MonthlyLimit,
    YearlyLimit,
    AccountFrozen,
    CallbackExpiry,
    PoolPolicy,
}

impl ComplianceLog {
    pub fn log(&self) {
        if self.result {
            trace!(
                check = ?self.check_type,
                user = %self.user_id,
                "Compliance check passed"
            );
        } else {
            info!(
                check = ?self.check_type,
                user = %self.user_id,
                reason = %self.reason.as_ref().unwrap_or(&"Unknown".to_string()),
                details = %self.details,
                "Compliance check failed"
            );
        }
    }
}

/// Log API requests
#[derive(Debug, Serialize)]
pub struct ApiRequestLog {
    pub endpoint: String,
    pub method: String,
    pub client_id: Option<String>,
    pub request_id: String,
    pub duration_ms: u64,
    pub status_code: u16,
    pub error: Option<String>,
}

impl ApiRequestLog {
    pub fn log(&self) {
        if self.status_code >= 500 {
            error!(
                endpoint = %self.endpoint,
                method = %self.method,
                request_id = %self.request_id,
                duration_ms = self.duration_ms,
                status = self.status_code,
                error = %self.error.as_ref().unwrap_or(&"Unknown".to_string()),
                "API request failed"
            );
        } else if self.status_code >= 400 {
            warn!(
                endpoint = %self.endpoint,
                method = %self.method,
                request_id = %self.request_id,
                duration_ms = self.duration_ms,
                status = self.status_code,
                error = %self.error.as_ref().unwrap_or(&"Bad request".to_string()),
                "API request error"
            );
        } else {
            info!(
                endpoint = %self.endpoint,
                method = %self.method,
                request_id = %self.request_id,
                duration_ms = self.duration_ms,
                status = self.status_code,
                "API request completed"
            );
        }
    }
}

/// Performance monitoring
pub struct PerfTimer {
    label: String,
    start: std::time::Instant,
}

impl PerfTimer {
    pub fn new(label: impl Into<String>) -> Self {
        let label = label.into();
        trace!(label = %label, "Starting timer");
        Self {
            label,
            start: std::time::Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub fn log_elapsed(&self) {
        let elapsed = self.elapsed_ms();
        if elapsed > 1000 {
            warn!(label = %self.label, elapsed_ms = elapsed, "Slow operation");
        } else {
            debug!(label = %self.label, elapsed_ms = elapsed, "Operation completed");
        }
    }
}

impl Drop for PerfTimer {
    fn drop(&mut self) {
        self.log_elapsed();
    }
}

/// Macro for structured logging with context
#[macro_export]
macro_rules! log_with_context {
    ($level:ident, $msg:expr, $($key:ident = $val:expr),*) => {
        tracing::$level!(
            $($key = %$val,)*
            $msg
        );
    };
}

/// Macro for error logging with automatic error chain
#[macro_export]
macro_rules! log_error_chain {
    ($err:expr) => {{
        let mut e = &$err as &dyn std::error::Error;
        tracing::error!("Error: {}", e);
        while let Some(source) = e.source() {
            tracing::error!("  Caused by: {}", source);
            e = source;
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_initialization() {
        init_test_logging();
        info!("Test log message");
        assert!(true);
    }

    #[test]
    fn test_circuit_metrics() {
        init_test_logging();
        let metrics = CircuitMetrics {
            circuit_type: "Transfer".to_string(),
            constraint_count: 10000,
            public_input_count: 8,
            witness_count: 256,
            setup_time_ms: 1500,
            proof_time_ms: 3000,
            verify_time_ms: 15,
        };
        metrics.log();
    }

    #[test]
    fn test_perf_timer() {
        init_test_logging();
        let _timer = PerfTimer::new("test_operation");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}