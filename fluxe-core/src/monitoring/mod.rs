//! Monitoring infrastructure for FLUXE
//!
//! This module provides metrics collection, health checking, and alerting
//! for the FLUXE multi-chain L2 system.

pub mod metrics;
pub mod health;
pub mod alerts;

pub use metrics::{Metrics, MetricsRegistry, Counter, Gauge, Histogram};
pub use health::{HealthChecker, HealthStatus, ComponentHealth};
pub use alerts::{Alert, AlertSeverity, AlertType, AlertHandler};
