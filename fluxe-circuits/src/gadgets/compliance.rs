// This file contains additional compliance-related gadgets
// The main ZkObjectVar and ComplianceStateVar are in zk_object.rs

use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

// Re-export from other modules to maintain compatibility
pub use super::zk_object::{ZkObjectVar, ComplianceStateVar};
pub use super::callbacks::{CallbackEntryVar, CallbackInvocationVar};

/// Additional compliance-related helper functions can be added here

/// Verify a compliance limit is not exceeded
pub fn verify_limit_not_exceeded(
    amount: &FpVar<F>,
    limit: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {
    // Check amount <= limit
    amount.is_cmp(limit, std::cmp::Ordering::Less, true)
}

/// Verify compliance gates for spending
pub fn verify_compliance_gates(
    frozen: &Boolean<F>,
    amount: &FpVar<F>,
    daily_limit: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {
    // Not frozen AND amount <= daily_limit
    let not_frozen = frozen.not();
    let within_limit = verify_limit_not_exceeded(amount, daily_limit)?;
    not_frozen.and(&within_limit)
}