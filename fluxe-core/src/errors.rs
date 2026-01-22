/// Comprehensive error handling for Fluxe protocol
use ark_serialize::SerializationError;
use thiserror::Error;

/// Main error type for Fluxe Core operations
#[derive(Error, Debug)]
pub enum FluxeError {
    // Merkle tree errors
    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] MerkleError),

    // Cryptographic errors
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    // Data structure errors
    #[error("Data structure error: {0}")]
    DataStructure(#[from] DataStructureError),

    // State management errors
    #[error("State management error: {0}")]
    StateManagement(#[from] StateError),

    // Verification errors
    #[error("Verification failed: {0}")]
    Verification(String),

    // Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),

    // Generic errors
    #[error("{0}")]
    Other(String),
}

/// Merkle tree specific errors
#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("Tree is full (depth: {depth}, max_size: {max_size})")]
    TreeFull { depth: usize, max_size: usize },

    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("Leaf not found at index {index}")]
    LeafNotFound { index: usize },

    #[error("Invalid tree depth: {0}")]
    InvalidDepth(usize),

    #[error("Inconsistent tree state: {0}")]
    InconsistentState(String),

    #[error("Non-membership proof failed: target {target} should be between {low} and {high}")]
    NonMembershipProofFailed {
        target: String,
        low: String,
        high: String,
    },

    #[error("Duplicate insertion: {value}")]
    DuplicateInsertion { value: String },
}

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("Invalid nullifier: {0}")]
    InvalidNullifier(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Hash computation failed: {0}")]
    HashError(String),

    #[error("Range proof failed: value {value} outside range [{min}, {max})")]
    RangeProofFailed {
        value: u64,
        min: u64,
        max: u64
    },

    #[error("Pedersen commitment error: {0}")]
    PedersenError(String),

    #[error("Poseidon hash error: {0}")]
    PoseidonError(String),
}

/// Data structure validation errors
#[derive(Error, Debug)]
pub enum DataStructureError {
    #[error("Invalid note: {0}")]
    InvalidNote(String),

    #[error("Invalid compliance state: {0}")]
    InvalidComplianceState(String),

    #[error("Invalid callback: {0}")]
    InvalidCallback(String),

    #[error("Asset type {0} not supported")]
    UnsupportedAssetType(u32),

    #[error("Pool {0} not found")]
    PoolNotFound(u32),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Field element conversion failed: {0}")]
    FieldConversionError(String),
}

/// State management errors
#[derive(Error, Debug)]
pub enum StateError {
    #[error("State transition invalid: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    #[error("Account frozen")]
    AccountFrozen,

    #[error("Daily limit exceeded: {spent}/{limit}")]
    DailyLimitExceeded { spent: u128, limit: u128 },

    #[error("Monthly limit exceeded: {spent}/{limit}")]
    MonthlyLimitExceeded { spent: u128, limit: u128 },

    #[error("Yearly limit exceeded: {spent}/{limit}")]
    YearlyLimitExceeded { spent: u128, limit: u128 },

    #[error("Callback expired at {expiry}, current time: {current}")]
    CallbackExpired { expiry: u64, current: u64 },

    #[error("Compliance check failed: {reason}")]
    ComplianceCheckFailed { reason: String },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Double spend detected: nullifier {0}")]
    DoubleSpend(String),

    #[error("Insufficient supply")]
    InsufficientSupply,

    #[error("Tree error: {0}")]
    TreeError(String),

    #[error("Invalid proof")]
    InvalidProof,


    #[error("Supply invariant violated: minted {minted}, burned {burned}, expected {expected}, actual {actual}")]
    SupplyInvariantViolated {
        minted: u128,
        burned: u128,
        expected: u128,
        actual: u128,
    },
}

/// Result type alias for Fluxe operations
pub type FluxeResult<T> = Result<T, FluxeError>;

impl From<String> for StateError {
    fn from(e: String) -> Self {
        StateError::TreeError(e)
    }
}

/// Helper trait for adding context to errors
pub trait ErrorContext<T> {
    /// Add context to an error
    fn context<S: Into<String>>(self, ctx: S) -> FluxeResult<T>;

    /// Add context with a closure (only evaluated if error)
    fn with_context<F, S>(self, f: F) -> FluxeResult<T>
    where
        F: FnOnce() -> S,
        S: Into<String>;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
    E: Into<FluxeError>,
{
    fn context<S: Into<String>>(self, ctx: S) -> FluxeResult<T> {
        self.map_err(|e| {
            let base_error = e.into();
            FluxeError::Other(format!("{}: {}", ctx.into(), base_error))
        })
    }

    fn with_context<F, S>(self, f: F) -> FluxeResult<T>
    where
        F: FnOnce() -> S,
        S: Into<String>,
    {
        self.map_err(|e| {
            let base_error = e.into();
            FluxeError::Other(format!("{}: {}", f().into(), base_error))
        })
    }
}

/// Validation helper functions
pub mod validation {
    use super::*;

    /// Validate that a value is within range
    pub fn validate_range(value: u64, min: u64, max: u64) -> Result<(), CryptoError> {
        if value < min || value >= max {
            return Err(CryptoError::RangeProofFailed { value, min, max });
        }
        Ok(())
    }

    /// Validate field element string
    pub fn validate_field_string(s: &str) -> Result<(), DataStructureError> {
        if !s.starts_with("0x") || s.len() != 66 {
            return Err(DataStructureError::FieldConversionError(
                format!("Invalid field element format: {}", s)
            ));
        }
        Ok(())
    }

    /// Validate amount is non-zero
    pub fn validate_amount(amount: u128) -> Result<(), DataStructureError> {
        if amount == 0 {
            return Err(DataStructureError::InvalidAmount(
                "Amount must be non-zero".to_string()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MerkleError::TreeFull { depth: 16, max_size: 65536 };
        assert_eq!(err.to_string(), "Tree is full (depth: 16, max_size: 65536)");
    }

    #[test]
    fn test_error_context() {
        let result: Result<(), MerkleError> = Err(MerkleError::InvalidDepth(256));
        let with_context = result.context("Creating tree");
        assert!(with_context.is_err());
        assert!(with_context.unwrap_err().to_string().contains("Creating tree"));
    }

    #[test]
    fn test_validation() {
        assert!(validation::validate_range(50, 0, 100).is_ok());
        assert!(validation::validate_range(100, 0, 100).is_err());
        assert!(validation::validate_amount(100).is_ok());
        assert!(validation::validate_amount(0).is_err());
    }
}