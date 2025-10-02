/// Circuit-specific error handling for Fluxe circuits
use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;
use thiserror::Error;

/// Main error type for circuit operations
#[derive(Error, Debug)]
pub enum CircuitError {
    #[error("Constraint generation failed: {0}")]
    ConstraintGeneration(String),

    #[error("Witness computation failed: {0}")]
    WitnessComputation(String),

    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("Proof verification failed: {0}")]
    ProofVerification(String),

    #[error("Setup generation failed: {0}")]
    SetupGeneration(String),

    #[error("Invalid circuit configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("Field element conversion failed: {0}")]
    FieldConversion(String),

    #[error("Range proof failed: value {value} outside range [{min}, {max})")]
    RangeProofFailed { value: u64, min: u64, max: u64 },

    #[error("Merkle proof verification failed: {0}")]
    MerkleProofFailed(String),

    #[error("Nullifier already spent: {0}")]
    NullifierAlreadySpent(String),

    #[error("Invalid note structure: {0}")]
    InvalidNote(String),

    #[error("Invalid object state: {0}")]
    InvalidObjectState(String),

    #[error("Callback verification failed: {0}")]
    CallbackVerificationFailed(String),

    #[error("Compliance check failed: {0}")]
    ComplianceCheckFailed(String),

    #[error("Value conservation failed: input {input} != output {output} + fee {fee}")]
    ValueConservationFailed {
        input: u128,
        output: u128,
        fee: u128,
    },

    #[error("Invalid lineage: {0}")]
    InvalidLineage(String),

    #[error("Pool policy violation: {0}")]
    PoolPolicyViolation(String),

    #[error("{0}")]
    Other(String),
}

/// Result type alias for circuit operations
pub type CircuitResult<T> = Result<T, CircuitError>;

/// Transfer circuit specific errors
#[derive(Error, Debug)]
pub enum TransferError {
    #[error("Invalid number of inputs: expected {expected}, got {actual}")]
    InvalidInputCount { expected: usize, actual: usize },

    #[error("Invalid number of outputs: expected {expected}, got {actual}")]
    InvalidOutputCount { expected: usize, actual: usize },

    #[error("Asset type mismatch: input {input} != output {output}")]
    AssetTypeMismatch { input: u32, output: u32 },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Invalid recipient address")]
    InvalidRecipient,

    #[error("Transfer amount exceeds limit: {amount} > {limit}")]
    ExceedsLimit { amount: u128, limit: u128 },
}

/// Mint circuit specific errors
#[derive(Error, Debug)]
pub enum MintError {
    #[error("Invalid mint amount: {0}")]
    InvalidAmount(String),

    #[error("Mint authorization failed")]
    Unauthorized,

    #[error("Asset type not supported: {0}")]
    UnsupportedAssetType(u32),

    #[error("Mint receipt validation failed")]
    InvalidReceipt,
}

/// Burn circuit specific errors
#[derive(Error, Debug)]
pub enum BurnError {
    #[error("Invalid burn amount: {0}")]
    InvalidAmount(String),

    #[error("Burn authorization failed")]
    Unauthorized,

    #[error("Exit receipt validation failed")]
    InvalidReceipt,

    #[error("Note already burned")]
    AlreadyBurned,
}

/// Object update circuit specific errors
#[derive(Error, Debug)]
pub enum ObjectUpdateError {
    #[error("Invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    #[error("Serial number mismatch: expected {expected}, got {actual}")]
    SerialMismatch { expected: u64, actual: u64 },

    #[error("Callback not found: {0}")]
    CallbackNotFound(String),

    #[error("Callback expired at {expiry}, current time: {current}")]
    CallbackExpired { expiry: u64, current: u64 },

    #[error("Invalid method execution: {0}")]
    InvalidMethodExecution(String),
}

/// Gadget-specific errors
#[derive(Error, Debug)]
pub enum GadgetError {
    #[error("Poseidon hash computation failed: {0}")]
    PoseidonHashFailed(String),

    #[error("Pedersen commitment failed: {0}")]
    PedersenCommitmentFailed(String),

    #[error("Boolean constraint failed: {0}")]
    BooleanConstraintFailed(String),

    #[error("Comparison failed: {0}")]
    ComparisonFailed(String),

    #[error("Arithmetic overflow: {0}")]
    ArithmeticOverflow(String),

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Invalid field element: {0}")]
    InvalidFieldElement(String),
}

/// Helper trait for adding context to circuit errors
pub trait CircuitErrorContext<T> {
    fn circuit_context<S: Into<String>>(self, ctx: S) -> CircuitResult<T>;
}

impl<T, E> CircuitErrorContext<T> for Result<T, E>
where
    E: Into<CircuitError>,
{
    fn circuit_context<S: Into<String>>(self, ctx: S) -> CircuitResult<T> {
        self.map_err(|e| {
            let base_error = e.into();
            CircuitError::Other(format!("{}: {}", ctx.into(), base_error))
        })
    }
}

/// Conversion implementations
impl From<TransferError> for CircuitError {
    fn from(err: TransferError) -> Self {
        CircuitError::Other(format!("Transfer error: {}", err))
    }
}

impl From<MintError> for CircuitError {
    fn from(err: MintError) -> Self {
        CircuitError::Other(format!("Mint error: {}", err))
    }
}

impl From<BurnError> for CircuitError {
    fn from(err: BurnError) -> Self {
        CircuitError::Other(format!("Burn error: {}", err))
    }
}

impl From<ObjectUpdateError> for CircuitError {
    fn from(err: ObjectUpdateError) -> Self {
        CircuitError::Other(format!("Object update error: {}", err))
    }
}

impl From<GadgetError> for CircuitError {
    fn from(err: GadgetError) -> Self {
        CircuitError::Other(format!("Gadget error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TransferError::InvalidInputCount {
            expected: 2,
            actual: 3,
        };
        assert_eq!(
            err.to_string(),
            "Invalid number of inputs: expected 2, got 3"
        );
    }

    #[test]
    fn test_error_conversion() {
        let transfer_err = TransferError::InvalidRecipient;
        let circuit_err: CircuitError = transfer_err.into();
        assert!(circuit_err.to_string().contains("Transfer error"));
    }

    #[test]
    fn test_error_context() {
        let result: Result<(), CircuitError> = Err(CircuitError::InvalidNote("test".to_string()));
        let with_context = result.circuit_context("Processing note");
        assert!(with_context.is_err());
        assert!(with_context
            .unwrap_err()
            .to_string()
            .contains("Processing note"));
    }
}