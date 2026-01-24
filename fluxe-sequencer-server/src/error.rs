use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

/// Sequencer server errors
#[derive(Debug, Error)]
pub enum SequencerError {
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Block not found: {0}")]
    BlockNotFound(u64),

    #[error("State error: {0}")]
    StateError(String),

    #[error("Sequencer busy")]
    SequencerBusy,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<SequencerError> for ErrorObjectOwned {
    fn from(err: SequencerError) -> Self {
        let (code, message) = match &err {
            SequencerError::InvalidTransaction(_) => (-32001, err.to_string()),
            SequencerError::ProofVerificationFailed(_) => (-32002, err.to_string()),
            SequencerError::TransactionNotFound(_) => (-32003, err.to_string()),
            SequencerError::BlockNotFound(_) => (-32004, err.to_string()),
            SequencerError::StateError(_) => (-32005, err.to_string()),
            SequencerError::SequencerBusy => (-32006, err.to_string()),
            SequencerError::Internal(_) => (-32603, err.to_string()),
            SequencerError::Serialization(_) => (-32700, err.to_string()),
        };
        ErrorObjectOwned::owned(code, message, None::<()>)
    }
}
