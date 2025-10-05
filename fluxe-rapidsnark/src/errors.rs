use thiserror::Error;

#[derive(Error, Debug)]
pub enum RapidsnarkError {
    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Circuit error: {0}")]
    Circuit(String),

    #[error("Prover error: {0}")]
    Prover(String),

    #[error("Verifier error: {0}")]
    Verifier(String),

    #[error("Field element conversion error: {0}")]
    FieldConversion(String),

    #[error("Fluxe error: {0}")]
    Fluxe(#[from] fluxe_core::errors::FluxeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, RapidsnarkError>;
