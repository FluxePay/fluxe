pub mod mint;
pub mod transfer;
pub mod burn;
pub mod object_update;

use crate::errors::{RapidsnarkError, Result};
use crate::serializer::{export_to_circom_files, CircuitStats};
use std::path::Path;

/// Trait for circuits that can be exported to Circom format
pub trait RapidsnarkCircuit {
    /// Export this circuit to R1CS and WTNS files
    fn export_to_rapidsnark<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        r1cs_path: P1,
        wtns_path: P2,
    ) -> Result<CircuitStats>;
}
