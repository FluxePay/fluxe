use fluxe_circuits::MintCircuit;
use crate::circuits::RapidsnarkCircuit;
use crate::errors::Result;
use crate::serializer::{export_to_circom_files, CircuitStats};
use std::path::Path;

impl RapidsnarkCircuit for MintCircuit {
    fn export_to_rapidsnark<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        r1cs_path: P1,
        wtns_path: P2,
    ) -> Result<CircuitStats> {
        export_to_circom_files(self.clone(), r1cs_path, wtns_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires actual tree setup with proper circuit configuration
    fn test_mint_circuit_export() {
        // This is a placeholder test - actual test would require proper setup
        // See integration tests for full examples
    }
}
