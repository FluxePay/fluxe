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
    use fluxe_core::{
        crypto::poseidon_hash,
        data_structures::{IngressReceipt, Note},
        merkle::{IncrementalTree, MerkleParams},
        types::*,
    };
    use ark_bls12_381::Fr;
    use ark_ff::Field;

    #[test]
    #[ignore] // Requires actual tree setup
    fn test_mint_circuit_export() {
        // This is a placeholder test - actual test would require proper setup
        // See integration tests for full examples
    }
}
