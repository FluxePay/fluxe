use ark_bls12_381::Fr as F;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::poseidon::poseidon_hash_zk;

/// Variable for encrypted memo
#[derive(Clone)]
pub struct MemoVar {
    pub encrypted_chunks: Vec<FpVar<F>>,
}

impl MemoVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        memo_bytes: &[u8],
    ) -> Result<Self, SynthesisError> {
        // Convert memo bytes to field elements (31 bytes per field element)
        let encrypted_chunks = memo_bytes
            .chunks(31)
            .map(|chunk| {
                use ark_ff::PrimeField;
                let mut bytes = vec![0u8; 32];
                bytes[..chunk.len()].copy_from_slice(chunk);
                let value = F::from_le_bytes_mod_order(&bytes);
                FpVar::new_witness(cs.clone(), || Ok(value))
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self { encrypted_chunks })
    }
    
    /// Compute hash of the memo
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        if self.encrypted_chunks.is_empty() {
            Ok(FpVar::zero())
        } else {
            poseidon_hash_zk(&self.encrypted_chunks)
        }
    }
}