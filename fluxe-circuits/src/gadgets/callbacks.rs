use ark_bls12_381::Fr as F;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::*,
    alloc::AllocVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use fluxe_core::data_structures::{CallbackEntry, CallbackInvocation};

use super::poseidon::poseidon_hash_zk;
use super::schnorr::SchnorrGadget;

/// Variable for CallbackEntry
#[derive(Clone)]
pub struct CallbackEntryVar {
    pub ticket: FpVar<F>,
    pub method_id: FpVar<F>,
    pub expiry_time: FpVar<F>,
    pub provider_key: FpVar<F>,
    pub user_rand: FpVar<F>,
}

impl CallbackEntryVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        f: impl FnOnce() -> Result<CallbackEntry, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let entry = f()?;
        let ticket = entry.ticket();
        Ok(Self {
            ticket: FpVar::new_witness(cs.clone(), || Ok(ticket))?,
            method_id: FpVar::new_witness(cs.clone(), || Ok(F::from(entry.method_id as u64)))?,
            expiry_time: FpVar::new_witness(cs.clone(), || Ok(F::from(entry.expiry)))?,
            provider_key: FpVar::new_witness(cs.clone(), || Ok(entry.provider_key))?,
            user_rand: FpVar::new_witness(cs, || Ok(entry.user_rand))?,
        })
    }
    
    /// Compute hash of this callback entry
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        poseidon_hash_zk(&[
            self.method_id.clone(),
            self.expiry_time.clone(),
            self.provider_key.clone(),
            self.user_rand.clone(),
        ])
    }
}

/// Variable for CallbackInvocation
#[derive(Clone)]
pub struct CallbackInvocationVar {
    pub ticket: FpVar<F>,
    pub payload: Vec<FpVar<F>>, // Encrypted payload as field elements
    pub timestamp: FpVar<F>,
    pub has_signature: Boolean<F>,
    pub signature: Vec<FpVar<F>>, // Signature components if present
}

impl CallbackInvocationVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        f: impl FnOnce() -> Result<CallbackInvocation, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let invocation = f()?;
        
        // Convert payload bytes to field elements
        let payload_vars = invocation.payload
            .chunks(31) // Pack 31 bytes per field element to stay under field size
            .map(|chunk| {
                use ark_ff::PrimeField;
                let mut bytes = vec![0u8; 32];
                bytes[..chunk.len()].copy_from_slice(chunk);
                let value = F::from_le_bytes_mod_order(&bytes);
                FpVar::new_witness(cs.clone(), || Ok(value))
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        // Handle optional signature
        let (has_signature, signature_vars) = if let Some(ref sig) = invocation.signature {
            // Serialize signature and convert to field elements
            use ark_serialize::CanonicalSerialize;
            let mut sig_bytes = Vec::new();
            sig.serialize_compressed(&mut sig_bytes).unwrap();
            
            let sig_vars = sig_bytes
                .chunks(31)
                .map(|chunk| {
                    use ark_ff::PrimeField;
                    let mut bytes = vec![0u8; 32];
                    bytes[..chunk.len()].copy_from_slice(chunk);
                    let value = F::from_le_bytes_mod_order(&bytes);
                    FpVar::new_witness(cs.clone(), || Ok(value))
                })
                .collect::<Result<Vec<_>, _>>()?;
            
            (Boolean::new_witness(cs.clone(), || Ok(true))?, sig_vars)
        } else {
            (Boolean::new_witness(cs.clone(), || Ok(false))?, vec![])
        };
        
        Ok(Self {
            ticket: FpVar::new_witness(cs.clone(), || Ok(invocation.ticket))?,
            payload: payload_vars,
            timestamp: FpVar::new_witness(cs, || Ok(F::from(invocation.timestamp)))?,
            has_signature,
            signature: signature_vars,
        })
    }
    
    /// Verify the signature on this invocation using Schnorr on Jubjub
    /// The signature should be valid under the provider's public key
    /// 
    /// Parameters:
    /// - cs: Constraint system reference
    /// - pk_x, pk_y: Provider's public key coordinates (in Fr)
    /// - r_x, r_y: Signature R point coordinates (in Fr)
    /// - s: Signature scalar
    pub fn verify_signature(
        &self,
        cs: ConstraintSystemRef<F>,
        pk_x: &FpVar<F>,
        pk_y: &FpVar<F>,
        r_x: &FpVar<F>,
        r_y: &FpVar<F>,
        s: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Build message fields: [ticket, timestamp, payload_hash]
        let payload_hash = if !self.payload.is_empty() {
            poseidon_hash_zk(&self.payload)?
        } else {
            FpVar::zero()
        };
        
        let msg_fields = vec![
            self.ticket.clone(),
            self.timestamp.clone(),
            payload_hash,
        ];
        
        // Use SchnorrGadget to verify the signature
        SchnorrGadget::verify(cs, pk_x, pk_y, r_x, r_y, s, &msg_fields)
    }
    
    /// Legacy verify_signature for backward compatibility (returns false)
    pub fn verify_signature_stub(&self) -> Result<Boolean<F>, SynthesisError> {
        // This is the old stub method - returns false for safety
        Ok(Boolean::FALSE)
    }
    
    /// Compute hash of this invocation
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        let mut hash_inputs = vec![self.ticket.clone(), self.timestamp.clone()];
        
        // Hash payload
        let payload_hash = if !self.payload.is_empty() {
            poseidon_hash_zk(&self.payload)?
        } else {
            FpVar::zero()
        };
        hash_inputs.push(payload_hash);
        
        // Hash signature
        let sig_hash = if !self.signature.is_empty() {
            poseidon_hash_zk(&self.signature)?
        } else {
            FpVar::zero()
        };
        hash_inputs.push(sig_hash);
        
        poseidon_hash_zk(&hash_inputs)
    }
}