use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use fluxe_core::data_structures::{ExitReceipt, IngressReceipt};

use crate::gadgets::poseidon::poseidon_hash_zk;

/// Ingress receipt variable for circuits
#[derive(Clone)]
pub struct IngressReceiptVar {
    pub asset_type: FpVar<F>,
    pub amount: FpVar<F>,
    pub beneficiary_cm: FpVar<F>,
    pub nonce: FpVar<F>,
    pub aux: FpVar<F>,
}

impl IngressReceiptVar {
    /// Create new ingress receipt variable as witness
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        receipt: impl FnOnce() -> Result<IngressReceipt, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let receipt = receipt()?;
        
        Ok(Self {
            asset_type: FpVar::new_witness(cs.clone(), || Ok(F::from(receipt.asset_type as u64)))?,
            amount: FpVar::new_witness(cs.clone(), || Ok(receipt.amount.to_field()))?,
            beneficiary_cm: FpVar::new_witness(cs.clone(), || Ok(receipt.beneficiary_cm))?,
            nonce: FpVar::new_witness(cs.clone(), || Ok(F::from(receipt.nonce)))?,
            aux: FpVar::new_witness(cs, || Ok(receipt.aux))?,
        })
    }
    
    /// Compute hash of this receipt
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        poseidon_hash_zk(&[
            self.asset_type.clone(),
            self.amount.clone(),
            self.beneficiary_cm.clone(),
            self.nonce.clone(),
            self.aux.clone(),
        ])
    }
}

/// Exit receipt variable for circuits
#[derive(Clone)]
pub struct ExitReceiptVar {
    pub asset_type: FpVar<F>,
    pub amount: FpVar<F>,
    pub burned_nf: FpVar<F>,
    pub nonce: FpVar<F>,
    pub aux: FpVar<F>,
}

impl ExitReceiptVar {
    /// Create new exit receipt variable as witness
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        receipt: impl FnOnce() -> Result<ExitReceipt, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let receipt = receipt()?;
        
        Ok(Self {
            asset_type: FpVar::new_witness(cs.clone(), || Ok(F::from(receipt.asset_type as u64)))?,
            amount: FpVar::new_witness(cs.clone(), || Ok(receipt.amount.to_field()))?,
            burned_nf: FpVar::new_witness(cs.clone(), || Ok(receipt.burned_nf))?,
            nonce: FpVar::new_witness(cs.clone(), || Ok(F::from(receipt.nonce)))?,
            aux: FpVar::new_witness(cs, || Ok(receipt.aux))?,
        })
    }
    
    /// Compute hash of this receipt
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        poseidon_hash_zk(&[
            self.asset_type.clone(),
            self.amount.clone(),
            self.burned_nf.clone(),
            self.nonce.clone(),
            self.aux.clone(),
        ])
    }
}