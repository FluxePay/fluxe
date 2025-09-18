use ark_bls12_381::Fr as F;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use fluxe_core::data_structures::{ZkObject, ComplianceState};

use super::poseidon::poseidon_hash_zk;

/// Variable for ZkObject
#[derive(Clone)]
pub struct ZkObjectVar {
    pub state_hash: FpVar<F>,
    pub serial: FpVar<F>,
    pub cb_head_hash: FpVar<F>,
}

impl ZkObjectVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        f: impl FnOnce() -> Result<ZkObject, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let obj = f()?;
        Ok(Self {
            state_hash: FpVar::new_witness(cs.clone(), || Ok(obj.state_hash))?,
            serial: FpVar::new_witness(cs.clone(), || Ok(F::from(obj.serial)))?,
            cb_head_hash: FpVar::new_witness(cs, || Ok(obj.cb_head_hash))?,
        })
    }
    
    /// Compute commitment to this object
    pub fn commitment(&self) -> Result<FpVar<F>, SynthesisError> {
        poseidon_hash_zk(&[
            self.state_hash.clone(),
            self.serial.clone(),
            self.cb_head_hash.clone(),
        ])
    }
}

/// Variable for ComplianceState
#[derive(Clone)]
pub struct ComplianceStateVar {
    pub level: FpVar<F>,
    pub risk_score: FpVar<F>,
    pub frozen: Boolean<F>,
    pub last_review_time: FpVar<F>,
    pub jurisdiction_bits: FpVar<F>,
    pub daily_limit: FpVar<F>,
    pub monthly_limit: FpVar<F>,
    pub yearly_limit: FpVar<F>,
    pub rep_hash: FpVar<F>,
}

impl ComplianceStateVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        f: impl FnOnce() -> Result<ComplianceState, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let state = f()?;
        Ok(Self {
            level: FpVar::new_witness(cs.clone(), || Ok(F::from(state.level)))?,
            risk_score: FpVar::new_witness(cs.clone(), || Ok(F::from(state.risk_score)))?,
            frozen: Boolean::new_witness(cs.clone(), || Ok(state.frozen))?,
            last_review_time: FpVar::new_witness(cs.clone(), || Ok(F::from(state.last_review_time)))?,
            jurisdiction_bits: FpVar::new_witness(cs.clone(), || {
                // Match the native bytes_to_field implementation
                Ok(fluxe_core::utils::bytes_to_field(&state.jurisdiction_bits))
            })?,
            daily_limit: FpVar::new_witness(cs.clone(), || Ok(state.daily_limit.to_field()))?,
            monthly_limit: FpVar::new_witness(cs.clone(), || Ok(state.monthly_limit.to_field()))?,
            yearly_limit: FpVar::new_witness(cs.clone(), || Ok(state.yearly_limit.to_field()))?,
            rep_hash: FpVar::new_witness(cs, || Ok(state.rep_hash))?,
        })
    }
    
    /// Compute hash of this state
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        // Convert frozen boolean to field element
        let frozen_field = FpVar::conditionally_select(
            &self.frozen,
            &FpVar::one(),
            &FpVar::zero(),
        )?;
        
        poseidon_hash_zk(&[
            self.level.clone(),
            self.risk_score.clone(),
            frozen_field,
            self.last_review_time.clone(),
            self.jurisdiction_bits.clone(),
            self.daily_limit.clone(),
            self.monthly_limit.clone(),
            self.yearly_limit.clone(),
            self.rep_hash.clone(),
        ])
    }
}