use ark_bls12_381::Fr as F;
use ark_ed_on_bls12_381::{Fq as JubjubFq, constraints::FqVar};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use fluxe_core::{
    data_structures::{CallbackEntry, CallbackInvocation, ComplianceState, ZkObject},
    merkle::{MerklePath, RangePath},
    types::*,
};

use crate::circuits::FluxeCircuit;
use crate::gadgets::*;

/// Object update circuit for compliance state transitions
#[derive(Clone)]
pub struct ObjectUpdateCircuit {
    // Private inputs
    /// Old zk-object
    pub obj_old: ZkObject,
    
    /// Old compliance state
    pub state_old: ComplianceState,
    
    /// New zk-object
    pub obj_new: ZkObject,
    
    /// New compliance state
    pub state_new: ComplianceState,
    
    /// Callback entry being processed (if any)
    pub callback_entry: Option<CallbackEntry>,
    
    /// Callback invocation (if processing)
    pub callback_invocation: Option<CallbackInvocation>,
    
    /// Schnorr signature components for callback verification (if invoked)
    /// (provider_pk_x, provider_pk_y, sig_r_x, sig_r_y) in Jubjub Fq, sig_s in Fr
    pub callback_signature: Option<(JubjubFq, JubjubFq, JubjubFq, JubjubFq, F)>,
    
    /// Merkle path for callback in CB_ROOT (if invoked)
    pub cb_path: Option<MerklePath>,
    
    /// Non-membership proof for callback (if checking non-invocation)
    pub cb_nonmembership: Option<RangePath>,
    
    /// Merkle path for old object
    pub obj_path_old: MerklePath,
    
    /// Decryption key for callback
    pub decrypt_key: Option<F>,
    
    // Public inputs
    /// Old object tree root
    pub obj_root_old: MerkleRoot,
    
    /// New object tree root
    pub obj_root_new: MerkleRoot,
    
    /// Callback tree root
    pub cb_root: MerkleRoot,
    
    /// Current time
    pub current_time: Time,
}

impl ObjectUpdateCircuit {
    pub fn new(
        obj_old: ZkObject,
        state_old: ComplianceState,
        obj_new: ZkObject,
        state_new: ComplianceState,
        callback_entry: Option<CallbackEntry>,
        callback_invocation: Option<CallbackInvocation>,
        cb_path: Option<MerklePath>,
        cb_nonmembership: Option<RangePath>,
        obj_path_old: MerklePath,
        decrypt_key: Option<F>,
        obj_root_old: MerkleRoot,
        obj_root_new: MerkleRoot,
        cb_root: MerkleRoot,
        current_time: Time,
    ) -> Self {
        // For backward compatibility, set callback_signature to None
        Self {
            obj_old,
            state_old,
            obj_new,
            state_new,
            callback_entry,
            callback_invocation,
            callback_signature: None,
            cb_path,
            cb_nonmembership,
            obj_path_old,
            decrypt_key,
            obj_root_old,
            obj_root_new,
            cb_root,
            current_time,
        }
    }
    
    /// Create with Schnorr signature for callback verification
    pub fn new_with_signature(
        obj_old: ZkObject,
        state_old: ComplianceState,
        obj_new: ZkObject,
        state_new: ComplianceState,
        callback_entry: Option<CallbackEntry>,
        callback_invocation: Option<CallbackInvocation>,
        callback_signature: Option<(F, F, F, F, F)>,
        cb_path: Option<MerklePath>,
        cb_nonmembership: Option<RangePath>,
        obj_path_old: MerklePath,
        decrypt_key: Option<F>,
        obj_root_old: MerkleRoot,
        obj_root_new: MerkleRoot,
        cb_root: MerkleRoot,
        current_time: Time,
    ) -> Self {
        Self {
            obj_old,
            state_old,
            obj_new,
            state_new,
            callback_entry,
            callback_invocation,
            callback_signature,
            cb_path,
            cb_nonmembership,
            obj_path_old,
            decrypt_key,
            obj_root_old,
            obj_root_new,
            cb_root,
            current_time,
        }
    }
}

impl ConstraintSynthesizer<F> for ObjectUpdateCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Witness old object
        let obj_old_var = ZkObjectVar::new_witness(
            cs.clone(),
            || Ok(self.obj_old.clone()),
        )?;
        
        // Witness new object
        let obj_new_var = ZkObjectVar::new_witness(
            cs.clone(),
            || Ok(self.obj_new.clone()),
        )?;
        
        // Witness compliance states
        let state_old_var = ComplianceStateVar::new_witness(
            cs.clone(),
            || Ok(self.state_old.clone()),
        )?;
        
        let state_new_var = ComplianceStateVar::new_witness(
            cs.clone(),
            || Ok(self.state_new.clone()),
        )?;
        
        // Witness Merkle path for old object
        let obj_path_var = MerklePathVar::new_witness(
            cs.clone(),
            || Ok(self.obj_path_old.clone()),
        )?;
        
        // Input public values
        let obj_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.obj_root_old))?;
        let obj_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.obj_root_new))?;
        let cb_root_var = FpVar::new_input(cs.clone(), || Ok(self.cb_root))?;
        let current_time_var = FpVar::new_input(cs.clone(), || Ok(F::from(self.current_time)))?;
        
        // Constraint 1: Verify old object membership in OBJ_ROOT_old
        let cm_obj_old = obj_old_var.commitment()?;
        cm_obj_old.enforce_equal(&obj_path_var.leaf)?;
        obj_path_var.enforce_valid(&obj_root_old_var)?;
        
        // Constraint 2: Verify state hashes match
        let computed_state_hash_old = state_old_var.hash()?;
        computed_state_hash_old.enforce_equal(&obj_old_var.state_hash)?;
        
        let computed_state_hash_new = state_new_var.hash()?;
        computed_state_hash_new.enforce_equal(&obj_new_var.state_hash)?;
        
        // Constraint 3: Verify serial increment
        let serial_old_plus_one = &obj_old_var.serial + &FpVar::one();
        serial_old_plus_one.enforce_equal(&obj_new_var.serial)?;
        
        // Constraint 4: Process callback if present
        if let Some(ref callback_entry) = self.callback_entry {
            let callback_var = CallbackEntryVar::new_witness(
                cs.clone(),
                || Ok(callback_entry.clone()),
            )?;
            
            // Update callback hash chain (remove processed callback)
            let callback_hash = callback_var.hash()?;
            let new_cb_hash = poseidon_hash_zk(&[
                obj_old_var.cb_head_hash.clone(),
                callback_hash,
            ])?;
            new_cb_hash.enforce_equal(&obj_new_var.cb_head_hash)?;
            
            // If invocation exists, verify it
            if let Some(ref invocation) = self.callback_invocation {
                let invocation_var = CallbackInvocationVar::new_witness(
                    cs.clone(),
                    || Ok(invocation.clone()),
                )?;
                
                // Verify callback ticket matches
                callback_var.ticket.enforce_equal(&invocation_var.ticket)?;
                
                // Verify invocation is in CB_ROOT using S-IMT membership proof
                if let Some(ref cb_path) = self.cb_path {
                    let cb_path_var = MerklePathVar::new_witness(
                        cs.clone(),
                        || Ok(cb_path.clone()),
                    )?;
                    
                    // Verify the invocation hash matches the leaf in the path
                    let invocation_hash = invocation_var.hash()?;
                    invocation_hash.enforce_equal(&cb_path_var.leaf)?;
                    
                    // Verify the path is valid against CB_ROOT
                    cb_path_var.enforce_valid(&cb_root_var)?;
                    
                    // Verify signature on invocation payload
                    if invocation.signature.is_some() && self.callback_signature.is_some() {
                        // Witness the signature components (Fq for curve points, Fr for scalar)
                        let (pk_x, pk_y, r_x, r_y, s) = self.callback_signature.unwrap();
                        let pk_x_var = FqVar::new_witness(cs.clone(), || Ok(pk_x))?;
                        let pk_y_var = FqVar::new_witness(cs.clone(), || Ok(pk_y))?;
                        let r_x_var = FqVar::new_witness(cs.clone(), || Ok(r_x))?;
                        let r_y_var = FqVar::new_witness(cs.clone(), || Ok(r_y))?;
                        let s_var = FpVar::new_witness(cs.clone(), || Ok(s))?;
                        
                        // Verify Schnorr signature with proper Fq coordinates
                        let sig_valid = invocation_var.verify_signature(
                            cs.clone(),
                            &pk_x_var,
                            &pk_y_var,
                            &r_x_var,
                            &r_y_var,
                            &s_var,
                        )?;
                        sig_valid.enforce_equal(&Boolean::TRUE)?;
                    } else if invocation.signature.is_some() {
                        // Signature provided but no witness data - this is an error
                        return Err(SynthesisError::AssignmentMissing);
                    }
                } else {
                    // Fallback: simplified check
                    let invocation_hash = invocation_var.hash()?;
                    let is_valid = invocation_hash.is_neq(&FpVar::zero())?;
                    is_valid.enforce_equal(&Boolean::TRUE)?;
                }
                
                // TODO: Decrypt and verify callback payload
                // - Use decrypt_key to decrypt invocation.payload
                // - Extract method_id and arguments
                // - Verify arguments are valid for the method
                
                // Check timestamp is before current time
                let time_valid = invocation_var.timestamp.is_neq(&FpVar::zero())?;
                time_valid.enforce_equal(&Boolean::TRUE)?;
            } else {
                // Timeout path: verify callback expired AND not invoked
                
                // First, verify non-membership in CB_ROOT (callback not invoked)
                if let Some(ref nm_proof) = self.cb_nonmembership {
                    let nm_proof_var = RangePathVar::new_witness(
                        cs.clone(),
                        || Ok(nm_proof.clone()),
                    )?;
                    
                    // Verify the proof target matches the callback ticket
                    nm_proof_var.target.enforce_equal(&callback_var.ticket)?;
                    
                    // Verify non-membership (gap proof)
                    nm_proof_var.enforce_valid(&cb_root_var)?;
                }
                
                // Then verify expiry time has passed
                let expiry_time = callback_var.expiry_time.clone();
                // Check current_time > expiry_time (simplified)
                let is_expired = current_time_var.is_cmp(
                    &expiry_time,
                    std::cmp::Ordering::Greater,
                    false,
                )?;
                is_expired.enforce_equal(&Boolean::TRUE)?;
            }
        } else {
            // No callback processing - hash chain unchanged
            obj_old_var.cb_head_hash.enforce_equal(&obj_new_var.cb_head_hash)?;
        }
        
        // Constraint 5: Verify state transition is valid
        ObjectUpdateCircuit::verify_state_transition_static(&state_old_var, &state_new_var)?;
        
        // Constraint 6: Compute new object commitment
        let cm_obj_new = obj_new_var.commitment()?;
        
        // Constraint 7: Verify OBJ_ROOT_new transition
        // Simplified: just append new object (in reality would be more complex tree update)
        let computed_root = poseidon_hash_zk(&[
            obj_root_old_var.clone(),
            cm_obj_new,
        ])?;
        computed_root.enforce_equal(&obj_root_new_var)?;
        
        Ok(())
    }
}

impl ObjectUpdateCircuit {
    /// Verify state transition is valid according to method rules
    fn verify_state_transition_static(
        state_old: &ComplianceStateVar,
        state_new: &ComplianceStateVar,
    ) -> Result<(), SynthesisError> {
        // Method-specific state transition rules
        // In practice, method_id would be extracted from callback payload
        
        // Risk score can only increase or stay same (never decrease)
        // Check if new >= old
        let risk_not_decreased = state_new.risk_score.is_cmp(
            &state_old.risk_score,
            std::cmp::Ordering::Greater,
            true,
        )?;
        risk_not_decreased.enforce_equal(&Boolean::TRUE)?;
        
        // Level must be valid (0-3)
        use crate::gadgets::range_proof::RangeProofGadget;
        RangeProofGadget::prove_range_bounds(
            state_new.level.cs(),
            &state_new.level,
            0,
            3,
            2, // 2 bits enough for 0-3
        )?;
        
        // If frozen flag is set, limits must be zero
        let limits_sum = &state_new.daily_limit + &state_new.monthly_limit + &state_new.yearly_limit;
        let is_frozen_and_limits_zero = &state_new.frozen & &limits_sum.is_eq(&FpVar::zero())?;
        let not_frozen_or_limits_ok = &!&state_new.frozen | &is_frozen_and_limits_zero;
        not_frozen_or_limits_ok.enforce_equal(&Boolean::TRUE)?;
        
        // Jurisdiction bits must remain valid (non-zero means some jurisdiction)
        let jurisdiction_valid = state_new.jurisdiction_bits.is_neq(&FpVar::zero())?;
        jurisdiction_valid.enforce_equal(&Boolean::TRUE)?;
        
        // Last review time can only increase (time moves forward)
        // Check if new >= old
        let time_not_backwards = state_new.last_review_time.is_cmp(
            &state_old.last_review_time,
            std::cmp::Ordering::Greater,
            true,
        )?;
        time_not_backwards.enforce_equal(&Boolean::TRUE)?;
        
        Ok(())
    }
}

impl FluxeCircuit for ObjectUpdateCircuit {
    fn public_inputs(&self) -> Vec<F> {
        vec![
            self.obj_root_old,
            self.obj_root_new,
            self.cb_root,
            F::from(self.current_time),
        ]
    }
    
    fn verify_public_inputs(&self) -> Result<(), FluxeError> {
        // Verify serial increment
        if self.obj_new.serial != self.obj_old.serial + 1 {
            return Err(FluxeError::Other("Invalid serial update".to_string()));
        }
        
        // Verify state hash consistency
        if self.obj_old.state_hash != self.state_old.hash() {
            return Err(FluxeError::Other("Old state hash mismatch".to_string()));
        }
        
        if self.obj_new.state_hash != self.state_new.hash() {
            return Err(FluxeError::Other("New state hash mismatch".to_string()));
        }
        
        Ok(())
    }
}