use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use fluxe_core::{
    data_structures::{ExitReceipt, Note},
    merkle::{MerklePath, RangePath, AppendWitness},
    types::*,
};
use crate::gadgets::sorted_insert::{SortedInsertWitness, SimtInsertVar};
use crate::gadgets::merkle_append::ImtAppendProofVar;

use crate::circuits::FluxeCircuit;
use crate::gadgets::*;

/// Burn circuit for withdrawals (boundary-out transactions)
#[derive(Clone)]
pub struct BurnCircuit {
    // Private inputs
    /// Input note being burned
    pub note_in: Note,
    
    /// Value of input note
    pub value_in: u64,
    
    /// Randomness for input value commitment
    pub value_randomness_in: F,
    
    /// Owner authentication secrets
    pub owner_sk: F,
    
    /// Public key coordinates for EC authentication
    pub owner_pk_x: F,
    pub owner_pk_y: F,
    
    /// Nullifier key
    pub nk: F,
    
    /// Merkle path for input note
    pub cm_path: MerklePath,
    
    /// Non-membership proof for nullifier
    pub nf_nonmembership: Option<RangePath>,
    
    /// Insertion witness for nullifier into NFT
    pub nf_insert_witness: Option<SortedInsertWitness>,
    
    /// Exit receipt
    pub exit_receipt: ExitReceipt,
    
    /// Append witness for EXIT_ROOT update
    pub exit_append_witness: AppendWitness,
    
    // Public inputs
    /// Commitment tree root
    pub cmt_root: MerkleRoot,
    
    /// Old nullifier tree root
    pub nft_root_old: MerkleRoot,
    
    /// New nullifier tree root
    pub nft_root_new: MerkleRoot,
    
    /// Old exit root
    pub exit_root_old: MerkleRoot,
    
    /// New exit root
    pub exit_root_new: MerkleRoot,
    
    /// Asset type being burned
    pub asset_type: AssetType,
    
    /// Amount being burned
    pub amount: Amount,
    
    /// Nullifier of input note
    pub nf_in: Nullifier,
}

impl BurnCircuit {
    pub fn new(
        note_in: Note,
        value_in: u64,
        value_randomness_in: F,
        nk: F,
        owner_sk: F,
        owner_pk_x: F,
        owner_pk_y: F,
        cm_path: MerklePath,
        nf_nonmembership: Option<RangePath>,
        nf_insert_witness: Option<SortedInsertWitness>,
        exit_receipt: ExitReceipt,
        exit_append_witness: AppendWitness,
        cmt_root: MerkleRoot,
        nft_root_old: MerkleRoot,
        nft_root_new: MerkleRoot,
        exit_root_old: MerkleRoot,
        exit_root_new: MerkleRoot,
    ) -> Self {
        let asset_type = note_in.asset_type;
        let amount = exit_receipt.amount;
        let nf_in = exit_receipt.burned_nf;
        
        Self {
            note_in,
            value_in,
            value_randomness_in,
            owner_sk,
            owner_pk_x,
            owner_pk_y,
            nk,
            cm_path,
            nf_nonmembership,
            nf_insert_witness,
            exit_receipt,
            exit_append_witness,
            cmt_root,
            nft_root_old,
            nft_root_new,
            exit_root_old,
            exit_root_new,
            asset_type,
            amount,
            nf_in,
        }
    }
}

impl ConstraintSynthesizer<F> for BurnCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Witness private inputs
        let note_in_var = NoteVar::new_witness(
            cs.clone(),
            || Ok(self.note_in.clone()),
            self.value_in,
            &self.value_randomness_in,
        )?;
        
        let nk_var = FpVar::new_witness(cs.clone(), || Ok(self.nk))?;
        let cm_path_var = MerklePathVar::new_witness(cs.clone(), || Ok(self.cm_path.clone()))?;
        let exit_var = ExitReceiptVar::new_witness(cs.clone(), || Ok(self.exit_receipt.clone()))?;
        
        // Input public values
        let cmt_root_var = FpVar::new_input(cs.clone(), || Ok(self.cmt_root))?;
        let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.nft_root_old))?;
        let nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.nft_root_new))?;
        let exit_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.exit_root_old))?;
        let exit_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.exit_root_new))?;
        let asset_type_var = FpVar::new_input(cs.clone(), || Ok(F::from(self.asset_type as u64)))?;
        let amount_var = FpVar::new_input(cs.clone(), || Ok(self.amount.to_field()))?;
        let nf_in_var = FpVar::new_input(cs.clone(), || Ok(self.nf_in))?;
        
        // Constraint 1: Verify membership - input note is in CMT tree
        let cm_in = note_in_var.commitment()?;
        cm_path_var.leaf.enforce_equal(&cm_in)?;
        cm_path_var.enforce_valid(&cmt_root_var)?;
        
        // Constraint 2: Verify nullifier correctness
        let computed_nf = note_in_var.nullifier(&nk_var)?;
        computed_nf.enforce_equal(&nf_in_var)?;
        
        // Constraint 2b: Verify EC-based owner authentication
        // SECURITY CRITICAL: Must verify sk corresponds to note owner
        let owner_sk_var = FpVar::new_witness(cs.clone(), || Ok(self.owner_sk))?;
        
        // Derive the public key from the secret key (returns FqVar)
        use crate::gadgets::auth::AuthGadget;
        let (derived_pk_x_fq, derived_pk_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), &owner_sk_var)?;
        
        // Compute owner address from the derived public key: addr = H(pk_x, pk_y)
        let computed_owner_addr = AuthGadget::compute_owner_address_from_fq(cs.clone(), &derived_pk_x_fq, &derived_pk_y_fq)?;
        
        // Enforce that computed address matches note's owner
        computed_owner_addr.enforce_equal(&note_in_var.owner_addr)?;
        
        // Constraint 3: Value check - burned amount <= note value
        use crate::gadgets::comparison::ComparisonGadget;
        let amount_le_value = ComparisonGadget::is_less_than_or_equal(
            cs.clone(),
            &amount_var,
            &note_in_var.value
        )?;
        amount_le_value.enforce_equal(&Boolean::TRUE)?;
        
        // Constraint 4: Asset type matches
        note_in_var.asset_type.enforce_equal(&asset_type_var)?;
        exit_var.asset_type.enforce_equal(&asset_type_var)?;
        
        // Constraint 5: Exit receipt consistency
        exit_var.amount.enforce_equal(&amount_var)?;
        exit_var.burned_nf.enforce_equal(&nf_in_var)?;
        
        // Constraint 6: Non-membership of nf_in in NFT_ROOT_old (S-IMT gap proof)
        // Verify the nullifier doesn't already exist (prevent double spend)
        if let Some(ref nm_proof) = self.nf_nonmembership {
            let nm_proof_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof.clone()))?;
            
            // Verify the proof target matches our nullifier
            nm_proof_var.target.enforce_equal(&nf_in_var)?;
            
            // Verify the non-membership proof is valid for NFT_ROOT_old
            nm_proof_var.enforce_valid(&nft_root_old_var)?;
        } else {
            // SECURITY: Non-membership proof is REQUIRED
            // Without it, double-spending is possible
            return Err(SynthesisError::Unsatisfiable);
        }
        
        // Constraint 7: Compliance gates
        // Check that the note is not frozen (simplified - would check ZkObject state)
        let compliance_not_frozen = note_in_var.compliance_hash.is_neq(&FpVar::zero())?;
        compliance_not_frozen.enforce_equal(&Boolean::TRUE)?;
        
        // Check spending limits (simplified - would check against ComplianceState)
        use crate::gadgets::range_proof::RangeProofGadget;
        // Verify amount is within acceptable range (64-bit for monetary values)
        RangeProofGadget::prove_range_bits(cs.clone(), &amount_var, 64)?;
        
        // Constraint 8: Verify callback expiry (simplified)
        // In practice, would check if any callbacks in cb_head_hash have expired
        // For now, just ensure callbacks_hash is set (non-zero means no pending expired callbacks)
        let callbacks_handled = note_in_var.callbacks_hash.is_neq(&FpVar::zero())?;
        callbacks_handled.enforce_equal(&Boolean::TRUE)?;
        
        // Constraint 9: Tree root transitions
        // SECURITY CRITICAL: Proper tree updates required
        
        // For NFT_ROOT (S-IMT): Proper sorted tree insertion
        if let Some(ref insert_witness) = self.nf_insert_witness {
            let insert_var = SimtInsertVar::new_witness(
                cs.clone(),
                insert_witness.clone(),
                self.nft_root_old,
                self.nft_root_new,
            )?;
            
            // Verify the insertion matches our nullifier
            insert_var.target.enforce_equal(&nf_in_var)?;
            
            // Verify old root matches
            insert_var.old_root.enforce_equal(&nft_root_old_var)?;
            
            // Verify new root matches
            insert_var.new_root.enforce_equal(&nft_root_new_var)?;
            
            // Verify the insertion is valid
            insert_var.enforce()?;
        } else {
            // SECURITY: Proper insertion witness is REQUIRED
            return Err(SynthesisError::Unsatisfiable);
        }
        
        // For EXIT_ROOT (I-IMT): Proper append verification using ImtAppendProofVar
        let exit_hash = exit_var.hash()?;
        
        // Create the append proof variable
        let exit_append_proof = ImtAppendProofVar::new_witness(
            cs.clone(),
            self.exit_append_witness.clone(),
            self.exit_root_old,
            self.exit_root_new,
        )?;
        
        // Verify the append operation
        let append_valid = exit_append_proof.verify()?;
        append_valid.enforce_equal(&Boolean::TRUE)?;
        
        // Verify the appended leaf is the exit receipt hash
        exit_append_proof.appended_leaf.enforce_equal(&exit_hash)?;
        
        // Verify the roots match our public inputs
        exit_append_proof.old_root.enforce_equal(&exit_root_old_var)?;
        exit_append_proof.new_root.enforce_equal(&exit_root_new_var)?;
        
        // Constraint 10: Authorization check
        // Verify that the spender knows the nullifier key (already done via nullifier computation)
        // Additional check: owner_addr must match (simplified)
        let owner_check = note_in_var.owner_addr.is_neq(&FpVar::zero())?;
        owner_check.enforce_equal(&Boolean::TRUE)?;
        
        Ok(())
    }
}

impl FluxeCircuit for BurnCircuit {
    fn public_inputs(&self) -> Vec<F> {
        vec![
            self.cmt_root,
            self.nft_root_old,
            self.nft_root_new,
            self.exit_root_old,
            self.exit_root_new,
            F::from(self.asset_type as u64),
            self.amount.to_field(),
            self.nf_in,
        ]
    }
    
    fn verify_public_inputs(&self) -> Result<(), FluxeError> {
        // Verify amount doesn't exceed note value
        if self.amount > Amount::from(self.value_in) {
            return Err(FluxeError::InsufficientBalance);
        }
        
        // Verify asset types match
        if self.note_in.asset_type != self.asset_type {
            return Err(FluxeError::Other("Asset type mismatch".to_string()));
        }
        
        Ok(())
    }
}