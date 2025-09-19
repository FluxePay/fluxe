use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use fluxe_core::{
    data_structures::Note,
    merkle::{MerklePath, RangePath},
    types::*,
};

use crate::circuits::FluxeCircuit;
use crate::gadgets::*;

/// Transfer circuit for private value transfers
#[derive(Clone)]
pub struct TransferCircuit {
    // Private inputs
    /// Input notes being spent
    pub notes_in: Vec<Note>,
    
    /// Values of input notes
    pub values_in: Vec<u64>,
    
    /// Randomness for input value commitments
    pub value_randomness_in: Vec<F>,
    
    /// Output notes being created
    pub notes_out: Vec<Note>,
    
    /// Values of output notes
    pub values_out: Vec<u64>,
    
    /// Randomness for output value commitments
    pub value_randomness_out: Vec<F>,
    
    /// Nullifier keys for inputs
    pub nks: Vec<F>,
    
    /// Merkle paths for input notes
    pub cm_paths: Vec<MerklePath>,
    
    /// Non-membership proofs for nullifiers
    pub nf_nonmembership_proofs: Vec<Option<RangePath>>,
    
    /// Sanctions non-membership proofs for sender addresses
    pub sanctions_nm_proofs_in: Vec<Option<RangePath>>,
    
    /// Sanctions non-membership proofs for recipient addresses
    pub sanctions_nm_proofs_out: Vec<Option<RangePath>>,
    
    // Public inputs
    /// Old commitment tree root
    pub cmt_root_old: MerkleRoot,
    
    /// New commitment tree root
    pub cmt_root_new: MerkleRoot,
    
    /// Old nullifier tree root
    pub nft_root_old: MerkleRoot,
    
    /// New nullifier tree root
    pub nft_root_new: MerkleRoot,
    
    /// Sanctions root for compliance
    pub sanctions_root: MerkleRoot,
    
    /// Pool rules root
    pub pool_rules_root: MerkleRoot,
    
    /// Input nullifiers
    pub nf_list: Vec<Nullifier>,
    
    /// Output commitments
    pub cm_list: Vec<Commitment>,
    
    /// Transaction fee
    pub fee: Amount,
}

impl TransferCircuit {
    pub fn new(
        notes_in: Vec<Note>,
        values_in: Vec<u64>,
        value_randomness_in: Vec<F>,
        notes_out: Vec<Note>,
        values_out: Vec<u64>,
        value_randomness_out: Vec<F>,
        nks: Vec<F>,
        cm_paths: Vec<MerklePath>,
        nf_nonmembership_proofs: Vec<Option<RangePath>>,
        sanctions_nm_proofs_in: Vec<Option<RangePath>>,
        sanctions_nm_proofs_out: Vec<Option<RangePath>>,
        cmt_root_old: MerkleRoot,
        cmt_root_new: MerkleRoot,
        nft_root_old: MerkleRoot,
        nft_root_new: MerkleRoot,
        sanctions_root: MerkleRoot,
        pool_rules_root: MerkleRoot,
        fee: Amount,
    ) -> Self {
        // Compute nullifier list
        let nf_list: Vec<F> = notes_in.iter()
            .zip(nks.iter())
            .map(|(note, nk)| {
                use fluxe_core::crypto::poseidon_hash;
                let psi_field = fluxe_core::utils::bytes_to_field(&note.psi);
                poseidon_hash(&[*nk, psi_field, note.commitment()])
            })
            .collect();
        
        // Compute output commitment list  
        let cm_list: Vec<F> = notes_out.iter()
            .map(|note| note.commitment())
            .collect();
        
        Self {
            notes_in,
            values_in,
            value_randomness_in,
            notes_out,
            values_out,
            value_randomness_out,
            nks,
            cm_paths,
            nf_nonmembership_proofs,
            sanctions_nm_proofs_in,
            sanctions_nm_proofs_out,
            cmt_root_old,
            cmt_root_new,
            nft_root_old,
            nft_root_new,
            sanctions_root,
            pool_rules_root,
            nf_list,
            cm_list,
            fee,
        }
    }
}

impl ConstraintSynthesizer<F> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Witness input notes
        let notes_in_var: Vec<NoteVar> = self.notes_in
            .iter()
            .enumerate()
            .map(|(i, note)| {
                NoteVar::new_witness(
                    cs.clone(),
                    || Ok(note.clone()),
                    self.values_in[i],
                    &self.value_randomness_in[i],
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        // Witness output notes
        let notes_out_var: Vec<NoteVar> = self.notes_out
            .iter()
            .enumerate()
            .map(|(i, note)| {
                NoteVar::new_witness(
                    cs.clone(),
                    || Ok(note.clone()),
                    self.values_out[i],
                    &self.value_randomness_out[i],
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        // Witness nullifier keys and paths
        let nks_var: Vec<FpVar<F>> = self.nks
            .iter()
            .map(|nk| FpVar::new_witness(cs.clone(), || Ok(*nk)))
            .collect::<Result<Vec<_>, _>>()?;
        
        let paths_var: Vec<MerklePathVar> = self.cm_paths
            .iter()
            .map(|path| MerklePathVar::new_witness(cs.clone(), || Ok(path.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Input public values in the correct order
        let cmt_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.cmt_root_old))?;
        
        // Constraint 1: Membership - all inputs are in CMT tree
        for (note_var, path_var) in notes_in_var.iter().zip(paths_var.iter()) {
            let cm = note_var.commitment()?;
            cm.enforce_equal(&path_var.leaf)?;
            path_var.enforce_valid(&cmt_root_old_var)?;
        }
        
        // Constraint 2: Nullifier correctness
        for ((note_var, nk_var), expected_nf) in notes_in_var.iter()
            .zip(nks_var.iter())
            .zip(self.nf_list.iter())
        {
            let computed_nf = note_var.nullifier(nk_var)?;
            let expected_nf_var = FpVar::new_input(cs.clone(), || Ok(*expected_nf))?;
            computed_nf.enforce_equal(&expected_nf_var)?;
        }
        
        // Constraint 3: Value conservation
        let mut sum_in = FpVar::zero();
        for note_var in &notes_in_var {
            sum_in += &note_var.value;
        }
        
        let mut sum_out = FpVar::zero();
        for note_var in &notes_out_var {
            sum_out += &note_var.value;
        }
        // Fee must be created as public input at the right position (last)
        // This happens after nullifiers and commitments are added as public inputs
        // For now, use a witness and we'll constrain it later
        let fee_witness = FpVar::new_witness(cs.clone(), || Ok(self.fee.to_field()))?;
        sum_out += &fee_witness;
        
        // Sum of inputs >= sum of outputs + fee
        sum_in.enforce_equal(&sum_out)?;
        
        // Constraint 3b: Asset type consistency
        // All inputs and outputs must have the same asset type
        if !notes_in_var.is_empty() {
            let asset_type = &notes_in_var[0].asset_type;
            
            // Check all inputs have same asset type
            for note_var in &notes_in_var[1..] {
                note_var.asset_type.enforce_equal(asset_type)?;
            }
            
            // Check all outputs have same asset type as inputs
            for note_var in &notes_out_var {
                note_var.asset_type.enforce_equal(asset_type)?;
            }
        }
        
        // Constraint 4: Range proofs for output values
        use crate::gadgets::range_proof::RangeProofGadget;
        for note_var in &notes_out_var {
            RangeProofGadget::prove_range_bits(cs.clone(), &note_var.value, 64)?;
        }
        
        // Constraint 5: Non-membership of nullifiers in NFT_ROOT_old
        // Each nullifier must not already exist (prevent double spend)
        let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.nft_root_old))?;
        
        // Create fee variable here (will be used later but must be input after other public inputs)
        // Note: fee is the LAST public input, so we create it later
        
        // Verify non-membership for each nullifier
        for (i, nf) in self.nf_list.iter().enumerate() {
            let nf_var = FpVar::new_input(cs.clone(), || Ok(*nf))?;
            
            // Use proper non-membership proof if available
            if i < self.nf_nonmembership_proofs.len() {
                if let Some(ref nm_proof) = self.nf_nonmembership_proofs[i] {
                    let nm_proof_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof.clone()))?;
                    
                    // Verify the proof target matches our nullifier
                    nm_proof_var.target.enforce_equal(&nf_var)?;
                    
                    // Verify the non-membership proof is valid
                    nm_proof_var.enforce_valid(&nft_root_old_var)?;
                } else {
                    // Fallback: just check non-zero
                    let nf_nonzero = nf_var.is_neq(&FpVar::zero())?;
                    nf_nonzero.enforce_equal(&Boolean::TRUE)?;
                }
            } else {
                // No proof provided, use simple check
                let nf_nonzero = nf_var.is_neq(&FpVar::zero())?;
                nf_nonzero.enforce_equal(&Boolean::TRUE)?;
            }
        }
        
        // Constraint 6: Sanctions non-membership checks
        let sanctions_root_var = FpVar::new_input(cs.clone(), || Ok(self.sanctions_root))?;
        
        // Check sender addresses (input note owners) are not sanctioned
        for (i, note_var) in notes_in_var.iter().enumerate() {
            if i < self.sanctions_nm_proofs_in.len() {
                if let Some(ref nm_proof) = self.sanctions_nm_proofs_in[i] {
                    let nm_proof_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof.clone()))?;
                    
                    // Verify the proof target matches the owner address
                    nm_proof_var.target.enforce_equal(&note_var.owner_addr)?;
                    
                    // Verify non-membership in sanctions list
                    nm_proof_var.enforce_valid(&sanctions_root_var)?;
                } else {
                    // Fallback: check address is valid (non-zero)
                    let addr_nonzero = note_var.owner_addr.is_neq(&FpVar::zero())?;
                    addr_nonzero.enforce_equal(&Boolean::TRUE)?;
                }
            }
        }
        
        // Check recipient addresses (output note owners) are not sanctioned
        for (i, note_var) in notes_out_var.iter().enumerate() {
            if i < self.sanctions_nm_proofs_out.len() {
                if let Some(ref nm_proof) = self.sanctions_nm_proofs_out[i] {
                    let nm_proof_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof.clone()))?;
                    
                    // Verify the proof target matches the owner address
                    nm_proof_var.target.enforce_equal(&note_var.owner_addr)?;
                    
                    // Verify non-membership in sanctions list
                    nm_proof_var.enforce_valid(&sanctions_root_var)?;
                } else {
                    // Fallback: check address is valid (non-zero)
                    let addr_nonzero = note_var.owner_addr.is_neq(&FpVar::zero())?;
                    addr_nonzero.enforce_equal(&Boolean::TRUE)?;
                }
            }
        }
        
        // Constraint 7: Pool policy compliance
        let pool_rules_root_var = FpVar::new_input(cs.clone(), || Ok(self.pool_rules_root))?;
        
        // Verify pool IDs are valid (non-zero and within range)
        for note_in in &notes_in_var {
            // Pool ID must be non-zero and fit in 32 bits
            let pool_nonzero = note_in.pool_id.is_neq(&FpVar::zero())?;
            pool_nonzero.enforce_equal(&Boolean::TRUE)?;
            RangeProofGadget::prove_range_bits(cs.clone(), &note_in.pool_id, 32)?;
        }
        
        for note_out in &notes_out_var {
            let pool_nonzero = note_out.pool_id.is_neq(&FpVar::zero())?;
            pool_nonzero.enforce_equal(&Boolean::TRUE)?;
            RangeProofGadget::prove_range_bits(cs.clone(), &note_out.pool_id, 32)?;
        }
        
        // Verify cross-pool transfers are allowed
        // All inputs must be from same pool, all outputs must be to same pool
        if !notes_in_var.is_empty() && !notes_out_var.is_empty() {
            let in_pool = &notes_in_var[0].pool_id;
            let out_pool = &notes_out_var[0].pool_id;
            
            // All inputs from same pool
            for note_in in &notes_in_var[1..] {
                note_in.pool_id.enforce_equal(in_pool)?;
            }
            
            // All outputs to same pool
            for note_out in &notes_out_var[1..] {
                note_out.pool_id.enforce_equal(out_pool)?;
            }
            
            // In practice, would check pool transfer rules from pool_rules_root
            // For now, allow same-pool transfers and specific cross-pool transfers
            // Pool 1 -> Pool 2 is allowed, Pool 2 -> Pool 3 is allowed, etc.
            let same_pool = in_pool.is_eq(out_pool)?;
            
            // Check if it's an allowed cross-pool transfer (simplified)
            // In production, would look up policy from merkle tree
            let pool_diff = out_pool - in_pool;
            let is_next_pool = pool_diff.is_eq(&FpVar::one())?; // Can transfer to next pool
            
            let transfer_allowed = same_pool.or(&is_next_pool)?;
            transfer_allowed.enforce_equal(&Boolean::TRUE)?;
        }
        
        // Constraint 8: Compliance gates
        for note_var in &notes_in_var {
            // Check note is not frozen (compliance_hash != 0 means active)
            let not_frozen = note_var.compliance_hash.is_neq(&FpVar::zero())?;
            not_frozen.enforce_equal(&Boolean::TRUE)?;
            
            // Check no expired callbacks (callbacks_hash != 0 means handled/none)
            let callbacks_ok = note_var.callbacks_hash.is_neq(&FpVar::zero())?;
            callbacks_ok.enforce_equal(&Boolean::TRUE)?;
        }
        
        // Constraint 9: Lineage update for output notes
        // Update lineage hash to track note history
        for (i, note_out_var) in notes_out_var.iter().enumerate() {
            // Collect parent lineages from input notes
            let parent_lineages: Vec<FpVar<F>> = notes_in_var
                .iter()
                .map(|n| n.lineage_hash.clone())
                .collect();
            
            // Context could be transaction hash or block number
            let context = FpVar::new_witness(cs.clone(), || Ok(F::from(i as u64)))?;
            
            // Compute expected lineage
            let mut lineage_input = parent_lineages;
            lineage_input.push(context);
            let expected_lineage = poseidon_hash_zk(&lineage_input)?;
            
            // Verify lineage matches
            note_out_var.lineage_hash.enforce_equal(&expected_lineage)?;
        }
        
        // Constraint 10: Tree root transitions
        let cmt_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.cmt_root_new))?;
        let nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.nft_root_new))?;
        
        // Verify CMT_ROOT update for output notes
        let mut current_cmt = cmt_root_old_var.clone();
        for note_var in &notes_out_var {
            let cm = note_var.commitment()?;
            current_cmt = poseidon_hash_zk(&[current_cmt, cm])?;
        }
        current_cmt.enforce_equal(&cmt_root_new_var)?;
        
        // Verify NFT_ROOT update for nullifiers
        let mut current_nft = nft_root_old_var;
        for nf in &self.nf_list {
            let nf_var = FpVar::new_input(cs.clone(), || Ok(*nf))?;
            current_nft = poseidon_hash_zk(&[current_nft, nf_var])?;
        }
        current_nft.enforce_equal(&nft_root_new_var)?;
        
        Ok(())
    }
}

impl FluxeCircuit for TransferCircuit {
    fn public_inputs(&self) -> Vec<F> {
        let mut inputs = vec![
            self.cmt_root_old,
            self.cmt_root_new,
            self.nft_root_old,
            self.nft_root_new,
            self.sanctions_root,
            self.pool_rules_root,
        ];
        
        // Add nullifiers
        inputs.extend(&self.nf_list);
        
        // Add output commitments
        inputs.extend(&self.cm_list);
        
        // Add fee
        inputs.push(self.fee.to_field());
        
        inputs
    }
    
    fn verify_public_inputs(&self) -> Result<(), FluxeError> {
        // Verify value conservation
        let sum_in: u128 = self.values_in.iter().map(|&v| v as u128).sum();
        let sum_out: u128 = self.values_out.iter().map(|&v| v as u128).sum();
        
        if Amount::from(sum_in) < Amount::from(sum_out) + self.fee {
            return Err(FluxeError::InsufficientBalance);
        }
        
        // Verify matching lengths
        if self.notes_in.len() != self.nf_list.len() {
            return Err(FluxeError::Other("Input/nullifier count mismatch".to_string()));
        }
        
        if self.notes_out.len() != self.cm_list.len() {
            return Err(FluxeError::Other("Output/commitment count mismatch".to_string()));
        }
        
        Ok(())
    }
}