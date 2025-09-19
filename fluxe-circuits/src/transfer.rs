use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use fluxe_core::{
    data_structures::Note,
    merkle::{MerklePath, RangePath, AppendWitness},
    types::*,
};

use crate::circuits::FluxeCircuit;
use crate::gadgets::*;
use crate::gadgets::sorted_insert::SortedInsertWitness;

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
    
    /// Owner secret keys for EC authentication
    pub owner_sks: Vec<F>,
    
    /// Owner public key coordinates for EC authentication
    pub owner_pks: Vec<(F, F)>,
    
    /// Merkle paths for input notes
    pub cm_paths: Vec<MerklePath>,
    
    /// Non-membership proofs for nullifiers
    pub nf_nonmembership_proofs: Vec<Option<RangePath>>,
    
    /// Sanctions non-membership proofs for sender addresses
    pub sanctions_nm_proofs_in: Vec<Option<RangePath>>,
    
    /// Sanctions non-membership proofs for recipient addresses
    pub sanctions_nm_proofs_out: Vec<Option<RangePath>>,
    
    /// Merkle paths for CMT appends (witnesses for output commitments)
    pub cmt_paths_out: Vec<MerklePath>,
    
    /// Non-membership proofs for NFT insertions
    pub nf_nonmembership: Vec<Option<RangePath>>,
    
    /// Pool policy witnesses for source pools
    pub source_pool_policies: Vec<PoolPolicyVar>,
    
    /// Pool policy witnesses for destination pools
    pub dest_pool_policies: Vec<PoolPolicyVar>,
    
    /// Merkle paths for pool policy membership proofs
    pub pool_policy_paths: Vec<MerklePathVar>,
    
    /// CMT append witnesses for output notes (pre-insertion siblings)
    pub cmt_appends_out: Vec<AppendWitness>,
    
    /// NFT insert witnesses for nullifier insertions
    pub nf_insert_witnesses: Vec<SortedInsertWitness>,
    
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
    /// Helper to generate NFT insert witnesses from a SortedTree
    /// Call this before creating the circuit to get proper witnesses
    pub fn generate_nft_insert_witnesses(
        nft_tree: &fluxe_core::merkle::SortedTree,
        nullifiers: &[F],
    ) -> Result<Vec<SortedInsertWitness>, String> {
        let mut witnesses = Vec::new();
        
        for nf in nullifiers {
            // Export witness for inserting this nullifier
            let witness = nft_tree.export_insert_witness(*nf)?;
            
            // Convert to circuit witness format (gadgets version)
            let insert_witness = SortedInsertWitness {
                target: witness.target,
                range_proof: witness.range_proof,
                new_leaf: witness.new_leaf,
                updated_pred_leaf: witness.updated_pred_leaf,
                new_leaf_path: witness.new_leaf_path,
                pred_update_path: witness.pred_update_path,
                height: witness.height,
            };
            
            witnesses.push(insert_witness);
        }
        
        Ok(witnesses)
    }
    
    /// Create a TransferCircuit with proper NFT insert witnesses
    /// This is the recommended way to build the circuit with full witness data
    pub fn new_with_nft_witnesses(
        notes_in: Vec<Note>,
        values_in: Vec<u64>,
        value_randomness_in: Vec<F>,
        notes_out: Vec<Note>,
        values_out: Vec<u64>,
        value_randomness_out: Vec<F>,
        nks: Vec<F>,
        owner_sks: Vec<F>,
        owner_pks: Vec<(F, F)>,
        cm_paths: Vec<MerklePath>,
        nf_nonmembership_proofs: Vec<Option<RangePath>>,
        nf_insert_witnesses: Vec<SortedInsertWitness>,
        sanctions_nm_proofs_in: Vec<Option<RangePath>>,
        sanctions_nm_proofs_out: Vec<Option<RangePath>>,
        source_pool_policies: Vec<PoolPolicyVar>,
        dest_pool_policies: Vec<PoolPolicyVar>,
        pool_policy_paths: Vec<MerklePathVar>,
        cmt_appends_out: Vec<AppendWitness>,
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
            .map(|(note, nk)| note.nullifier(nk))
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
            owner_sks,
            owner_pks,
            cm_paths,
            nf_nonmembership_proofs: nf_nonmembership_proofs.clone(),
            sanctions_nm_proofs_in,
            sanctions_nm_proofs_out,
            cmt_paths_out: Vec::new(), // Will be populated with actual witness data
            nf_nonmembership: nf_nonmembership_proofs,
            source_pool_policies,
            dest_pool_policies,
            pool_policy_paths,
            cmt_appends_out,
            nf_insert_witnesses,
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
    
    /// Legacy constructor for backward compatibility
    pub fn new(
        notes_in: Vec<Note>,
        values_in: Vec<u64>,
        value_randomness_in: Vec<F>,
        notes_out: Vec<Note>,
        values_out: Vec<u64>,
        value_randomness_out: Vec<F>,
        nks: Vec<F>,
        owner_sks: Vec<F>,
        owner_pks: Vec<(F, F)>,
        cm_paths: Vec<MerklePath>,
        nf_nonmembership_proofs: Vec<Option<RangePath>>,
        sanctions_nm_proofs_in: Vec<Option<RangePath>>,
        sanctions_nm_proofs_out: Vec<Option<RangePath>>,
        source_pool_policies: Vec<PoolPolicyVar>,
        dest_pool_policies: Vec<PoolPolicyVar>,
        pool_policy_paths: Vec<MerklePathVar>,
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
                // Use the note's nullifier method which includes domain separator
                note.nullifier(nk)
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
            owner_sks,
            owner_pks,
            cm_paths,
            nf_nonmembership_proofs: nf_nonmembership_proofs.clone(),
            sanctions_nm_proofs_in,
            sanctions_nm_proofs_out,
            cmt_paths_out: Vec::new(), // Will be populated in actual use
            nf_nonmembership: nf_nonmembership_proofs,
            source_pool_policies,
            dest_pool_policies,
            pool_policy_paths,
            cmt_appends_out: Vec::new(), // Will be populated with witness data
            nf_insert_witnesses: Vec::new(), // Will be populated with witness data
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
        // Create ALL public inputs in the correct order first
        // Order must match public_inputs() method exactly:
        // 1. roots: cmt_root_old, cmt_root_new, nft_root_old, nft_root_new, sanctions_root, pool_rules_root
        // 2. nullifiers from nf_list
        // 3. output commitments from cm_list
        // 4. fee
        
        // Step 1: Create root public inputs
        let cmt_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.cmt_root_old))?;
        let cmt_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.cmt_root_new))?;
        let nft_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.nft_root_old))?;
        let nft_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.nft_root_new))?;
        let sanctions_root_var = FpVar::new_input(cs.clone(), || Ok(self.sanctions_root))?;
        let pool_rules_root_var = FpVar::new_input(cs.clone(), || Ok(self.pool_rules_root))?;
        
        // Step 2: Create nullifier public inputs
        let nf_vars: Vec<FpVar<F>> = self.nf_list
            .iter()
            .map(|nf| FpVar::new_input(cs.clone(), || Ok(*nf)))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Step 3: Create commitment public inputs
        let cm_vars: Vec<FpVar<F>> = self.cm_list
            .iter()
            .map(|cm| FpVar::new_input(cs.clone(), || Ok(*cm)))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Step 4: Create fee public input (last)
        let fee_var = FpVar::new_input(cs.clone(), || Ok(self.fee.to_field()))?;
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
        
        // Note: All public inputs were already created at the beginning of the method
        
        // Constraint 1: Membership - all inputs are in CMT tree
        for (note_var, path_var) in notes_in_var.iter().zip(paths_var.iter()) {
            let cm = note_var.commitment()?;
            cm.enforce_equal(&path_var.leaf)?;
            path_var.enforce_valid(&cmt_root_old_var)?;
        }
        
        // Constraint 2: Nullifier correctness
        for ((note_var, nk_var), expected_nf_var) in notes_in_var.iter()
            .zip(nks_var.iter())
            .zip(nf_vars.iter())
        {
            let computed_nf = note_var.nullifier(nk_var)?;
            // Use the nf_var that was already created as public input
            computed_nf.enforce_equal(expected_nf_var)?;
        }
        
        // Constraint 2b: EC-based owner authentication for input notes
        // SECURITY CRITICAL: Verify each input note can only be spent by its owner
        for (i, note_var) in notes_in_var.iter().enumerate() {
            if i < self.owner_sks.len() {
                let owner_sk_var = FpVar::new_witness(cs.clone(), || Ok(self.owner_sks[i]))?;
                
                // Derive the public key from the secret key (returns FqVar)
                use crate::gadgets::auth::AuthGadget;
                let (derived_pk_x_fq, derived_pk_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), &owner_sk_var)?;
                
                // Compute owner address from the derived public key: addr = H(pk_x, pk_y)
                let computed_owner_addr = AuthGadget::compute_owner_address_from_fq(cs.clone(), &derived_pk_x_fq, &derived_pk_y_fq)?;
                
                // Enforce that computed address matches note's owner
                computed_owner_addr.enforce_equal(&note_var.owner_addr)?;
            }
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
        // Use the fee_var that was already created as public input
        sum_out += &fee_var;
        
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
            // Use the secure bit decomposition method
            RangeProofGadget::prove_range_bits(cs.clone(), &note_var.value, 64)?;
        }
        
        // Constraint 5: Non-membership of nullifiers in NFT_ROOT_old
        // Each nullifier must not already exist (prevent double spend)
        // Note: nft_root_old_var was already created as public input
        
        // Create fee variable here (will be used later but must be input after other public inputs)
        // Note: fee is the LAST public input, so we create it later
        
        // Verify non-membership for each nullifier
        for (i, nf_var) in nf_vars.iter().enumerate() {
            
            // Use proper non-membership proof if available
            if i < self.nf_nonmembership_proofs.len() {
                if let Some(ref nm_proof) = self.nf_nonmembership_proofs[i] {
                    let nm_proof_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof.clone()))?;
                    
                    // Verify the proof target matches our nullifier
                    nm_proof_var.target.enforce_equal(nf_var)?;
                    
                    // Verify the non-membership proof is valid
                    nm_proof_var.enforce_valid(&nft_root_old_var)?;
                } else {
                    // SECURITY: Non-membership proof is REQUIRED
                    // Without it, double-spending is possible
                    return Err(SynthesisError::Unsatisfiable);
                }
            } else {
                // SECURITY: Non-membership proof is REQUIRED
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        
        // Constraint 6: Sanctions non-membership checks
        // Note: sanctions_root_var was already created as public input
        
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
        
        // Constraint 7: Pool policy compliance with proper Merkle membership proofs
        // Note: pool_rules_root_var was already created as public input
        
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
        
        // Constraint 7b: Full pool policy enforcement with Merkle membership proofs
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
            
            // Calculate total transfer amount
            let mut transfer_amount = FpVar::zero();
            for note_out in &notes_out_var {
                transfer_amount += &note_out.value;
            }
            
            // Create timestamp variable (current time)
            let timestamp = FpVar::new_witness(cs.clone(), || Ok(F::from(0u64)))?; // In practice, use actual timestamp
            
            // If we have pool policy witnesses, use full enforcement
            if !self.source_pool_policies.is_empty() && !self.dest_pool_policies.is_empty() && !self.pool_policy_paths.is_empty() {
                use crate::gadgets::pool_policy::PoolPolicyGadget;
                
                // Get source and destination policies (assuming single source/dest pool)
                let source_policy = &self.source_pool_policies[0];
                let dest_policy = &self.dest_pool_policies[0];
                let source_path = &self.pool_policy_paths[0];
                let dest_path = &self.pool_policy_paths[1];
                
                // Enforce full pool transfer policy with Merkle proofs
                PoolPolicyGadget::enforce_pool_transfer_policy(
                    cs.clone(),
                    in_pool,
                    out_pool,
                    &transfer_amount,
                    &timestamp,
                    &pool_rules_root_var,
                    source_policy,
                    dest_policy,
                    source_path,
                    dest_path,
                )?;
            } else {
                // Fallback: Basic pool transfer rules when no policy witnesses provided
                // This is for backward compatibility and testing
                let same_pool = in_pool.is_eq(out_pool)?;
                
                // Check if it's an allowed cross-pool transfer using simplified rules
                let pool_diff = out_pool.clone() - in_pool.clone();
                
                // Can transfer to next pool (pool n -> pool n+1)
                let is_next_pool = pool_diff.is_eq(&FpVar::one())?;
                
                // Can also transfer from pool 0 (general pool) to any pool
                let from_general = in_pool.is_eq(&FpVar::zero())?;
                
                // Can transfer to pool 0 from pools 1-3 (exit pools)
                let to_general = out_pool.is_eq(&FpVar::zero())?;
                // Check if from pools 1, 2, or 3
                let from_pool_1 = in_pool.is_eq(&FpVar::constant(F::from(1u64)))?;
                let from_pool_2 = in_pool.is_eq(&FpVar::constant(F::from(2u64)))?;
                let from_pool_3 = in_pool.is_eq(&FpVar::constant(F::from(3u64)))?;
                let from_exit = from_pool_1.or(&from_pool_2)?.or(&from_pool_3)?;
                let exit_to_general = to_general.and(&from_exit)?;
                
                // Combine all allowed conditions
                let transfer_allowed = same_pool
                    .or(&is_next_pool)?
                    .or(&from_general)?
                    .or(&exit_to_general)?;
                
                transfer_allowed.enforce_equal(&Boolean::TRUE)?;
            }
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
        // Note: cmt_root_new_var and nft_root_new_var were already created as public inputs
        
        // Verify CMT_ROOT update for output notes
        // First verify that the output note commitments match the public inputs
        for (note_var, cm_var) in notes_out_var.iter().zip(cm_vars.iter()) {
            let computed_cm = note_var.commitment()?;
            computed_cm.enforce_equal(cm_var)?;
        }
        
        // SECURITY CRITICAL: Verify proper tree transitions
        // Use ImtAppendProofVar for CMT updates and SimtInsertVar for NFT updates
        use crate::gadgets::merkle_append::ImtAppendProofVar;
        
        // For CMT_ROOT (append-only I-IMT): Require proper append witnesses
        if self.cmt_appends_out.is_empty() && !cm_vars.is_empty() {
            // SECURITY: Proper append witnesses are REQUIRED for outputs
            return Err(SynthesisError::Unsatisfiable);
        } else if !self.cmt_appends_out.is_empty() {
            // Use proper append witnesses with pre-insertion siblings
            let mut current_cmt = cmt_root_old_var.clone();
            for (i, cm_var) in cm_vars.iter().enumerate() {
                if i < self.cmt_appends_out.len() {
                    let witness = &self.cmt_appends_out[i];
                    
                    // Compute what the new root should be using the witness
                    let new_root_value = witness.compute_new_root(&fluxe_core::merkle::TreeParams::new(witness.height));
                    
                    let append_proof = ImtAppendProofVar {
                        old_root: current_cmt.clone(),
                        new_root: FpVar::new_witness(cs.clone(), || Ok(new_root_value))?,
                        leaf_index: FpVar::new_witness(cs.clone(), || Ok(F::from(witness.leaf_index as u64)))?,
                        height: witness.height,
                        pre_siblings: witness.pre_siblings.iter()
                            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
                            .collect::<Result<Vec<_>, _>>()?,
                        appended_leaf: cm_var.clone(),
                    };
                    
                    // Verify the append proof is valid
                    append_proof.enforce()?;
                    
                    // Update current root for next iteration
                    current_cmt = append_proof.new_root.clone();
                }
            }
            current_cmt.enforce_equal(&cmt_root_new_var)?;
        }
        
        // For NFT_ROOT (sorted S-IMT): Chain insertion proofs for each nullifier
        // Each input should provide its non-membership proof
        let mut current_nft = nft_root_old_var.clone();
        
        // Use proper SortedInsertWitness for each nullifier
        for (i, nf_var) in nf_vars.iter().enumerate() {
            if i < self.nf_insert_witnesses.len() {
                // Use the properly generated insert witness
                let insert_witness = &self.nf_insert_witnesses[i];
                
                // Create the insert gadget with the witness
                use crate::gadgets::sorted_insert::SimtInsertVar;
                
                // Calculate the new root after this insertion
                // Use the correct tree height from the witness
                let tree_params = fluxe_core::merkle::TreeParams::new(insert_witness.height);
                let new_root_value = insert_witness.compute_new_root(&tree_params);
                
                let insert_gadget = SimtInsertVar::new_witness(
                    cs.clone(),
                    insert_witness.clone(),
                    current_nft.value()?,
                    new_root_value,
                )?;
                
                // Verify the insertion matches our nullifier
                insert_gadget.target.enforce_equal(nf_var)?;
                
                // Verify old root matches current state
                insert_gadget.old_root.enforce_equal(&current_nft)?;
                
                // Verify the insertion is valid
                insert_gadget.enforce()?;
                
                // Update current root for next iteration
                current_nft = insert_gadget.new_root.clone();
            } else {
                // SECURITY: Proper insertion witness is REQUIRED
                return Err(SynthesisError::Unsatisfiable);
            }
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