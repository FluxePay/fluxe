use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use fluxe_core::{
    crypto::poseidon_hash,
    data_structures::{IngressReceipt, Note},
    merkle::{IncrementalTree, MerklePath, AppendWitness},
    types::*,
};

use crate::circuits::FluxeCircuit;
use crate::gadgets::*;

/// Mint circuit for deposits (boundary-in transactions)
#[derive(Clone)]
pub struct MintCircuit {
    // Private inputs
    /// Output notes being created
    pub notes_out: Vec<Note>,
    
    /// Value witnesses for Pedersen commitments
    pub values: Vec<u64>,
    
    /// Randomness for value commitments
    pub value_randomness: Vec<F>,
    
    /// Ingress receipt details
    pub ingress_receipt: IngressReceipt,
    
    /// Append witnesses for output notes (pre-insertion siblings)
    pub cmt_append_witnesses: Vec<AppendWitness>,
    
    /// Append witness for ingress receipt (pre-insertion siblings)
    pub ingress_append_witness: AppendWitness,
    
    // Public inputs
    /// Old commitment tree root
    pub cmt_root_old: MerkleRoot,
    
    /// New commitment tree root
    pub cmt_root_new: MerkleRoot,
    
    /// Old ingress root
    pub ingress_root_old: MerkleRoot,
    
    /// New ingress root
    pub ingress_root_new: MerkleRoot,
    
    /// Asset type being minted
    pub asset_type: AssetType,
    
    /// Total amount being minted
    pub amount: Amount,
    
    /// Commitment to output notes list
    pub cm_out_list_commit: F,
}

impl MintCircuit {
    pub fn new(
        notes_out: Vec<Note>,
        values: Vec<u64>,
        value_randomness: Vec<F>,
        ingress_receipt: IngressReceipt,
        cmt_tree: &mut IncrementalTree,
        ingress_tree: &mut IncrementalTree,
    ) -> Self {
        assert_eq!(notes_out.len(), values.len());
        assert_eq!(notes_out.len(), value_randomness.len());
        
        let asset_type = ingress_receipt.asset_type;
        let amount = ingress_receipt.amount;
        
        // Compute commitment to output list
        let mut cm_list = F::from(0);
        for note in &notes_out {
            cm_list = poseidon_hash(&[cm_list, note.commitment()]);
        }
        
        // Get old roots
        let cmt_root_old = cmt_tree.root();
        let ingress_root_old = ingress_tree.root();
        
        // Get pre-insertion witnesses
        let mut cmt_append_witnesses = Vec::new();
        let commitments: Vec<F> = notes_out.iter().map(|n| n.commitment()).collect();
        
        // For each note, get the append witness before appending
        for (i, cm) in commitments.iter().enumerate() {
            let leaf_index = cmt_tree.num_leaves();
            let pre_siblings = cmt_tree.get_siblings_for_index(leaf_index);
            cmt_append_witnesses.push(AppendWitness::new(
                *cm,
                leaf_index,
                pre_siblings,
                cmt_tree.height(),
            ));
            cmt_tree.append(*cm);
        }
        
        // Get ingress append witness
        let ingress_hash = ingress_receipt.hash();
        let ingress_leaf_index = ingress_tree.num_leaves();
        let ingress_pre_siblings = ingress_tree.get_siblings_for_index(ingress_leaf_index);
        let ingress_append_witness = AppendWitness::new(
            ingress_hash,
            ingress_leaf_index,
            ingress_pre_siblings,
            ingress_tree.height(),
        );
        ingress_tree.append(ingress_hash);
        
        // Get new roots after appending
        let cmt_root_new = cmt_tree.root();
        let ingress_root_new = ingress_tree.root();
        
        Self {
            notes_out,
            values,
            value_randomness,
            ingress_receipt,
            cmt_append_witnesses,
            ingress_append_witness,
            cmt_root_old,
            cmt_root_new,
            ingress_root_old,
            ingress_root_new,
            asset_type,
            amount,
            cm_out_list_commit: cm_list,
        }
    }
}

impl ConstraintSynthesizer<F> for MintCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Witness private inputs
        let notes_out_vars = self.notes_out
            .iter()
            .enumerate()
            .map(|(i, note)| {
                NoteVar::new_witness(
                    cs.clone(),
                    || Ok(note.clone()),
                    self.values[i],
                    &self.value_randomness[i],
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        // Witness ingress receipt
        let ingress_var = IngressReceiptVar::new_witness(cs.clone(), || Ok(self.ingress_receipt.clone()))?;
        
        // Create append proof gadgets
        use crate::gadgets::merkle_append::ImtAppendProofVar;
        
        // Input public values
        let cmt_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.cmt_root_old))?;
        let cmt_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.cmt_root_new))?;
        let ingress_root_old_var = FpVar::new_input(cs.clone(), || Ok(self.ingress_root_old))?;
        let ingress_root_new_var = FpVar::new_input(cs.clone(), || Ok(self.ingress_root_new))?;
        
        let asset_type_var = FpVar::new_input(cs.clone(), || Ok(F::from(self.asset_type as u64)))?;
        let amount_var = FpVar::new_input(cs.clone(), || Ok(self.amount.to_field()))?;
        let cm_out_list_var = FpVar::new_input(cs.clone(), || Ok(self.cm_out_list_commit))?;
        
        // Constraint 1: Verify ingress receipt is valid
        ingress_var.asset_type.enforce_equal(&asset_type_var)?;
        ingress_var.amount.enforce_equal(&amount_var)?;
        
        // Constraint 1b: Verify beneficiary_cm matches output commitments
        // The ingress receipt should specify which notes are being minted
        // Compute hash of all output commitments
        let mut beneficiary_cm_computed = FpVar::zero();
        for note_var in &notes_out_vars {
            let cm = note_var.commitment()?;
            beneficiary_cm_computed = poseidon_hash_zk(&[beneficiary_cm_computed.clone(), cm])?;
        }
        ingress_var.beneficiary_cm.enforce_equal(&beneficiary_cm_computed)?;
        
        // Constraint 2: Sum of output values equals amount
        let mut sum_var = FpVar::zero();
        for note_var in &notes_out_vars {
            sum_var += &note_var.value;
        }
        sum_var.enforce_equal(&amount_var)?;
        
        // Constraint 3: All outputs have correct asset type
        for note_var in &notes_out_vars {
            note_var.asset_type.enforce_equal(&asset_type_var)?;
        }
        
        // Constraint 4: Verify cm_out_list commitment
        let mut cm_list_var = FpVar::zero();
        for note_var in &notes_out_vars {
            let cm = note_var.commitment()?;
            cm_list_var = poseidon_hash_zk(&[cm_list_var.clone(), cm])?;
        }
        cm_list_var.enforce_equal(&cm_out_list_var)?;
        
        // Constraint 5: Verify range proofs for values
        for (_i, note_var) in notes_out_vars.iter().enumerate() {
            // Ensure value fits in 64 bits using secure bit decomposition
            use crate::gadgets::range_proof::RangeProofGadget;
            RangeProofGadget::prove_range_bits(cs.clone(), &note_var.value, 64)?;
            
            // TODO: Verify Pedersen commitment with EC-based opening
            // Would use pedersen_ec::verify_opening here
        }
        
        // Constraint 6: Verify CMT_ROOT updates using proper Merkle append proofs
        let mut current_cmt_root = cmt_root_old_var.clone();
        
        for (i, note_var) in notes_out_vars.iter().enumerate() {
            let witness = &self.cmt_append_witnesses[i];
            
            // Create append proof for this note
            let append_proof = ImtAppendProofVar {
                old_root: current_cmt_root.clone(),
                new_root: FpVar::new_witness(cs.clone(), || Ok(F::from(0)))?, // Will be computed
                leaf_index: FpVar::new_witness(cs.clone(), || Ok(F::from(witness.leaf_index as u64)))?,
                appended_leaf: note_var.commitment()?,
                pre_siblings: witness.pre_siblings
                    .iter()
                    .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
                    .collect::<Result<Vec<_>, _>>()?,
                height: witness.height,
            };
            
            // Verify the old root matches
            let computed_old = append_proof.compute_root_with_empty()?;
            computed_old.enforce_equal(&current_cmt_root)?;
            
            // Compute and set new root
            let computed_new_root = append_proof.compute_root_with_leaf()?;
            current_cmt_root = computed_new_root;
        }
        
        // Verify final CMT root matches
        current_cmt_root.enforce_equal(&cmt_root_new_var)?;
        
        // Constraint 7: Verify INGRESS_ROOT update using proper append proof
        let ingress_hash = ingress_var.hash()?;
        let ingress_append_proof = ImtAppendProofVar {
            old_root: ingress_root_old_var.clone(),
            new_root: ingress_root_new_var.clone(),
            leaf_index: FpVar::new_witness(cs.clone(), || Ok(F::from(self.ingress_append_witness.leaf_index as u64)))?,
            appended_leaf: ingress_hash,
            pre_siblings: self.ingress_append_witness.pre_siblings
                .iter()
                .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
                .collect::<Result<Vec<_>, _>>()?,
            height: self.ingress_append_witness.height,
        };
        
        // Verify the append is valid
        ingress_append_proof.enforce()?;
        
        // Constraint 8: Verify all notes have valid compliance fields
        for note_var in &notes_out_vars {
            // Pool ID must be valid (non-zero for active pools)
            let pool_id_nonzero = note_var.pool_id.is_neq(&FpVar::zero())?;
            pool_id_nonzero.enforce_equal(&Boolean::TRUE)?;
        }
        
        Ok(())
    }
}

impl FluxeCircuit for MintCircuit {
    fn public_inputs(&self) -> Vec<F> {
        vec![
            self.cmt_root_old,
            self.cmt_root_new,
            self.ingress_root_old,
            self.ingress_root_new,
            F::from(self.asset_type as u64),
            self.amount.to_field(),
            self.cm_out_list_commit,
        ]
    }
    
    fn verify_public_inputs(&self) -> Result<(), FluxeError> {
        // Verify sum of values equals amount
        let sum: u128 = self.values.iter().map(|&v| v as u128).sum();
        if Amount::from(sum) != self.amount {
            return Err(FluxeError::Other("Value sum mismatch".to_string()));
        }
        
        // Verify all notes have correct asset type
        for note in &self.notes_out {
            if note.asset_type != self.asset_type {
                return Err(FluxeError::Other("Asset type mismatch".to_string()));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use fluxe_core::crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness};
    use rand::thread_rng;

    #[test]
    fn test_mint_circuit_with_merkle_trees() {
        use fluxe_core::merkle::IncrementalTree;
        use fluxe_core::crypto::poseidon_hash;
        
        // Test with a single output note
        let mut rng = thread_rng();
        let params = PedersenParams::setup_value_commitment();
        
        let value = 1000u64;
        let randomness = F::rand(&mut rng);
        
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        let owner = F::rand(&mut rng);
        let note = Note::new(1, v_comm, owner, [1u8; 32], 1);
        
        // Create ingress receipt
        // The beneficiary_cm should be a hash chain of all output commitments
        let cm = note.commitment();
        let beneficiary_cm = poseidon_hash(&[F::from(0u64), cm]);  // Hash chain starting from 0
        let ingress = IngressReceipt::new(1, Amount::from(value as u128), beneficiary_cm, 1);
        
        // Create proper Merkle trees
        let mut cmt_tree = IncrementalTree::new(16); // 16 levels
        let mut ingress_tree = IncrementalTree::new(16);
        
        // Use the constructor which properly handles witness generation and tree updates
        let circuit = MintCircuit::new(
            vec![note],
            vec![value],
            vec![randomness],
            ingress,
            &mut cmt_tree,
            &mut ingress_tree,
        );
        
        // Test constraint generation
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Generate constraints and check satisfaction
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        
        // Verify the constraint system is satisfied
        if !cs.is_satisfied().unwrap() {
            println!("Constraint system not satisfied!");
            println!("Num constraints: {}", cs.num_constraints());
            let unsatisfied = cs.which_is_unsatisfied();
            if let Ok(Some(unsatisfied)) = unsatisfied {
                println!("First unsatisfied constraint: {:?}", unsatisfied);
            }
        }
        assert!(cs.is_satisfied().unwrap());
    }
}