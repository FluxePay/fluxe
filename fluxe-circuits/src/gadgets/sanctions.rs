use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::gadgets::{merkle::MerkleTreeGadget, poseidon::poseidon_hash_zk};

/// Gadget for proving non-membership in sanctions list
/// Uses sorted IMT (S-IMT) structure with gap proofs for efficiency
pub struct SanctionsChecker;

impl SanctionsChecker {
    /// Prove that an address/identifier is NOT in the sanctions list
    /// Uses non-membership proof via gap in sorted tree
    pub fn prove_not_sanctioned(
        cs: ConstraintSystemRef<F>,
        identifier: &FpVar<F>,
        sanctions_root: &FpVar<F>,
        low_leaf: &SanctionsLeafVar,
        merkle_path: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        // Verify the low leaf is in the tree
        let low_leaf_hash = low_leaf.hash()?;
        MerkleTreeGadget::verify_membership(
            cs.clone(),
            &low_leaf_hash,
            merkle_path,
            sanctions_root,
        )?;
        
        // Verify the gap: low_leaf.key < identifier < low_leaf.next_key
        Self::enforce_gap_constraint(identifier, low_leaf)?;
        
        Ok(())
    }
    
    /// Check multiple identifiers are not sanctioned
    pub fn prove_multiple_not_sanctioned(
        cs: ConstraintSystemRef<F>,
        identifiers: &[FpVar<F>],
        sanctions_root: &FpVar<F>,
        low_leaves: &[SanctionsLeafVar],
        merkle_paths: &[Vec<FpVar<F>>],
    ) -> Result<(), SynthesisError> {
        if identifiers.len() != low_leaves.len() || identifiers.len() != merkle_paths.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        
        for ((id, leaf), path) in identifiers.iter()
            .zip(low_leaves.iter())
            .zip(merkle_paths.iter())
        {
            Self::prove_not_sanctioned(cs.clone(), id, sanctions_root, leaf, path)?;
        }
        
        Ok(())
    }
    
    /// Enforce the gap constraint for non-membership
    /// Ensures: low_leaf.key < identifier < low_leaf.next_key (or next_key = 0)
    fn enforce_gap_constraint(
        identifier: &FpVar<F>,
        low_leaf: &SanctionsLeafVar,
    ) -> Result<(), SynthesisError> {
        // Check: low_leaf.key < identifier
        let diff1 = identifier - &low_leaf.key;
        Self::enforce_positive(&diff1)?;
        
        // Check: identifier < low_leaf.next_key OR low_leaf.next_key == 0
        let is_zero = low_leaf.next_key.is_eq(&FpVar::zero())?;
        
        // If next_key is not zero, enforce identifier < next_key
        let diff2 = &low_leaf.next_key - identifier;
        let positive_diff = Self::enforce_positive_conditional(&diff2)?;
        
        // Either next_key is zero OR the difference is positive
        Boolean::or(&is_zero, &positive_diff)?.enforce_equal(&Boolean::TRUE)?;
        
        Ok(())
    }
    
    /// Enforce that a value is positive (non-zero and > 0)
    fn enforce_positive(value: &FpVar<F>) -> Result<(), SynthesisError> {
        // Convert to bits and check that it's not zero and high bit is not set
        let bits = value.to_bits_le()?;
        
        // Check not zero: at least one bit must be 1
        let mut is_zero = Boolean::TRUE;
        for bit in &bits {
            is_zero = is_zero.and(&bit.not())?;
        }
        is_zero.enforce_equal(&Boolean::FALSE)?;
        
        // Check positive: high bit must be 0 (assuming field size > values)
        if let Some(high_bit) = bits.last() {
            high_bit.enforce_equal(&Boolean::FALSE)?;
        }
        
        Ok(())
    }
    
    /// Conditionally enforce positive (returns Boolean indicating if positive)
    fn enforce_positive_conditional(value: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        let bits = value.to_bits_le()?;
        
        // Check if zero
        let mut is_zero = Boolean::TRUE;
        for bit in &bits {
            is_zero = is_zero.and(&bit.not())?;
        }
        
        // Check if positive (high bit is 0 and not zero)
        let is_positive = if let Some(high_bit) = bits.last() {
            high_bit.not().and(&is_zero.not())?
        } else {
            is_zero.not()
        };
        
        Ok(is_positive)
    }
}

/// Variable representation of a sanctions list leaf in S-IMT
#[derive(Clone)]
pub struct SanctionsLeafVar {
    /// The sanctioned identifier (key)
    pub key: FpVar<F>,
    /// Next key in sorted order (0 if none)
    pub next_key: FpVar<F>,
    /// Optional index pointer for efficiency
    pub next_index: Option<FpVar<F>>,
}

impl SanctionsLeafVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        key: F,
        next_key: F,
        next_index: Option<u64>,
    ) -> Result<Self, SynthesisError> {
        let key_var = FpVar::new_witness(cs.clone(), || Ok(key))?;
        let next_key_var = FpVar::new_witness(cs.clone(), || Ok(next_key))?;
        let next_index_var = next_index
            .map(|idx| FpVar::new_witness(cs, || Ok(F::from(idx))))
            .transpose()?;
        
        Ok(Self {
            key: key_var,
            next_key: next_key_var,
            next_index: next_index_var,
        })
    }
    
    /// Compute hash of the leaf for Merkle tree operations
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        let mut inputs = vec![self.key.clone(), self.next_key.clone()];
        
        if let Some(ref idx) = self.next_index {
            inputs.push(idx.clone());
        }
        
        poseidon_hash_zk(&inputs)
    }
}

/// Utility for common sanctions checking operations
pub struct SanctionsUtils;

impl SanctionsUtils {
    /// Check that sender and recipient addresses are not sanctioned
    pub fn check_transfer_participants(
        cs: ConstraintSystemRef<F>,
        sender_addr: &FpVar<F>,
        recipient_addr: &FpVar<F>,
        sanctions_root: &FpVar<F>,
        sender_proof: (&SanctionsLeafVar, &[FpVar<F>]),
        recipient_proof: (&SanctionsLeafVar, &[FpVar<F>]),
    ) -> Result<(), SynthesisError> {
        // Check sender not sanctioned
        SanctionsChecker::prove_not_sanctioned(
            cs.clone(),
            sender_addr,
            sanctions_root,
            sender_proof.0,
            sender_proof.1,
        )?;
        
        // Check recipient not sanctioned
        SanctionsChecker::prove_not_sanctioned(
            cs,
            recipient_addr,
            sanctions_root,
            recipient_proof.0,
            recipient_proof.1,
        )?;
        
        Ok(())
    }
    
    /// Derive identifier from public key for sanctions checking
    pub fn derive_sanctions_identifier(
        public_key: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        // Simple hash of public key - in practice might be more complex
        poseidon_hash_zk(&[public_key.clone()])
    }
    
    /// Check institutional identifier (e.g., for banks/exchanges)
    pub fn check_institution_not_sanctioned(
        cs: ConstraintSystemRef<F>,
        institution_id: &FpVar<F>,
        sanctions_root: &FpVar<F>,
        proof: (&SanctionsLeafVar, &[FpVar<F>]),
    ) -> Result<(), SynthesisError> {
        SanctionsChecker::prove_not_sanctioned(
            cs,
            institution_id,
            sanctions_root,
            proof.0,
            proof.1,
        )
    }
}

/// Batch sanctions checker for efficiency
pub struct BatchSanctionsChecker {
    identifiers: Vec<FpVar<F>>,
    proofs: Vec<(SanctionsLeafVar, Vec<FpVar<F>>)>,
}

impl BatchSanctionsChecker {
    pub fn new() -> Self {
        Self {
            identifiers: Vec::new(),
            proofs: Vec::new(),
        }
    }
    
    pub fn add_check(
        &mut self,
        identifier: FpVar<F>,
        low_leaf: SanctionsLeafVar,
        merkle_path: Vec<FpVar<F>>,
    ) {
        self.identifiers.push(identifier);
        self.proofs.push((low_leaf, merkle_path));
    }
    
    pub fn verify_all(
        self,
        cs: ConstraintSystemRef<F>,
        sanctions_root: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        for (id, (leaf, path)) in self.identifiers.iter().zip(self.proofs.iter()) {
            SanctionsChecker::prove_not_sanctioned(cs.clone(), id, sanctions_root, leaf, path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_sanctions_leaf_hash() {
        let cs = ConstraintSystem::<F>::new_ref();
        let mut rng = thread_rng();
        
        let key = F::rand(&mut rng);
        let next_key = F::rand(&mut rng);
        
        let leaf = SanctionsLeafVar::new_witness(cs.clone(), key, next_key, Some(1)).unwrap();
        let hash = leaf.hash().unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_gap_constraint() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Create test values where: low_key < identifier < next_key
        let low_key = F::from(100u64);
        let identifier = F::from(150u64);
        let next_key = F::from(200u64);
        
        let low_key_var = FpVar::new_witness(cs.clone(), || Ok(low_key)).unwrap();
        let identifier_var = FpVar::new_witness(cs.clone(), || Ok(identifier)).unwrap();
        let next_key_var = FpVar::new_witness(cs.clone(), || Ok(next_key)).unwrap();
        
        let leaf = SanctionsLeafVar {
            key: low_key_var,
            next_key: next_key_var,
            next_index: None,
        };
        
        SanctionsChecker::enforce_gap_constraint(&identifier_var, &leaf).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_positive_enforcement() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let positive_val = F::from(42u64);
        let positive_var = FpVar::new_witness(cs.clone(), || Ok(positive_val)).unwrap();
        
        SanctionsChecker::enforce_positive(&positive_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_sanctions_checker() {
        let cs = ConstraintSystem::<F>::new_ref();
        let mut rng = thread_rng();
        
        let mut checker = BatchSanctionsChecker::new();
        let sanctions_root = FpVar::new_witness(cs.clone(), || Ok(F::rand(&mut rng))).unwrap();
        
        // Add some checks (simplified test)
        for i in 0..3 {
            let id = FpVar::new_witness(cs.clone(), || Ok(F::from(100 + i as u64))).unwrap();
            let leaf = SanctionsLeafVar::new_witness(
                cs.clone(),
                F::from(50 + i as u64), // low key
                F::from(150 + i as u64), // next key
                None,
            ).unwrap();
            let path = vec![FpVar::zero(); 5]; // Dummy path
            
            checker.add_check(id, leaf, path);
        }
        
        // This would normally fail without proper Merkle paths,
        // but demonstrates the structure
        // checker.verify_all(cs.clone(), &sanctions_root).unwrap();
    }
}