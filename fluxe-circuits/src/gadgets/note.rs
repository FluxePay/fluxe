use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use fluxe_core::{
    crypto::{domain_sep_to_field, DOM_NOTE, DOM_NF},
    data_structures::Note,
};

use crate::gadgets::{pedersen::PedersenCommitmentVar, poseidon::poseidon_hash_zk};

/// Note variable for circuits
#[derive(Clone)]
pub struct NoteVar {
    pub asset_type: FpVar<F>,
    pub v_comm: PedersenCommitmentVar,
    pub value: FpVar<F>, // Actual value (private)
    pub owner_addr: FpVar<F>,
    pub psi: Vec<UInt8<F>>,
    pub chain_hint: FpVar<F>,
    pub compliance_hash: FpVar<F>,
    pub lineage_hash: FpVar<F>,
    pub pool_id: FpVar<F>,
    pub callbacks_hash: FpVar<F>,
    pub memo_hash: FpVar<F>,
}

impl NoteVar {
    /// Create new note variable as witness
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        note: impl FnOnce() -> Result<Note, SynthesisError>,
        value: u64,
        value_randomness: &F,
    ) -> Result<Self, SynthesisError> {
        let note = note()?;
        
        let asset_type = FpVar::new_witness(cs.clone(), || Ok(F::from(note.asset_type as u64)))?;
        let value_var = FpVar::new_witness(cs.clone(), || Ok(F::from(value)))?;
        
        // TODO: Use value_randomness to verify the commitment
        // Currently not implemented due to missing EC operations in circuit
        let _ = value_randomness; // Suppress unused warning
        
        // Use the commitment from the note directly
        use ark_ff::{BigInteger, PrimeField};
        let v_comm_bytes = note.v_comm.commitment.x.into_bigint().to_bytes_le();
        let v_comm_x_fr = fluxe_core::utils::bytes_to_field(&v_comm_bytes);
        let commitment_x = FpVar::new_witness(cs.clone(), || Ok(v_comm_x_fr))?;
        let v_comm = PedersenCommitmentVar { commitment_x };
        
        let owner_addr = FpVar::new_witness(cs.clone(), || Ok(note.owner_addr))?;
        
        let psi = note.psi
            .iter()
            .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)))
            .collect::<Result<Vec<_>, _>>()?;
        
        let chain_hint = FpVar::new_witness(cs.clone(), || Ok(F::from(note.chain_hint as u64)))?;
        let compliance_hash = FpVar::new_witness(cs.clone(), || Ok(note.compliance_hash))?;
        let lineage_hash = FpVar::new_witness(cs.clone(), || Ok(note.lineage_hash))?;
        let pool_id = FpVar::new_witness(cs.clone(), || Ok(F::from(note.pool_id as u64)))?;
        let callbacks_hash = FpVar::new_witness(cs.clone(), || Ok(note.callbacks_hash))?;
        let memo_hash = FpVar::new_witness(cs.clone(), || Ok(note.memo_hash))?;
        
        Ok(Self {
            asset_type,
            v_comm,
            value: value_var,
            owner_addr,
            psi,
            chain_hint,
            compliance_hash,
            lineage_hash,
            pool_id,
            callbacks_hash,
            memo_hash,
        })
    }
    
    /// Compute note commitment
    pub fn commitment(&self) -> Result<FpVar<F>, SynthesisError> {
        let dom_note = FpVar::constant(domain_sep_to_field(DOM_NOTE));
        
        // Convert psi bytes to field element using the same algorithm as utils::bytes_to_field
        // Truncate to 31 bytes to ensure we're below the field modulus
        let truncated_psi = if self.psi.len() > 31 {
            &self.psi[..31]
        } else {
            &self.psi[..]
        };
        
        let mut psi_field = FpVar::zero();
        let mut multiplier = FpVar::one();
        let two_five_six = FpVar::constant(F::from(256u64));
        
        for byte in truncated_psi {
            let byte_bits = byte.to_bits_le()?;
            let byte_value = Boolean::le_bits_to_fp_var(&byte_bits)?;
            psi_field += &byte_value * &multiplier;
            multiplier *= &two_five_six;
        }
        
        // Pad with zeros if less than 31 bytes
        for _ in truncated_psi.len()..31 {
            // multiplier continues but we add 0, so just update multiplier
            multiplier *= &two_five_six;
        }
        
        
        let input = vec![
            dom_note,
            self.asset_type.clone(),
            self.v_comm.commitment_x.clone(), // Use x-coordinate of commitment point
            self.owner_addr.clone(),
            psi_field,
            self.chain_hint.clone(),
            self.compliance_hash.clone(),
            self.lineage_hash.clone(),
            self.pool_id.clone(),
            self.callbacks_hash.clone(),
            self.memo_hash.clone(),
        ];
        
        poseidon_hash_zk(&input)
    }
    
    /// Compute nullifier
    pub fn nullifier(&self, nk: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        let cm = self.commitment()?;
        let dom_nf = FpVar::constant(domain_sep_to_field(DOM_NF));
        
        // Convert psi to field using the same algorithm as commitment
        let truncated_psi = if self.psi.len() > 31 {
            &self.psi[..31]
        } else {
            &self.psi[..]
        };
        
        let mut psi_field = FpVar::zero();
        let mut multiplier = FpVar::one();
        let two_five_six = FpVar::constant(F::from(256u64));
        
        for byte in truncated_psi {
            let byte_bits = byte.to_bits_le()?;
            let byte_value = Boolean::le_bits_to_fp_var(&byte_bits)?;
            psi_field += &byte_value * &multiplier;
            multiplier *= &two_five_six;
        }
        
        poseidon_hash_zk(&[dom_nf, nk.clone(), psi_field, cm])
    }
    
    /// Verify value is in valid range (simplified - would use bulletproofs)
    pub fn verify_value_range(&self) -> Result<(), SynthesisError> {
        // Check value fits in 64 bits
        let bits = self.value.to_bits_le()?;
        
        // Ensure high bits are zero (beyond 64 bits)
        if bits.len() > 64 {
            for bit in &bits[64..] {
                bit.enforce_equal(&Boolean::FALSE)?;
            }
        }
        
        Ok(())
    }
    
    /// Update lineage hash
    pub fn update_lineage(
        &mut self,
        parent_lineages: &[FpVar<F>],
        context: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        let mut input = parent_lineages.to_vec();
        input.push(context.clone());
        
        self.lineage_hash = poseidon_hash_zk(&input)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use fluxe_core::crypto::pedersen::{PedersenCommitment, PedersenParams, PedersenRandomness};
    use rand::thread_rng;

    #[test]
    fn test_note_var_commitment() {
        let cs = ConstraintSystem::<F>::new_ref();
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
        
        let note_var = NoteVar::new_witness(cs.clone(), || Ok(note.clone()), value, &randomness).unwrap();
        
        let commitment_var = note_var.commitment().unwrap();
        let expected = FpVar::constant(note.commitment());
        
        commitment_var.enforce_equal(&expected).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_note_var_nullifier() {
        let cs = ConstraintSystem::<F>::new_ref();
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
        let nk = F::rand(&mut rng);
        let note = Note::new(1, v_comm, owner, [1u8; 32], 1);
        
        let note_var = NoteVar::new_witness(cs.clone(), || Ok(note.clone()), value, &randomness).unwrap();
        let nk_var = FpVar::new_witness(cs.clone(), || Ok(nk)).unwrap();
        
        let nullifier_var = note_var.nullifier(&nk_var).unwrap();
        let expected = FpVar::constant(note.nullifier(&nk));
        
        nullifier_var.enforce_equal(&expected).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}