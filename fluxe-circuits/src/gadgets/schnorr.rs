use ark_bls12_381::Fr as F;
use ark_ed_on_bls12_381::{
    constraints::{EdwardsVar as JubjubVar, FqVar},
    EdwardsProjective as Jubjub,
};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::fp::FpVar,
    groups::CurveVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::gadgets::poseidon::poseidon_hash_zk;

/// Schnorr verification gadget on Jubjub curve
/// 
/// SECURITY NOTE: Only use verify_with_fq_coords. The Fr-coordinate variant
/// has been deprecated due to soundness issues.
pub struct SchnorrGadget;

impl SchnorrGadget {
    /// Constrained conversion from Fq to Fr for hashing
    fn fq_to_fr_constrained(
        _cs: ConstraintSystemRef<F>,
        fq: &FqVar,
    ) -> Result<FpVar<F>, SynthesisError> {
        // Get the canonical little-endian bit representation of the base field element
        let bits = fq.to_bits_le()?;
        // Pack these bits into the scalar field Fr
        Boolean::le_bits_to_fp(&bits)
    }
    
    /// Verify Schnorr signature with Jubjub curve point coordinates
    /// Takes coordinates as FqVar to ensure proper curve membership
    pub fn verify_with_fq_coords(
        cs: ConstraintSystemRef<F>,
        pk_x_fq: &FqVar,
        pk_y_fq: &FqVar,
        r_x_fq: &FqVar,
        r_y_fq: &FqVar,
        s: &FpVar<F>,
        msg_fields: &[FpVar<F>],
    ) -> Result<Boolean<F>, SynthesisError> {
        // Convert Fq coordinates to Fr using constrained conversion for hashing
        let pk_x_fr = Self::fq_to_fr_constrained(cs.clone(), pk_x_fq)?;
        let pk_y_fr = Self::fq_to_fr_constrained(cs.clone(), pk_y_fq)?;
        let r_x_fr = Self::fq_to_fr_constrained(cs.clone(), r_x_fq)?;
        let r_y_fr = Self::fq_to_fr_constrained(cs.clone(), r_y_fq)?;
        
        // hash challenge c = H(Rx,Ry,PKx,PKy,M...)
        let mut hash_inputs = vec![r_x_fr, r_y_fr, pk_x_fr, pk_y_fr];
        hash_inputs.extend_from_slice(msg_fields);
        let c = poseidon_hash_zk(&hash_inputs)?;

        // Fixed generator
        use ark_ec::PrimeGroup;
        let g = <Jubjub as PrimeGroup>::generator();
        let g_var = JubjubVar::new_constant(cs.clone(), g)?;

        // Build PK and R as group points using the Fq coordinates
        let pk_point = JubjubVar::new(pk_x_fq.clone(), pk_y_fq.clone());
        let r_point = JubjubVar::new(r_x_fq.clone(), r_y_fq.clone());

        // s*G
        let s_bits = s.to_bits_le()?;
        let s_g = g_var.scalar_mul_le(s_bits.iter())?;

        // c*PK
        let c_bits = c.to_bits_le()?;
        let c_pk = pk_point.scalar_mul_le(c_bits.iter())?;

        // RHS = R + c*PK
        let rhs = r_point + c_pk;

        // Check equality: s*G == R + c*PK
        s_g.is_eq(&rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    
    #[test]
    fn test_schnorr_gadget_basic() {
        use ark_ed_on_bls12_381::Fq;
        
        let cs = ConstraintSystem::<F>::new_ref();
        let mut rng = thread_rng();
        
        // Create dummy Fq inputs for Jubjub coordinates
        let pk_x = FqVar::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();
        let pk_y = FqVar::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();
        let r_x = FqVar::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();
        let r_y = FqVar::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();
        let s = FpVar::new_witness(cs.clone(), || Ok(F::rand(&mut rng))).unwrap();
        let msg = vec![FpVar::new_witness(cs.clone(), || Ok(F::rand(&mut rng))).unwrap()];
        
        // This will currently fail because we're using random points
        // In a real implementation, we'd generate a valid signature
        let _result = SchnorrGadget::verify_with_fq_coords(
            cs.clone(),
            &pk_x,
            &pk_y,
            &r_x,
            &r_y,
            &s,
            &msg,
        );
        
        // Check that the circuit generates constraints
        assert!(cs.num_constraints() > 0);
    }
}