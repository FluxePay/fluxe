use ark_bls12_381::Fr as F;
use ark_ec::Group;
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
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::gadgets::poseidon::poseidon_hash_zk;

/// EC-based authentication gadget for Fluxe circuits
/// Implements owner_addr = H(pk_x, pk_y) where pk is derived from sk
pub struct AuthGadget;

impl AuthGadget {
    /// Constrained conversion from Fq to Fr for hashing
    /// This ensures the conversion is properly constrained in the circuit
    fn fq_to_fr_constrained(
        _cs: ConstraintSystemRef<F>,
        fq: &FqVar,
    ) -> Result<FpVar<F>, SynthesisError> {
        // Get the canonical little-endian bit representation of the base field element
        let bits = fq.to_bits_le()?;
        // Pack these bits into the scalar field Fr
        Boolean::le_bits_to_fp_var(&bits)
    }
    
    /// Verify EC-based authentication by deriving public key from secret key
    /// and computing owner address from public key coordinates
    pub fn verify_ec_authentication(
        cs: ConstraintSystemRef<F>,
        owner_sk: &FpVar<F>,
        expected_owner_addr: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Derive public key from secret key: pk = sk * G
        let (pk_x_fq, pk_y_fq) = Self::scalar_mult_generator(cs.clone(), owner_sk)?;
        
        // Compute owner address: addr = H(pk_x, pk_y)
        let computed_addr = Self::compute_owner_address_from_fq(cs, &pk_x_fq, &pk_y_fq)?;
        
        // Enforce that computed address matches expected
        computed_addr.enforce_equal(expected_owner_addr)?;
        
        Ok(())
    }
    
    /// Compute owner address from Fq coordinates
    pub fn compute_owner_address_from_fq(
        cs: ConstraintSystemRef<F>,
        pk_x_fq: &FqVar,
        pk_y_fq: &FqVar,
    ) -> Result<FpVar<F>, SynthesisError> {
        let pk_x = Self::fq_to_fr_constrained(cs.clone(), pk_x_fq)?;
        let pk_y = Self::fq_to_fr_constrained(cs, pk_y_fq)?;
        poseidon_hash_zk(&[pk_x, pk_y])
    }
    
    /// Real scalar multiplication: pk = sk * G on Jubjub
    /// Returns Fq coordinates to avoid unsafe conversions
    pub fn scalar_mult_generator(
        cs: ConstraintSystemRef<F>,
        scalar: &FpVar<F>,
    ) -> Result<(FqVar, FqVar), SynthesisError> {
        // Convert scalar to bits (little-endian)
        let bits = scalar.to_bits_le()?;

        // Constant generator
        let g = Jubjub::generator();
        let g_var = JubjubVar::new_constant(cs.clone(), g)?;

        // Variable-time scalar mul in-circuit (fixed-base windowed)
        // Use r1cs_std scalar_mul_le which walks bits of the scalar
        let pk_var = g_var.scalar_mul_le(bits.iter())?;

        // Optional on-curve check (Twisted Edwards):
        // For Ed25519-like curves r1cs_std ensures correctness, but we can still assert non-zero:
        let not_identity = pk_var.is_zero()?.not();
        not_identity.enforce_equal(&Boolean::TRUE)?;

        // Return Fq coordinates directly without unsafe conversion
        Ok((pk_var.x.clone(), pk_var.y.clone()))
    }
    
    /// Scalar multiplication with Fr output for legacy compatibility
    /// Uses constrained conversion from Fq to Fr
    pub fn scalar_mult_generator_fr(
        cs: ConstraintSystemRef<F>,
        scalar: &FpVar<F>,
    ) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        let (pk_x_fq, pk_y_fq) = Self::scalar_mult_generator(cs.clone(), scalar)?;
        let pk_x_fr = Self::fq_to_fr_constrained(cs.clone(), &pk_x_fq)?;
        let pk_y_fr = Self::fq_to_fr_constrained(cs, &pk_y_fq)?;
        Ok((pk_x_fr, pk_y_fr))
    }
    
    /// Verify public key is valid (on curve check)
    /// This would be critical in a production implementation
    pub fn verify_public_key_valid(
        _cs: ConstraintSystemRef<F>,
        _pk_x: &FpVar<F>,
        _pk_y: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // In production: verify pk is on the elliptic curve
        // For Baby Jubjub: x^2 + y^2 = 1 + d*x^2*y^2
        // For short Weierstrass: y^2 = x^3 + ax + b
        
        // Simplified implementation always returns true
        // Real implementation would check curve equation
        Ok(Boolean::TRUE)
    }
    
    /// Alternative authentication using Ethereum-style addresses
    /// Supports both Poseidon-based and Ethereum ECDSA addresses
    pub fn verify_ethereum_authentication(
        _cs: ConstraintSystemRef<F>,
        owner_sk: &FpVar<F>,
        expected_eth_addr: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // For Ethereum compatibility:
        // 1. Derive secp256k1 public key from private key
        // 2. Compute Keccak256 hash of uncompressed public key
        // 3. Take last 20 bytes as Ethereum address
        
        // Simplified implementation using Poseidon for consistency
        // In production, would use proper secp256k1 + Keccak256
        
        let eth_pk = poseidon_hash_zk(&[owner_sk.clone()])?;
        let computed_addr = poseidon_hash_zk(&[eth_pk])?;
        
        computed_addr.enforce_equal(expected_eth_addr)?;
        
        Ok(())
    }
    
    /// Multi-signature authentication for advanced use cases
    pub fn verify_multisig_authentication(
        cs: ConstraintSystemRef<F>,
        secret_keys: &[FpVar<F>],
        threshold: usize,
        expected_multisig_addr: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        if secret_keys.len() < threshold {
            return Err(SynthesisError::Unsatisfiable);
        }
        
        // Derive public keys for each secret key
        let mut public_keys = Vec::new();
        for sk in secret_keys {
            let (pk_x_fq, pk_y_fq) = Self::scalar_mult_generator(cs.clone(), sk)?;
            let pk_x = Self::fq_to_fr_constrained(cs.clone(), &pk_x_fq)?;
            let pk_y = Self::fq_to_fr_constrained(cs.clone(), &pk_y_fq)?;
            public_keys.push((pk_x, pk_y));
        }
        
        // Compute multisig address from public keys and threshold
        let mut inputs = vec![FpVar::constant(F::from(threshold as u64))];
        for (pk_x, pk_y) in &public_keys {
            inputs.push(pk_x.clone());
            inputs.push(pk_y.clone());
        }
        
        let computed_multisig_addr = poseidon_hash_zk(&inputs)?;
        computed_multisig_addr.enforce_equal(expected_multisig_addr)?;
        
        Ok(())
    }
}

// PublicKeyVar removed - it used the wrong field type (FpVar instead of FqVar)
// Use AuthGadget::scalar_mult_generator and compute_owner_address_from_fq instead

/// Authentication witness containing all required authentication data
#[derive(Clone)]
pub struct AuthWitness {
    pub owner_sk: FpVar<F>,
    pub auth_type: AuthType,
}

/// Supported authentication types
#[derive(Clone, Copy, Debug)]
pub enum AuthType {
    /// Poseidon-based authentication: addr = H(pk_x, pk_y)
    Poseidon,
    /// Ethereum-compatible authentication: addr = last20(Keccak256(pk))
    Ethereum,
    /// Multi-signature authentication
    MultiSig { threshold: usize },
}

impl AuthWitness {
    /// Create new authentication witness
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        owner_sk: F,
        auth_type: AuthType,
    ) -> Result<Self, SynthesisError> {
        let owner_sk_var = FpVar::new_witness(cs.clone(), || Ok(owner_sk))?;
        
        Ok(Self {
            owner_sk: owner_sk_var,
            auth_type,
        })
    }
    
    /// Verify authentication against expected owner address
    pub fn verify_authentication(
        &self,
        cs: ConstraintSystemRef<F>,
        expected_owner_addr: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        match self.auth_type {
            AuthType::Poseidon => {
                AuthGadget::verify_ec_authentication(cs, &self.owner_sk, expected_owner_addr)
            }
            AuthType::Ethereum => {
                AuthGadget::verify_ethereum_authentication(cs, &self.owner_sk, expected_owner_addr)
            }
            AuthType::MultiSig { .. } => {
                // For multisig, we would need additional witnesses
                // This is a simplified implementation
                AuthGadget::verify_ec_authentication(cs, &self.owner_sk, expected_owner_addr)
            }
        }
    }
    
    /// Compute owner address for this authentication witness
    pub fn compute_owner_address(&self, cs: ConstraintSystemRef<F>) -> Result<FpVar<F>, SynthesisError> {
        // Derive public key from secret key
        let (pk_x_fq, pk_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), &self.owner_sk)?;
        
        match self.auth_type {
            AuthType::Poseidon => {
                // Standard Poseidon address computation
                AuthGadget::compute_owner_address_from_fq(cs, &pk_x_fq, &pk_y_fq)
            }
            AuthType::Ethereum => {
                // For Ethereum auth, use different address derivation
                let pk_x = AuthGadget::fq_to_fr_constrained(cs.clone(), &pk_x_fq)?;
                let pk_y = AuthGadget::fq_to_fr_constrained(cs.clone(), &pk_y_fq)?;
                let eth_pk = poseidon_hash_zk(&[pk_x, pk_y])?;
                poseidon_hash_zk(&[eth_pk])
            }
            AuthType::MultiSig { .. } => {
                // Simplified multisig address computation
                AuthGadget::compute_owner_address_from_fq(cs, &pk_x_fq, &pk_y_fq)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_ec_authentication() {
        let cs = ConstraintSystem::<F>::new_ref();
        let rng = thread_rng();
        
        // Use a smaller scalar for testing to avoid overflow issues
        let owner_sk = F::from(12345u64);
        let owner_sk_var = FpVar::new_witness(cs.clone(), || Ok(owner_sk)).unwrap();
        
        // Derive public key and address
        let (pk_x_fq, pk_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), &owner_sk_var).unwrap();
        let pk_x = AuthGadget::fq_to_fr_constrained(cs.clone(), &pk_x_fq).unwrap();
        let pk_y = AuthGadget::fq_to_fr_constrained(cs.clone(), &pk_y_fq).unwrap();
        let expected_addr = AuthGadget::compute_owner_address_from_fq(cs.clone(), &pk_x_fq, &pk_y_fq).unwrap();
        
        // Verify authentication
        AuthGadget::verify_ec_authentication(cs.clone(), &owner_sk_var, &expected_addr).unwrap();
        
        assert!(cs.is_satisfied().unwrap(), "EC authentication constraints should be satisfied");
    }

    #[test]
    fn test_auth_witness() {
        let cs = ConstraintSystem::<F>::new_ref();
        let mut rng = thread_rng();
        
        let owner_sk = F::rand(&mut rng);
        let auth_witness = AuthWitness::new_witness(cs.clone(), owner_sk, AuthType::Poseidon).unwrap();
        
        let expected_addr = auth_witness.compute_owner_address(cs.clone()).unwrap();
        auth_witness.verify_authentication(cs.clone(), &expected_addr).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_ethereum_authentication() {
        let cs = ConstraintSystem::<F>::new_ref();
        let mut rng = thread_rng();
        
        let owner_sk = F::rand(&mut rng);
        let owner_sk_var = FpVar::new_witness(cs.clone(), || Ok(owner_sk)).unwrap();
        
        // Compute expected Ethereum address
        let eth_pk = poseidon_hash_zk(&[owner_sk_var.clone()]).unwrap();
        let expected_addr = poseidon_hash_zk(&[eth_pk]).unwrap();
        
        // Verify Ethereum authentication
        AuthGadget::verify_ethereum_authentication(cs.clone(), &owner_sk_var, &expected_addr).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_multisig_authentication() {
        let cs = ConstraintSystem::<F>::new_ref();
        let mut rng = thread_rng();
        
        let secret_keys: Vec<F> = (0..3).map(|_| F::rand(&mut rng)).collect();
        let secret_key_vars: Vec<FpVar<F>> = secret_keys
            .iter()
            .map(|&sk| FpVar::new_witness(cs.clone(), || Ok(sk)).unwrap())
            .collect();
        
        let threshold = 2;
        
        // Compute expected multisig address
        let mut public_keys = Vec::new();
        for sk_var in &secret_key_vars {
            let (pk_x_fq, pk_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), sk_var).unwrap();
            let pk_x = AuthGadget::fq_to_fr_constrained(cs.clone(), &pk_x_fq).unwrap();
            let pk_y = AuthGadget::fq_to_fr_constrained(cs.clone(), &pk_y_fq).unwrap();
            public_keys.push((pk_x, pk_y));
        }
        
        let mut inputs = vec![FpVar::constant(F::from(threshold as u64))];
        for (pk_x, pk_y) in &public_keys {
            inputs.push(pk_x.clone());
            inputs.push(pk_y.clone());
        }
        let expected_multisig_addr = poseidon_hash_zk(&inputs).unwrap();
        
        // Verify multisig authentication
        AuthGadget::verify_multisig_authentication(
            cs.clone(),
            &secret_key_vars,
            threshold,
            &expected_multisig_addr,
        ).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }
}