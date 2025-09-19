use ark_bls12_381::Fr as F;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ed_on_bls12_381::EdwardsProjective as Jubjub;
use ark_ff::{BigInteger, PrimeField};

use super::poseidon_hash;

/// Compute EC public key from secret key using Jubjub curve
/// Returns (pk_x, pk_y) as field elements in Fr
pub fn compute_ec_public_key(sk: F) -> (F, F) {
    // Compute pk = sk * G on Jubjub curve
    let g = <Jubjub as PrimeGroup>::generator();
    
    // Scalar multiplication
    let sk_bigint = sk.into_bigint();
    let pk = g.mul_bigint(sk_bigint);
    
    // Get affine coordinates
    let pk_affine = pk.into_affine();
    
    // Convert coordinates from Fq to Fr
    // This is safe since both fields have same size for BLS12-381
    let x_bytes = pk_affine.x.into_bigint().to_bytes_le();
    let y_bytes = pk_affine.y.into_bigint().to_bytes_le();
    
    let pk_x = F::from_le_bytes_mod_order(&x_bytes);
    let pk_y = F::from_le_bytes_mod_order(&y_bytes);
    
    (pk_x, pk_y)
}

/// Compute owner address from EC public key
pub fn compute_owner_address_from_sk(sk: F) -> F {
    let (pk_x, pk_y) = compute_ec_public_key(sk);
    poseidon_hash(&[pk_x, pk_y])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ec_public_key_computation() {
        // Test with a known secret key
        let sk = F::from(12345u64);
        let (pk_x, pk_y) = compute_ec_public_key(sk);
        
        // Verify the public key is deterministic
        let (pk_x2, pk_y2) = compute_ec_public_key(sk);
        assert_eq!(pk_x, pk_x2);
        assert_eq!(pk_y, pk_y2);
        
        // Verify different secret keys give different public keys
        let sk2 = F::from(67890u64);
        let (pk_x3, pk_y3) = compute_ec_public_key(sk2);
        assert_ne!(pk_x, pk_x3);
        assert_ne!(pk_y, pk_y3);
    }
    
    #[test]
    fn test_owner_address_computation() {
        let sk = F::from(42u64);
        let addr = compute_owner_address_from_sk(sk);
        
        // Verify deterministic
        let addr2 = compute_owner_address_from_sk(sk);
        assert_eq!(addr, addr2);
        
        // Verify different for different keys
        let sk2 = F::from(43u64);
        let addr3 = compute_owner_address_from_sk(sk2);
        assert_ne!(addr, addr3);
    }
}