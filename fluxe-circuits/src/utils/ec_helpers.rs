use ark_bls12_381::Fr as F;
use ark_ed_on_bls12_381::{EdwardsProjective, Fq};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero, One, AdditiveGroup};
use fluxe_core::crypto::poseidon::poseidon_hash;

/// Convert Fq to Fr using the same method as the circuit
/// The circuit uses bit decomposition and reconstruction, not byte-level modular reduction
pub fn fq_to_fr_circuit_compatible(fq: &Fq) -> F {
    // Get the bit representation (matches fq.to_bits_le() in circuit)
    let bits = fq.into_bigint().to_bits_le();
    
    // Reconstruct Fr from bits (matches le_bits_to_fp in circuit)
    let mut result = F::zero();
    let mut power = F::one();
    
    // Only process up to the number of bits that fit in Fr
    // Fr is ~255 bits, Fq is ~381 bits, so we need to be careful
    let num_bits = std::cmp::min(bits.len(), F::MODULUS_BIT_SIZE as usize);
    
    for i in 0..num_bits {
        if bits[i] {
            result += power;
        }
        power = power.double();
    }
    
    result
}

/// Compute owner address from EC public key using circuit-compatible method
pub fn compute_owner_address_circuit_compatible(owner_sk: F) -> F {
    let g = <EdwardsProjective as PrimeGroup>::generator();
    let pk = g.mul_bigint(owner_sk.into_bigint());
    let pk_affine = pk.into_affine();
    
    // Convert Fq coordinates to Fr using circuit-compatible method
    let pk_x_fr = fq_to_fr_circuit_compatible(&pk_affine.x);
    let pk_y_fr = fq_to_fr_circuit_compatible(&pk_affine.y);
    
    // Compute address as H(pk_x, pk_y)
    let inputs = [pk_x_fr, pk_y_fr];
    poseidon_hash(&inputs)
}

/// Get public key coordinates in Fr using circuit-compatible conversion
pub fn get_pk_coords_circuit_compatible(owner_sk: F) -> (F, F) {
    let g = <EdwardsProjective as PrimeGroup>::generator();
    let pk = g.mul_bigint(owner_sk.into_bigint());
    let pk_affine = pk.into_affine();
    
    let pk_x_fr = fq_to_fr_circuit_compatible(&pk_affine.x);
    let pk_y_fr = fq_to_fr_circuit_compatible(&pk_affine.y);
    
    (pk_x_fr, pk_y_fr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;
    
    #[test]
    fn test_fq_to_fr_conversion() {
        let mut rng = thread_rng();
        
        // Test that our conversion method produces consistent results
        for _ in 0..10 {
            let owner_sk = F::rand(&mut rng);
            let addr1 = compute_owner_address_circuit_compatible(owner_sk);
            let addr2 = compute_owner_address_circuit_compatible(owner_sk);
            assert_eq!(addr1, addr2, "Address computation should be deterministic");
        }
    }
    
    #[test]
    fn test_different_conversion_methods() {
        let mut rng = thread_rng();
        
        for _ in 0..5 {
            let owner_sk = F::rand(&mut rng);
            let g = <EdwardsProjective as PrimeGroup>::generator();
            let pk = g.mul_bigint(owner_sk.into_bigint());
            let pk_affine = pk.into_affine();
            
            // Method 1: Circuit-compatible (bit-based)
            let pk_x_bits = fq_to_fr_circuit_compatible(&pk_affine.x);
            
            // Method 2: Byte-based modular reduction
            let pk_x_bytes_raw = pk_affine.x.into_bigint().to_bytes_le();
            let pk_x_bytes = F::from_le_bytes_mod_order(&pk_x_bytes_raw);
            
            // These will generally NOT be equal due to different reduction methods
            println!("pk_x (bits):  {:?}", pk_x_bits);
            println!("pk_x (bytes): {:?}", pk_x_bytes);
            println!("Equal: {}", pk_x_bits == pk_x_bytes);
        }
    }
}