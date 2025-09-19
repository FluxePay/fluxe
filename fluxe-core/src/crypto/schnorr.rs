use ark_bls12_381::{Fr as F, Fq, G1Projective as G1, G1Affine};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use crate::crypto::poseidon_hash;

/// Convert Fq coordinate to Fr for hashing
pub fn fq_to_fr(fq: Fq) -> F {
    // Convert Fq to bytes and then to Fr
    // This is safe because we're just using it for hashing
    let mut bytes = Vec::new();
    fq.serialize_uncompressed(&mut bytes).unwrap();
    crate::utils::bytes_to_field(&bytes)
}

/// Schnorr signature over BLS12-381 G1
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrSignature {
    /// Commitment R = r * G
    pub r_point: G1,
    /// Response s = r + c * sk
    pub s: F,
}

/// Schnorr public key
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrPublicKey {
    pub point: G1,
}

/// Schnorr secret key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrSecretKey {
    pub scalar: F,
}

impl SchnorrSecretKey {
    /// Generate a new random secret key
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Self {
            scalar: F::rand(rng),
        }
    }

    /// Derive public key from secret key
    pub fn public_key(&self) -> SchnorrPublicKey {
        let generator = <G1 as PrimeGroup>::generator();
        SchnorrPublicKey {
            point: (generator * self.scalar).into_affine().into(),
        }
    }

    /// Sign a message
    pub fn sign<R: Rng>(&self, message: &[F], rng: &mut R) -> SchnorrSignature {
        // Generate random nonce
        let r = F::rand(rng);
        let generator = <G1 as PrimeGroup>::generator();
        let r_point: G1 = generator * r;
        
        // Compute challenge c = H(R || pk || msg)
        let pk_point = self.public_key().point;
        let mut challenge_input = vec![];
        
        // Add R coordinates
        let r_affine: G1Affine = r_point.into_affine();
        challenge_input.push(fq_to_fr(r_affine.x));
        challenge_input.push(fq_to_fr(r_affine.y));
        
        // Add public key coordinates
        let pk_affine: G1Affine = pk_point.into_affine();
        challenge_input.push(fq_to_fr(pk_affine.x));
        challenge_input.push(fq_to_fr(pk_affine.y));
        
        // Add message
        challenge_input.extend_from_slice(message);
        
        // Hash to get challenge
        let c = poseidon_hash(&challenge_input);
        
        // Compute response s = r + c * sk
        let s = r + c * self.scalar;
        
        SchnorrSignature { r_point, s }
    }
}

impl SchnorrPublicKey {
    /// Verify a signature on a message
    pub fn verify(&self, message: &[F], signature: &SchnorrSignature) -> bool {
        let generator = <G1 as PrimeGroup>::generator();
        
        // Compute challenge c = H(R || pk || msg)
        let mut challenge_input = vec![];
        
        // Add R coordinates
        let r_affine: G1Affine = signature.r_point.into_affine();
        challenge_input.push(fq_to_fr(r_affine.x));
        challenge_input.push(fq_to_fr(r_affine.y));
        
        // Add public key coordinates
        let pk_affine: G1Affine = self.point.into_affine();
        challenge_input.push(fq_to_fr(pk_affine.x));
        challenge_input.push(fq_to_fr(pk_affine.y));
        
        // Add message
        challenge_input.extend_from_slice(message);
        
        // Hash to get challenge
        let c = poseidon_hash(&challenge_input);
        
        // Verify: s * G = R + c * pk
        let lhs = generator * signature.s;
        let rhs = signature.r_point + self.point * c;
        
        lhs == rhs
    }

    /// Convert public key to field element (for use as ticket)
    pub fn to_field(&self) -> F {
        let affine: G1Affine = self.point.into_affine();
        poseidon_hash(&[fq_to_fr(affine.x), fq_to_fr(affine.y)])
    }
}

impl SchnorrSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Self::deserialize_uncompressed(&mut &bytes[..])
            .map_err(|e| format!("Failed to deserialize signature: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_schnorr_signature() {
        let mut rng = test_rng();
        
        // Generate key pair
        let sk = SchnorrSecretKey::random(&mut rng);
        let pk = sk.public_key();
        
        // Create message
        let message = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        
        // Sign message
        let signature = sk.sign(&message, &mut rng);
        
        // Verify signature
        assert!(pk.verify(&message, &signature));
        
        // Verify wrong message fails
        let wrong_message = vec![F::from(4u64), F::from(5u64), F::from(6u64)];
        assert!(!pk.verify(&wrong_message, &signature));
    }

    #[test]
    fn test_signature_serialization() {
        let mut rng = test_rng();
        
        let sk = SchnorrSecretKey::random(&mut rng);
        let message = vec![F::from(42u64)];
        let signature = sk.sign(&message, &mut rng);
        
        // Serialize and deserialize
        let bytes = signature.to_bytes();
        let signature2 = SchnorrSignature::from_bytes(&bytes).unwrap();
        
        assert_eq!(signature, signature2);
    }

    #[test]
    fn test_public_key_to_field() {
        let mut rng = test_rng();
        
        let sk = SchnorrSecretKey::random(&mut rng);
        let pk = sk.public_key();
        
        let field1 = pk.to_field();
        let field2 = pk.to_field();
        
        // Should be deterministic
        assert_eq!(field1, field2);
    }
}