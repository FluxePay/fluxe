//! Groth16 Verification Module
//!
//! This module implements BN254 Groth16 proof verification using the `bn` crate.
//! When running inside SP1 zkVM, the pairing operations use hardware precompiles
//! for efficient verification (~10M cycles per proof).
//!
//! Format: Gnark-compatible (big-endian coordinates)

use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fr, Fq, Fq2, Group, Gt, G1, G2};

/// Groth16 Proof (BN254)
///
/// Format: Gnark uncompressed (256 bytes total)
/// - A: 64 bytes (G1 uncompressed)
/// - B: 128 bytes (G2 uncompressed)
/// - C: 64 bytes (G1 uncompressed)
#[derive(Clone, Debug)]
pub struct Groth16Proof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

/// Groth16 Verifying Key (BN254)
///
/// Format: Gnark format
#[derive(Clone, Debug)]
pub struct Groth16VerifyingKey {
    /// Alpha in G1
    pub alpha: G1,
    /// Beta in G2
    pub beta: G2,
    /// Gamma in G2
    pub gamma: G2,
    /// Delta in G2
    pub delta: G2,
    /// IC (K) points in G1 - one for each public input + 1
    pub ic: Vec<G1>,
}

/// Error type for Groth16 verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Groth16Error {
    /// Invalid proof format
    InvalidProof,
    /// Invalid verifying key format
    InvalidVerifyingKey,
    /// Wrong number of public inputs
    InvalidPublicInputCount,
    /// Point not on curve
    InvalidPoint,
    /// Pairing check failed
    VerificationFailed,
}

/// Parse a G1 point from 64 bytes (gnark uncompressed format, big-endian)
pub fn parse_g1_be(bytes: &[u8]) -> Result<G1, Groth16Error> {
    if bytes.len() != 64 {
        return Err(Groth16Error::InvalidPoint);
    }

    // Check for point at infinity (all zeros)
    if bytes.iter().all(|&b| b == 0) {
        return Ok(G1::zero());
    }

    // Gnark uses big-endian coordinates
    let x = parse_fq_be(&bytes[0..32])?;
    let y = parse_fq_be(&bytes[32..64])?;

    AffineG1::new(x, y)
        .map(Into::into)
        .map_err(|_| Groth16Error::InvalidPoint)
}

/// Parse a G2 point from 128 bytes (gnark uncompressed format, big-endian)
pub fn parse_g2_be(bytes: &[u8]) -> Result<G2, Groth16Error> {
    if bytes.len() != 128 {
        return Err(Groth16Error::InvalidPoint);
    }

    // Check for point at infinity
    if bytes.iter().all(|&b| b == 0) {
        return Ok(G2::zero());
    }

    // Gnark G2 format: x.c1 (32) || x.c0 (32) || y.c1 (32) || y.c0 (32)
    let x_c1 = parse_fq_be(&bytes[0..32])?;
    let x_c0 = parse_fq_be(&bytes[32..64])?;
    let y_c1 = parse_fq_be(&bytes[64..96])?;
    let y_c0 = parse_fq_be(&bytes[96..128])?;

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    AffineG2::new(x, y)
        .map(Into::into)
        .map_err(|_| Groth16Error::InvalidPoint)
}

/// Parse an Fq element from 32 bytes (big-endian)
fn parse_fq_be(bytes: &[u8]) -> Result<Fq, Groth16Error> {
    if bytes.len() != 32 {
        return Err(Groth16Error::InvalidPoint);
    }

    // The bn crate's from_be_bytes_mod_order takes big-endian bytes
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Fq::from_be_bytes_mod_order(&arr).map_err(|_| Groth16Error::InvalidPoint)
}

/// Parse an Fr element from 32 bytes (big-endian)
///
/// The bn crate's Fr::from_slice expects big-endian bytes.
pub fn parse_fr_be(bytes: &[u8]) -> Result<Fr, Groth16Error> {
    if bytes.len() != 32 {
        return Err(Groth16Error::InvalidPoint);
    }

    // from_slice expects big-endian, which is what we have
    Fr::from_slice(bytes).map_err(|_| Groth16Error::InvalidPoint)
}

impl Groth16Proof {
    /// Parse a Groth16 proof from gnark uncompressed format (256 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        if bytes.len() != 256 {
            return Err(Groth16Error::InvalidProof);
        }

        let a = parse_g1_be(&bytes[0..64])?;
        let b = parse_g2_be(&bytes[64..192])?;
        let c = parse_g1_be(&bytes[192..256])?;

        Ok(Self { a, b, c })
    }
}

impl Groth16VerifyingKey {
    /// Parse a verifying key from gnark format
    ///
    /// Gnark VK format:
    /// - alpha: 64 bytes (G1)
    /// - beta: 128 bytes (G2)
    /// - gamma: 128 bytes (G2)
    /// - delta: 128 bytes (G2)
    /// - ic_len: 4 bytes (big-endian u32)
    /// - ic: ic_len * 64 bytes (G1 points)
    ///
    /// Note: beta is NEGATED during parsing for verification equation compatibility
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        if bytes.len() < 448 + 4 {
            return Err(Groth16Error::InvalidVerifyingKey);
        }

        let alpha = parse_g1_be(&bytes[0..64])?;
        let beta = parse_g2_be(&bytes[64..192])?;
        let gamma = parse_g2_be(&bytes[192..320])?;
        let delta = parse_g2_be(&bytes[320..448])?;

        // Read IC length (4 bytes big-endian at offset 448)
        let ic_len = u32::from_be_bytes([bytes[448], bytes[449], bytes[450], bytes[451]]) as usize;

        let expected_len = 448 + 4 + ic_len * 64;
        if bytes.len() < expected_len {
            return Err(Groth16Error::InvalidVerifyingKey);
        }

        let mut ic = Vec::with_capacity(ic_len);
        for i in 0..ic_len {
            let offset = 452 + i * 64;
            let point = parse_g1_be(&bytes[offset..offset + 64])?;
            ic.push(point);
        }

        Ok(Self {
            alpha,
            beta,
            gamma,
            delta,
            ic,
        })
    }
}

/// Verify a Groth16 proof
///
/// This function verifies the pairing equation:
/// e(A, B) = e(alpha, beta) * e(sum(ic[i] * input[i]), gamma) * e(C, delta)
///
/// Rearranged for batch verification:
/// e(A, B) * e(-alpha, beta) * e(-L, gamma) * e(-C, delta) = 1
///
/// We negate in G1 (alpha, L, C) rather than G2 for consistency.
pub fn verify(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool, Groth16Error> {
    // Check that we have the right number of public inputs
    // ic has one extra element (ic[0] is the constant term)
    if public_inputs.len() + 1 != vk.ic.len() {
        return Err(Groth16Error::InvalidPublicInputCount);
    }

    // Compute prepared inputs: ic[0] + sum(ic[i+1] * input[i])
    let mut prepared_inputs = vk.ic[0];
    for (i, input) in public_inputs.iter().enumerate() {
        prepared_inputs = prepared_inputs + vk.ic[i + 1] * *input;
    }

    // Perform the pairing check
    // Equation: e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)
    // Rearranged: e(A, B) * e(-alpha, beta) * e(-L, gamma) * e(-C, delta) = 1
    let neg_alpha = -vk.alpha;
    let neg_l = -prepared_inputs;
    let neg_c = -proof.c;

    let pairs = [
        (proof.a, proof.b),
        (neg_alpha, vk.beta),
        (neg_l, vk.gamma),
        (neg_c, vk.delta),
    ];

    // pairing_batch computes the product of pairings and checks if it equals 1
    let result = pairing_batch(&pairs);

    Ok(result == Gt::one())
}

/// Verify a proof from raw bytes
pub fn verify_bytes(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
) -> Result<bool, Groth16Error> {
    let vk = Groth16VerifyingKey::from_bytes(vk_bytes)?;
    let proof = Groth16Proof::from_bytes(proof_bytes)?;

    let inputs: Result<Vec<Fr>, Groth16Error> = public_inputs
        .iter()
        .map(|bytes| parse_fr_be(bytes))
        .collect();
    let inputs = inputs?;

    verify(&vk, &proof, &inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_g1_zero() {
        let bytes = [0u8; 64];
        let point = parse_g1_be(&bytes).unwrap();
        assert!(point.is_zero());
    }

    #[test]
    fn test_parse_g2_zero() {
        let bytes = [0u8; 128];
        let point = parse_g2_be(&bytes).unwrap();
        assert!(point.is_zero());
    }

    #[test]
    fn test_invalid_proof_length() {
        let bytes = [0u8; 100]; // Wrong length
        assert!(matches!(
            Groth16Proof::from_bytes(&bytes),
            Err(Groth16Error::InvalidProof)
        ));
    }

    #[test]
    fn test_invalid_vk_length() {
        let bytes = [0u8; 100]; // Wrong length
        assert!(matches!(
            Groth16VerifyingKey::from_bytes(&bytes),
            Err(Groth16Error::InvalidVerifyingKey)
        ));
    }
}

/// Integration tests that generate real proofs and verify them
#[cfg(test)]
mod integration_tests {
    use super::*;
    use ark_bn254::{Bn254, Fr as ArkFr};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use rand::{SeedableRng, rngs::StdRng};

    /// Simple test circuit: prove knowledge of x such that x^3 + x + 5 = out
    #[derive(Clone)]
    struct CubicCircuit {
        x: Option<ArkFr>,
    }

    impl ConstraintSynthesizer<ArkFr> for CubicCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ArkFr>,
        ) -> Result<(), SynthesisError> {
            use ark_r1cs_std::alloc::AllocVar;
            use ark_r1cs_std::eq::EqGadget;
            use ark_r1cs_std::fields::fp::FpVar;
            use ark_r1cs_std::fields::FieldVar;

            // Allocate x as a private witness
            let x = FpVar::new_witness(cs.clone(), || {
                self.x.ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Compute x^2
            let x_sq = &x * &x;

            // Compute x^3
            let x_cu = &x_sq * &x;

            // Compute x^3 + x + 5
            let five = FpVar::constant(ArkFr::from(5u64));
            let out = &x_cu + &x + &five;

            // Allocate the output as a public input
            let expected_out = FpVar::new_input(cs, || {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                let x_cu = x_val * x_val * x_val;
                Ok(x_cu + x_val + ArkFr::from(5u64))
            })?;

            // Enforce that out == expected_out
            out.enforce_equal(&expected_out)?;

            Ok(())
        }
    }

    /// Convert arkworks G1Affine to gnark bytes (big-endian)
    fn ark_g1_to_gnark(point: &ark_bn254::G1Affine) -> [u8; 64] {
        use ark_ec::AffineRepr;
        use ark_ff::{PrimeField, BigInteger};

        let mut bytes = [0u8; 64];
        if point.is_zero() {
            return bytes;
        }

        let x = point.x().unwrap();
        let y = point.y().unwrap();

        // Convert Fq to bytes via BigInt (returns Vec<u8>)
        let x_le_vec = x.into_bigint().to_bytes_le();
        let y_le_vec = y.into_bigint().to_bytes_le();

        // Copy to fixed arrays and reverse for big-endian
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&x_le_vec[..32]);
        y_bytes.copy_from_slice(&y_le_vec[..32]);
        x_bytes.reverse();
        y_bytes.reverse();

        bytes[0..32].copy_from_slice(&x_bytes);
        bytes[32..64].copy_from_slice(&y_bytes);
        bytes
    }

    /// Convert arkworks G2Affine to gnark bytes (big-endian)
    fn ark_g2_to_gnark(point: &ark_bn254::G2Affine) -> [u8; 128] {
        use ark_ec::AffineRepr;
        use ark_ff::{PrimeField, BigInteger};

        let mut bytes = [0u8; 128];
        if point.is_zero() {
            return bytes;
        }

        let x = point.x().unwrap();
        let y = point.y().unwrap();

        // Convert Fq to bytes via BigInt (returns Vec<u8>)
        let x_c0_vec = x.c0.into_bigint().to_bytes_le();
        let x_c1_vec = x.c1.into_bigint().to_bytes_le();
        let y_c0_vec = y.c0.into_bigint().to_bytes_le();
        let y_c1_vec = y.c1.into_bigint().to_bytes_le();

        // Copy to fixed arrays
        let mut x_c0 = [0u8; 32];
        let mut x_c1 = [0u8; 32];
        let mut y_c0 = [0u8; 32];
        let mut y_c1 = [0u8; 32];
        x_c0.copy_from_slice(&x_c0_vec[..32]);
        x_c1.copy_from_slice(&x_c1_vec[..32]);
        y_c0.copy_from_slice(&y_c0_vec[..32]);
        y_c1.copy_from_slice(&y_c1_vec[..32]);

        // Convert to big-endian
        x_c0.reverse();
        x_c1.reverse();
        y_c0.reverse();
        y_c1.reverse();

        // Gnark G2 format: x.c1 || x.c0 || y.c1 || y.c0
        bytes[0..32].copy_from_slice(&x_c1);
        bytes[32..64].copy_from_slice(&x_c0);
        bytes[64..96].copy_from_slice(&y_c1);
        bytes[96..128].copy_from_slice(&y_c0);
        bytes
    }

    /// Convert arkworks Fr to big-endian bytes
    fn ark_fr_to_be(fr: &ArkFr) -> [u8; 32] {
        use ark_ff::{PrimeField, BigInteger};
        let le_vec = fr.into_bigint().to_bytes_le();
        let mut be_bytes = [0u8; 32];
        be_bytes.copy_from_slice(&le_vec[..32]);
        be_bytes.reverse();
        be_bytes
    }

    /// Convert arkworks proof to gnark bytes
    fn ark_proof_to_gnark(proof: &ark_groth16::Proof<Bn254>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&ark_g1_to_gnark(&proof.a));
        bytes.extend_from_slice(&ark_g2_to_gnark(&proof.b));
        bytes.extend_from_slice(&ark_g1_to_gnark(&proof.c));
        bytes
    }

    /// Convert arkworks VK to gnark bytes
    fn ark_vk_to_gnark(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<u8> {
        let ic_len = vk.gamma_abc_g1.len();
        let mut bytes = Vec::with_capacity(448 + 4 + ic_len * 64);

        bytes.extend_from_slice(&ark_g1_to_gnark(&vk.alpha_g1));
        bytes.extend_from_slice(&ark_g2_to_gnark(&vk.beta_g2));
        bytes.extend_from_slice(&ark_g2_to_gnark(&vk.gamma_g2));
        bytes.extend_from_slice(&ark_g2_to_gnark(&vk.delta_g2));

        // IC length as big-endian u32
        bytes.extend_from_slice(&(ic_len as u32).to_be_bytes());

        // IC points
        for point in &vk.gamma_abc_g1 {
            bytes.extend_from_slice(&ark_g1_to_gnark(point));
        }

        bytes
    }

    #[test]
    fn test_generator_conversion() {
        use ark_ec::AffineRepr;
        use ark_ff::{PrimeField, BigInteger};

        // Get arkworks G1 generator
        let ark_gen = ark_bn254::G1Affine::generator();
        let ark_x = ark_gen.x().unwrap();
        let ark_y = ark_gen.y().unwrap();

        // Convert to bytes (big-endian)
        let x_le = ark_x.into_bigint().to_bytes_le();
        let y_le = ark_y.into_bigint().to_bytes_le();

        let mut x_be = [0u8; 32];
        let mut y_be = [0u8; 32];
        x_be.copy_from_slice(&x_le[..32]);
        y_be.copy_from_slice(&y_le[..32]);
        x_be.reverse();
        y_be.reverse();

        println!("Arkworks G1 generator x (BE): {:?}", hex::encode(&x_be));
        println!("Arkworks G1 generator y (BE): {:?}", hex::encode(&y_be));

        // Get bn crate G1 generator and extract its coordinates
        let bn_gen = bn::G1::one();

        // Convert bn::G1 to affine to get coordinates
        let bn_gen_affine = bn::AffineG1::from_jacobian(bn_gen).unwrap();

        // Get x and y as big-endian bytes
        let mut bn_x_be = [0u8; 32];
        let mut bn_y_be = [0u8; 32];
        bn_gen_affine.x().to_big_endian(&mut bn_x_be).unwrap();
        bn_gen_affine.y().to_big_endian(&mut bn_y_be).unwrap();

        println!("bn G1 generator x (BE): {:?}", hex::encode(&bn_x_be));
        println!("bn G1 generator y (BE): {:?}", hex::encode(&bn_y_be));

        // Now try to parse our arkworks bytes with the groth16 module
        let mut g1_bytes = [0u8; 64];
        g1_bytes[0..32].copy_from_slice(&x_be);
        g1_bytes[32..64].copy_from_slice(&y_be);

        let parsed = parse_g1_be(&g1_bytes);
        println!("Parsing arkworks generator: {:?}", parsed.is_ok());

        // Compare the bytes - they should be the same if both use (1, 2) as generator
        assert_eq!(x_be, bn_x_be, "Generator x coordinates don't match");
        assert_eq!(y_be, bn_y_be, "Generator y coordinates don't match");
    }

    #[test]
    fn test_pairing_consistency() {
        // Test that arkworks and bn crate pairings are consistent
        // Use generators for simplicity

        // Arkworks pairing of generators
        use ark_ec::pairing::Pairing;
        use ark_ec::AffineRepr;
        let ark_g1 = ark_bn254::G1Affine::generator();
        let ark_g2 = ark_bn254::G2Affine::generator();
        let ark_pairing = Bn254::pairing(ark_g1, ark_g2);
        println!("Arkworks pairing(G1, G2) computed");

        // bn crate pairing of generators
        let bn_g1 = bn::G1::one();
        let bn_g2 = bn::G2::one();
        let bn_pairing = bn::pairing(bn_g1, bn_g2);
        println!("bn pairing(G1, G2) computed");

        // Both should equal the generator of Gt
        // Let's compute e(G1, G2)^2 and e(2*G1, G2) - they should be equal if pairing is bilinear

        let ark_double = Bn254::pairing(ark_g1 + ark_g1, ark_g2);
        let ark_squared = ark_pairing + ark_pairing;
        println!("Arkworks: e(2G1, G2) == 2*e(G1, G2)? {}", ark_double == ark_squared);

        // Test bn bilinearity
        let bn_double_g1 = bn_g1 + bn_g1;
        let bn_pairing_double = bn::pairing(bn_double_g1, bn_g2);
        // Note: Gt is multiplicative, so doubling the pairing means squaring in Gt
        let bn_squared = bn_pairing * bn_pairing;
        println!("bn: e(2G1, G2) == e(G1, G2)^2? {}", bn_pairing_double == bn_squared);

        // Test the batch pairing
        let pairs = [(bn_g1, bn_g2), (-bn_g1, bn_g2)];
        let batch_result = bn::pairing_batch(&pairs);
        println!("bn: e(G1, G2) * e(-G1, G2) == 1? {}", batch_result == bn::Gt::one());
    }

    #[test]
    fn test_g2_generator_conversion() {
        use ark_ec::AffineRepr;
        use ark_ff::{PrimeField, BigInteger};

        // Get arkworks G2 generator
        let ark_gen = ark_bn254::G2Affine::generator();
        let ark_x = ark_gen.x().unwrap();
        let ark_y = ark_gen.y().unwrap();

        println!("Arkworks G2 generator x.c0: {:?}", hex::encode(ark_x.c0.into_bigint().to_bytes_le()));
        println!("Arkworks G2 generator x.c1: {:?}", hex::encode(ark_x.c1.into_bigint().to_bytes_le()));
        println!("Arkworks G2 generator y.c0: {:?}", hex::encode(ark_y.c0.into_bigint().to_bytes_le()));
        println!("Arkworks G2 generator y.c1: {:?}", hex::encode(ark_y.c1.into_bigint().to_bytes_le()));

        // Convert arkworks G2 to our gnark format
        let gnark_bytes = ark_g2_to_gnark(&ark_gen);
        println!("Gnark bytes (128): {:?}", hex::encode(&gnark_bytes));

        // Get bn crate G2 generator
        let bn_gen = bn::G2::one();
        let bn_gen_affine = bn::AffineG2::from_jacobian(bn_gen).unwrap();

        // Get x and y as big-endian bytes
        let mut bn_x_c0_be = [0u8; 32];
        let mut bn_x_c1_be = [0u8; 32];
        let mut bn_y_c0_be = [0u8; 32];
        let mut bn_y_c1_be = [0u8; 32];
        bn_gen_affine.x().real().to_big_endian(&mut bn_x_c0_be).unwrap();
        bn_gen_affine.x().imaginary().to_big_endian(&mut bn_x_c1_be).unwrap();
        bn_gen_affine.y().real().to_big_endian(&mut bn_y_c0_be).unwrap();
        bn_gen_affine.y().imaginary().to_big_endian(&mut bn_y_c1_be).unwrap();

        println!("bn G2 generator x.c0 (BE): {:?}", hex::encode(&bn_x_c0_be));
        println!("bn G2 generator x.c1 (BE): {:?}", hex::encode(&bn_x_c1_be));
        println!("bn G2 generator y.c0 (BE): {:?}", hex::encode(&bn_y_c0_be));
        println!("bn G2 generator y.c1 (BE): {:?}", hex::encode(&bn_y_c1_be));

        // Parse our gnark bytes
        let parsed = parse_g2_be(&gnark_bytes);
        println!("Parsing G2: {:?}", parsed.is_ok());

        if let Ok(g2) = parsed {
            let g2_affine = bn::AffineG2::from_jacobian(g2).unwrap();
            let mut parsed_x_c0 = [0u8; 32];
            let mut parsed_x_c1 = [0u8; 32];
            g2_affine.x().real().to_big_endian(&mut parsed_x_c0).unwrap();
            g2_affine.x().imaginary().to_big_endian(&mut parsed_x_c1).unwrap();
            println!("Parsed G2 x.c0 (BE): {:?}", hex::encode(&parsed_x_c0));
            println!("Parsed G2 x.c1 (BE): {:?}", hex::encode(&parsed_x_c1));
        }
    }

    #[test]
    fn test_groth16_verification_valid_proof() {
        use ark_ec::pairing::Pairing;

        let mut rng = StdRng::seed_from_u64(42);

        // Create circuit with x = 3 (so output = 27 + 3 + 5 = 35)
        let circuit = CubicCircuit { x: Some(ArkFr::from(3u64)) };

        // Generate proving and verifying keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            CubicCircuit { x: None },
            &mut rng,
        ).unwrap();

        // Generate proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        // Compute public input (the output value)
        let x = ArkFr::from(3u64);
        let output = x * x * x + x + ArkFr::from(5u64); // 35

        // Verify with arkworks (sanity check)
        let ark_valid = Groth16::<Bn254>::verify(&vk, &[output], &proof).unwrap();
        assert!(ark_valid, "Arkworks verification failed");
        println!("Arkworks verification: PASSED");

        // Now let's try to verify using bn crate
        // First, test the generator conversion to make sure it works

        use ark_ec::AffineRepr;

        // Test: arkworks generator -> gnark bytes -> bn crate
        let ark_gen = ark_bn254::G1Affine::generator();
        let gnark_gen_bytes = ark_g1_to_gnark(&ark_gen);
        let bn_gen_parsed = parse_g1_be(&gnark_gen_bytes).unwrap();
        let bn_gen_native = bn::G1::one();

        // These should match
        let bn_gen_parsed_affine = bn::AffineG1::from_jacobian(bn_gen_parsed).unwrap();
        let bn_gen_native_affine = bn::AffineG1::from_jacobian(bn_gen_native).unwrap();

        let mut parsed_x = [0u8; 32];
        let mut native_x = [0u8; 32];
        let mut parsed_y = [0u8; 32];
        let mut native_y = [0u8; 32];
        bn_gen_parsed_affine.x().to_big_endian(&mut parsed_x).unwrap();
        bn_gen_native_affine.x().to_big_endian(&mut native_x).unwrap();
        bn_gen_parsed_affine.y().to_big_endian(&mut parsed_y).unwrap();
        bn_gen_native_affine.y().to_big_endian(&mut native_y).unwrap();

        println!("G1 gen: parsed x = {:?}", hex::encode(&parsed_x));
        println!("G1 gen: native x = {:?}", hex::encode(&native_x));
        println!("G1 gen: parsed y = {:?}", hex::encode(&parsed_y));
        println!("G1 gen: native y = {:?}", hex::encode(&native_y));
        println!("G1 generators x match: {}", parsed_x == native_x);
        println!("G1 generators y match: {}", parsed_y == native_y);

        // Test pairing with generators to verify the conversion
        let _ark_pairing_gg = Bn254::pairing(ark_gen, ark_bn254::G2Affine::generator());
        let bn_pairing_parsed = bn::pairing(bn_gen_parsed, bn::G2::one());
        let bn_pairing_native = bn::pairing(bn_gen_native, bn::G2::one());
        println!("bn pairing(parsed_gen, G2_gen) == bn pairing(native_gen, G2_gen)? {}", bn_pairing_parsed == bn_pairing_native);

        // Test doubling: G + G
        let bn_2g = bn_gen_native + bn_gen_native;
        let ark_2g: ark_bn254::G1Affine = (ark_gen + ark_gen).into();

        let bn_2g_affine = bn::AffineG1::from_jacobian(bn_2g).unwrap();
        let mut bn_2g_x = [0u8; 32];
        bn_2g_affine.x().to_big_endian(&mut bn_2g_x).unwrap();

        let ark_2g_x_le = ark_2g.x().unwrap().into_bigint().to_bytes_le();
        let mut ark_2g_x_be = [0u8; 32];
        ark_2g_x_be.copy_from_slice(&ark_2g_x_le[..32]);
        ark_2g_x_be.reverse();

        println!("2G: bn x = {:?}", hex::encode(&bn_2g_x));
        println!("2G: ark x = {:?}", hex::encode(&ark_2g_x_be));
        println!("2G matches: {}", bn_2g_x == ark_2g_x_be);

        // Test scalar mul with Fr = 2
        let bn_two = bn::Fr::from_str("2").unwrap();
        let bn_2g_scalar = bn_gen_native * bn_two;
        let bn_2g_scalar_affine = bn::AffineG1::from_jacobian(bn_2g_scalar).unwrap();
        let mut bn_2g_scalar_x = [0u8; 32];
        bn_2g_scalar_affine.x().to_big_endian(&mut bn_2g_scalar_x).unwrap();
        println!("G*2: bn x = {:?}", hex::encode(&bn_2g_scalar_x));
        println!("G*2 == G+G in bn? {}", bn_2g_scalar_x == bn_2g_x);

        // Convert proof points
        let bn_a = parse_g1_be(&ark_g1_to_gnark(&proof.a)).unwrap();
        let bn_b = parse_g2_be(&ark_g2_to_gnark(&proof.b)).unwrap();
        let bn_c = parse_g1_be(&ark_g1_to_gnark(&proof.c)).unwrap();

        // Convert VK points
        let bn_alpha = parse_g1_be(&ark_g1_to_gnark(&vk.alpha_g1)).unwrap();
        let bn_beta = parse_g2_be(&ark_g2_to_gnark(&vk.beta_g2)).unwrap();
        let bn_gamma = parse_g2_be(&ark_g2_to_gnark(&vk.gamma_g2)).unwrap();
        let bn_delta = parse_g2_be(&ark_g2_to_gnark(&vk.delta_g2)).unwrap();

        // Convert IC points
        let bn_ic0 = parse_g1_be(&ark_g1_to_gnark(&vk.gamma_abc_g1[0])).unwrap();
        let bn_ic1 = parse_g1_be(&ark_g1_to_gnark(&vk.gamma_abc_g1[1])).unwrap();

        // Debug: compare ic points
        let bn_ic0_affine = bn::AffineG1::from_jacobian(bn_ic0).unwrap();
        let mut ic0_x = [0u8; 32];
        bn_ic0_affine.x().to_big_endian(&mut ic0_x).unwrap();
        println!("bn IC[0].x: {:?}", hex::encode(&ic0_x));

        // Also print arkworks IC[0]
        use ark_ff::{PrimeField, BigInteger};
        let ark_ic0_x_le = vk.gamma_abc_g1[0].x().unwrap().into_bigint().to_bytes_le();
        let mut ark_ic0_x_be = [0u8; 32];
        ark_ic0_x_be.copy_from_slice(&ark_ic0_x_le[..32]);
        ark_ic0_x_be.reverse();
        println!("ark IC[0].x: {:?}", hex::encode(&ark_ic0_x_be));

        // Convert public input
        let ark_output_bytes = ark_fr_to_be(&output);
        println!("ark output (BE): {:?}", hex::encode(&ark_output_bytes));

        // Test different ways of creating Fr = 35
        let bn_input_from_str = bn::Fr::from_str("35").unwrap();
        let bn_input_from_slice = parse_fr_be(&ark_output_bytes).unwrap();

        // Scalar mul with both
        let test_from_str = bn::G1::one() * bn_input_from_str;
        let test_from_slice = bn::G1::one() * bn_input_from_slice;

        let test_str_affine = bn::AffineG1::from_jacobian(test_from_str).unwrap();
        let test_slice_affine = bn::AffineG1::from_jacobian(test_from_slice).unwrap();

        let mut test_str_x = [0u8; 32];
        let mut test_slice_x = [0u8; 32];
        test_str_affine.x().to_big_endian(&mut test_str_x).unwrap();
        test_slice_affine.x().to_big_endian(&mut test_slice_x).unwrap();

        println!("bn G*35 (from_str), x: {:?}", hex::encode(&test_str_x));
        println!("bn G*35 (from_slice), x: {:?}", hex::encode(&test_slice_x));
        println!("from_str == from_slice? {}", test_str_x == test_slice_x);

        // Also do the same in arkworks
        let ark_test = ark_bn254::G1Affine::generator() * output;
        let ark_test_affine: ark_bn254::G1Affine = ark_test.into();
        let ark_test_x_le = ark_test_affine.x().unwrap().into_bigint().to_bytes_le();
        let mut ark_test_x_be = [0u8; 32];
        ark_test_x_be.copy_from_slice(&ark_test_x_le[..32]);
        ark_test_x_be.reverse();
        println!("ark G*35, x: {:?}", hex::encode(&ark_test_x_be));
        println!("bn from_str == ark? {}", test_str_x == ark_test_x_be);

        let bn_input = bn_input_from_slice;

        // Compute L = ic0 + ic1 * input
        let bn_l = bn_ic0 + bn_ic1 * bn_input;

        // Let's test each pairing individually by comparing arkworks vs bn

        // First, verify arkworks L computation
        let ark_l = vk.gamma_abc_g1[0] + vk.gamma_abc_g1[1] * output;
        // Convert arkworks L to bn
        let ark_l_gnark = ark_g1_to_gnark(&ark_l.into());
        let bn_l_from_ark = parse_g1_be(&ark_l_gnark).unwrap();

        // Compare with bn_l computed from bn operations
        let bn_l_affine = bn::AffineG1::from_jacobian(bn_l).unwrap();
        let bn_l_from_ark_affine = bn::AffineG1::from_jacobian(bn_l_from_ark).unwrap();

        let mut bn_l_x = [0u8; 32];
        let mut bn_l_ark_x = [0u8; 32];
        bn_l_affine.x().to_big_endian(&mut bn_l_x).unwrap();
        bn_l_from_ark_affine.x().to_big_endian(&mut bn_l_ark_x).unwrap();

        println!("bn L (from bn ops) x: {:?}", hex::encode(&bn_l_x));
        println!("bn L (from ark) x:    {:?}", hex::encode(&bn_l_ark_x));
        println!("L values match: {}", bn_l_x == bn_l_ark_x);

        // Now compute each pairing term individually
        let e_ab = bn::pairing(bn_a, bn_b);
        let e_alpha_beta = bn::pairing(bn_alpha, bn_beta);
        let e_l_gamma = bn::pairing(bn_l, bn_gamma);
        let e_c_delta = bn::pairing(bn_c, bn_delta);

        // Also compute using arkworks-converted L
        let e_l_gamma_ark = bn::pairing(bn_l_from_ark, bn_gamma);
        println!("e(L_bn, γ) == e(L_ark, γ)? {}", e_l_gamma == e_l_gamma_ark);

        // The equation is: e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)
        let rhs = e_alpha_beta * e_l_gamma * e_c_delta;
        println!("bn: e(A,B) == e(α,β) * e(L,γ) * e(C,δ)? {}", e_ab == rhs);

        // Let's also check if the individual terms are non-trivial
        println!("e(A,B) is one? {}", e_ab == bn::Gt::one());
        println!("e(α,β) is one? {}", e_alpha_beta == bn::Gt::one());
        println!("e(L,γ) is one? {}", e_l_gamma == bn::Gt::one());
        println!("e(C,δ) is one? {}", e_c_delta == bn::Gt::one());

        // Try the rearranged form with negations in G1
        let neg_alpha = -bn_alpha;
        let neg_l = -bn_l;
        let neg_c = -bn_c;

        let pairs = [
            (bn_a, bn_b),
            (neg_alpha, bn_beta),
            (neg_l, bn_gamma),
            (neg_c, bn_delta),
        ];
        let batch_result = bn::pairing_batch(&pairs);
        println!("bn batch pairing == 1? {}", batch_result == bn::Gt::one());

        assert!(batch_result == bn::Gt::one(), "bn verification failed");

        // Now verify with our full implementation
        let gnark_proof_bytes = ark_proof_to_gnark(&proof);
        let gnark_vk_bytes = ark_vk_to_gnark(&vk);
        let public_inputs = vec![ark_fr_to_be(&output)];

        let result = verify_bytes(&gnark_vk_bytes, &gnark_proof_bytes, &public_inputs);
        println!("Full verify_bytes result: {:?}", result);
        assert!(result.is_ok(), "Verification returned error: {:?}", result);
        assert!(result.unwrap(), "Proof verification failed");
    }

    #[test]
    fn test_groth16_verification_invalid_proof() {
        let mut rng = StdRng::seed_from_u64(42);

        // Create circuit with x = 3
        let circuit = CubicCircuit { x: Some(ArkFr::from(3u64)) };

        // Generate proving and verifying keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            CubicCircuit { x: None },
            &mut rng,
        ).unwrap();

        // Generate proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Use wrong public input (36 instead of 35)
        let wrong_output = ArkFr::from(36u64);

        // Convert to gnark format
        let gnark_proof_bytes = ark_proof_to_gnark(&proof);
        let gnark_vk_bytes = ark_vk_to_gnark(&vk);
        let wrong_public_inputs = vec![ark_fr_to_be(&wrong_output)];

        // Verify should fail
        let result = verify_bytes(&gnark_vk_bytes, &gnark_proof_bytes, &wrong_public_inputs);
        assert!(result.is_ok(), "Verification returned error: {:?}", result);
        assert!(!result.unwrap(), "Invalid proof should not verify");
    }

    #[test]
    fn test_groth16_verification_multiple_inputs() {
        // Test with different x values
        let test_cases = vec![
            (0u64, 5u64),    // 0^3 + 0 + 5 = 5
            (1u64, 7u64),    // 1^3 + 1 + 5 = 7
            (2u64, 15u64),   // 2^3 + 2 + 5 = 15
            (5u64, 135u64),  // 5^3 + 5 + 5 = 135
        ];

        let mut rng = StdRng::seed_from_u64(42);

        // Generate keys once
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            CubicCircuit { x: None },
            &mut rng,
        ).unwrap();

        let gnark_vk_bytes = ark_vk_to_gnark(&vk);

        for (x_val, expected_out) in test_cases {
            let circuit = CubicCircuit { x: Some(ArkFr::from(x_val)) };
            let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

            let output = ArkFr::from(expected_out);
            let gnark_proof_bytes = ark_proof_to_gnark(&proof);
            let public_inputs = vec![ark_fr_to_be(&output)];

            let result = verify_bytes(&gnark_vk_bytes, &gnark_proof_bytes, &public_inputs);
            assert!(
                result.is_ok() && result.unwrap(),
                "Failed for x={}, expected_out={}",
                x_val, expected_out
            );
        }
    }
}
