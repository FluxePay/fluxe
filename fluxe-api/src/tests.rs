use crate::api::*;
use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_groth16::Proof;

#[cfg(test)]
mod api_tests {
    use super::*;

    #[test]
    fn test_parse_field_from_hex() {
        // Test valid hex with 0x prefix
        let hex = "0x0123456789abcdef";
        let result = parse_field_from_hex(hex);
        assert!(result.is_ok());

        // Test valid hex without prefix
        let hex = "0123456789abcdef";
        let result = parse_field_from_hex(hex);
        assert!(result.is_ok());

        // Test invalid hex
        let hex = "0xGGGG";
        let result = parse_field_from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_public_inputs() {
        // Test valid inputs
        let inputs = vec![
            "0x01".to_string(),
            "0x02".to_string(),
            "0x03".to_string(),
        ];
        let result = parse_public_inputs(&inputs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);

        // Test empty inputs
        let inputs = vec![];
        let result = parse_public_inputs(&inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_field_to_hex_roundtrip() {
        use ark_ff::UniformRand;
        let mut rng = ark_std::test_rng();
        
        // Test roundtrip conversion
        let field = Fr::rand(&mut rng);
        let hex = field_to_hex(&field);
        let parsed = parse_field_from_hex(&hex).unwrap();
        assert_eq!(field, parsed);
    }

    #[test]
    fn test_compute_notes_commitment() {
        use fluxe_core::data_structures::Note;
        use fluxe_core::crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness};
        use fluxe_core::crypto::poseidon_hash;

        let params = PedersenParams::setup_value_commitment();
        
        // Create test notes
        let mut notes = Vec::new();
        for i in 0..3 {
            let value = 100u64;
            let randomness = Fr::from(42u64 + i);
            let v_comm = PedersenCommitment::commit(
                &params,
                value,
                &PedersenRandomness { r: randomness },
            );
            
            let note = Note::new(
                1, // asset_type
                v_comm,
                Fr::from(123u64), // owner_addr
                [0u8; 32], // psi
                1, // chain_hint
            );
            notes.push(note);
        }

        // Compute commitment
        let commitment = compute_notes_commitment(&notes);

        // Verify it matches manual computation
        let mut expected = Fr::from(0u64);
        for note in &notes {
            let cm = note.commitment();
            expected = poseidon_hash(&[expected, cm]);
        }
        
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_convert_serializable_notes() {
        let serializable_notes = vec![
            SerializableNote {
                asset_type: 1,
                owner_addr: "0x123".to_string(),
                psi: [1u8; 32],
                chain_hint: 1,
                pool_id: 0,
            },
            SerializableNote {
                asset_type: 2,
                owner_addr: "0x456".to_string(),
                psi: [2u8; 32],
                chain_hint: 2,
                pool_id: 1,
            },
        ];

        let result = convert_serializable_notes(&serializable_notes);
        assert!(result.is_ok());
        
        let notes = result.unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].asset_type, 1);
        assert_eq!(notes[1].asset_type, 2);
    }

    #[test]
    fn test_proof_parsing() {
        use ark_groth16::{Proof, ProvingKey, VerifyingKey};
        use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
        use ark_bls12_381::Bls12_381;

        // Create a dummy circuit for testing
        struct DummyCircuit;
        impl ConstraintSynthesizer<Fr> for DummyCircuit {
            fn generate_constraints(
                self,
                cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
            ) -> Result<(), ark_relations::r1cs::SynthesisError> {
                Ok(())
            }
        }

        // Generate a proof
        let mut rng = ark_std::test_rng();
        let (pk, _vk) = ark_groth16::Groth16::<Bls12_381>::setup(
            DummyCircuit,
            &mut rng
        ).unwrap();
        
        let proof = ark_groth16::Groth16::<Bls12_381>::prove(
            &pk,
            DummyCircuit,
            &mut rng
        ).unwrap();

        // Serialize the proof
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        // Test parsing
        let parsed_proof = parse_proof_from_bytes(&proof_bytes);
        assert!(parsed_proof.is_ok());
        
        // Verify it matches the original
        let parsed = parsed_proof.unwrap();
        let mut parsed_bytes = Vec::new();
        parsed.serialize_compressed(&mut parsed_bytes).unwrap();
        assert_eq!(proof_bytes, parsed_bytes);
    }
}