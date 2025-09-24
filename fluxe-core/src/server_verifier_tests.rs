#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        data_structures::{Note, IngressReceipt, ExitReceipt},
        merkle::IncrementalTree,
        state_manager::StateManager,
        crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
    };
    use ark_bls12_381::{Bls12_381, Fr as F};
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
    use ark_std::test_rng;

    // Dummy circuit for testing
    struct DummyCircuit;
    impl ConstraintSynthesizer<F> for DummyCircuit {
        fn generate_constraints(
            self,
            _cs: ConstraintSystemRef<F>,
        ) -> Result<(), ark_relations::r1cs::SynthesisError> {
            Ok(())
        }
    }

    fn setup_test_verifier() -> (ServerVerifier, ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
        let mut rng = test_rng();
        let (pk, vk) = Groth16::<Bls12_381>::setup(DummyCircuit, &mut rng).unwrap();
        
        let state = StateManager::new();
        let verifier = ServerVerifier::new(
            state,
            vk.clone(),
            vk.clone(),
            vk.clone(),
            vk.clone(),
        );
        
        (verifier, pk, vk)
    }

    #[test]
    fn test_deterministic_batch_replay() {
        let (mut verifier, pk, _vk) = setup_test_verifier();
        let mut rng = test_rng();
        let params = PedersenParams::setup_value_commitment();

        // Create a mint transaction
        let value = 1000u64;
        let randomness = F::from(42u64);
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        let note_out = Note::new(
            1, // asset_type
            v_comm,
            F::from(123u64), // owner_addr
            [0u8; 32],
            1, // chain_hint
        );
        
        let ingress_receipt = IngressReceipt::new(
            1, // asset_type
            1000u128.into(),
            note_out.commitment(),
            1, // nonce
        );

        // Get initial roots
        let old_roots = verifier.state.get_roots();
        
        // Manually compute what the new roots should be after mint
        let mut expected_state = verifier.state.clone();
        expected_state.ingress_tree.append(ingress_receipt.hash());
        expected_state.cmt_tree.append(note_out.commitment());
        let expected_new_roots = expected_state.get_roots();

        // Create verified transaction
        let proof = Groth16::<Bls12_381>::prove(&pk, DummyCircuit, &mut rng).unwrap();
        let tx = VerifiedTransaction {
            tx_type: TransactionType::Mint,
            proof,
            public_inputs: vec![
                old_roots.cmt_root,
                expected_new_roots.cmt_root,
                old_roots.ingress_root,
                expected_new_roots.ingress_root,
            ],
            old_roots: old_roots.clone(),
            new_roots: expected_new_roots.clone(),
            transaction_data: TransactionData::Mint {
                asset_type: 1,
                amount: 1000u128.into(),
                notes_out: vec![note_out],
                ingress_receipt,
            },
        };

        // Add transaction and process batch
        verifier.add_transaction(tx).unwrap();
        let block = verifier.process_batch().unwrap();

        // Verify that the final roots match expected
        assert_eq!(block.new_roots, expected_new_roots);
        assert_eq!(block.prev_roots, old_roots);
        
        // Verify supply was updated
        assert_eq!(
            verifier.state.supply.get(&1).unwrap().value(),
            1000u128
        );
    }

    #[test]
    fn test_double_spend_detection() {
        let (mut verifier, pk, _vk) = setup_test_verifier();
        let mut rng = test_rng();
        
        let nullifier = F::from(999u64);
        let old_roots = verifier.state.get_roots();
        
        // Create two transfers with the same nullifier
        let proof1 = Groth16::<Bls12_381>::prove(&pk, DummyCircuit, &mut rng).unwrap();
        let tx1 = VerifiedTransaction {
            tx_type: TransactionType::Transfer,
            proof: proof1,
            public_inputs: vec![],
            old_roots: old_roots.clone(),
            new_roots: old_roots.clone(),
            transaction_data: TransactionData::Transfer {
                nullifiers: vec![nullifier],
                notes_out: vec![],
            },
        };

        let proof2 = Groth16::<Bls12_381>::prove(&pk, DummyCircuit, &mut rng).unwrap();
        let tx2 = VerifiedTransaction {
            tx_type: TransactionType::Transfer,
            proof: proof2,
            public_inputs: vec![],
            old_roots: old_roots.clone(),
            new_roots: old_roots.clone(),
            transaction_data: TransactionData::Transfer {
                nullifiers: vec![nullifier],
                notes_out: vec![],
            },
        };

        // Add both transactions
        verifier.add_transaction(tx1).unwrap();
        verifier.add_transaction(tx2).unwrap();
        
        // Processing should fail due to double spend
        let result = verifier.process_batch();
        assert!(result.is_err());
        
        match result.unwrap_err() {
            FluxeError::DoubleSpend(nf) => assert_eq!(nf, nullifier),
            _ => panic!("Expected DoubleSpend error"),
        }
    }

    #[test]
    fn test_transaction_ordering() {
        let (mut verifier, pk, _vk) = setup_test_verifier();
        let mut rng = test_rng();
        let params = PedersenParams::setup_value_commitment();

        // Create multiple transaction types to verify ordering
        
        // 1. Mint transaction
        let mint_note = Note::new(
            1,
            PedersenCommitment::commit(
                &params,
                100u64,
                &PedersenRandomness { r: F::from(1u64) },
            ),
            F::from(1u64),
            [1u8; 32],
            1,
        );
        
        let ingress = IngressReceipt::new(
            1,
            100u128.into(),
            mint_note.commitment(),
            1,
        );

        // 2. Transfer transaction
        let transfer_note = Note::new(
            1,
            PedersenCommitment::commit(
                &params,
                50u64,
                &PedersenRandomness { r: F::from(2u64) },
            ),
            F::from(2u64),
            [2u8; 32],
            1,
        );

        // 3. Burn transaction
        let burn_nf = F::from(888u64);
        let exit = ExitReceipt::new(
            1,
            50u128.into(),
            burn_nf,
            1,
        );

        let old_roots = verifier.state.get_roots();

        // Create transactions (in mixed order to test reordering)
        let burn_tx = VerifiedTransaction {
            tx_type: TransactionType::Burn,
            proof: Groth16::<Bls12_381>::prove(&pk, DummyCircuit, &mut rng).unwrap(),
            public_inputs: vec![],
            old_roots: old_roots.clone(),
            new_roots: old_roots.clone(),
            transaction_data: TransactionData::Burn {
                asset_type: 1,
                amount: 50u128.into(),
                nullifier: burn_nf,
                exit_receipt: exit,
            },
        };

        let mint_tx = VerifiedTransaction {
            tx_type: TransactionType::Mint,
            proof: Groth16::<Bls12_381>::prove(&pk, DummyCircuit, &mut rng).unwrap(),
            public_inputs: vec![],
            old_roots: old_roots.clone(),
            new_roots: old_roots.clone(),
            transaction_data: TransactionData::Mint {
                asset_type: 1,
                amount: 100u128.into(),
                notes_out: vec![mint_note],
                ingress_receipt: ingress,
            },
        };

        let transfer_tx = VerifiedTransaction {
            tx_type: TransactionType::Transfer,
            proof: Groth16::<Bls12_381>::prove(&pk, DummyCircuit, &mut rng).unwrap(),
            public_inputs: vec![],
            old_roots: old_roots.clone(),
            new_roots: old_roots.clone(),
            transaction_data: TransactionData::Transfer {
                nullifiers: vec![F::from(777u64)],
                notes_out: vec![transfer_note],
            },
        };

        // Add in mixed order
        verifier.add_transaction(burn_tx).unwrap();
        verifier.add_transaction(mint_tx).unwrap();
        verifier.add_transaction(transfer_tx).unwrap();

        // Process should succeed despite mixed order
        let block = verifier.process_batch().unwrap();
        
        // Verify final state
        assert!(verifier.state.nft_tree.contains(&burn_nf));
        assert!(verifier.state.nft_tree.contains(&F::from(777u64)));
        assert_eq!(
            verifier.state.supply.get(&1).unwrap().value(),
            50u128 // 100 minted - 50 burned
        );
        
        // Verify roots were updated
        assert_ne!(block.new_roots.cmt_root, block.prev_roots.cmt_root);
        assert_ne!(block.new_roots.nft_root, block.prev_roots.nft_root);
        assert_ne!(block.new_roots.ingress_root, block.prev_roots.ingress_root);
        assert_ne!(block.new_roots.exit_root, block.prev_roots.exit_root);
    }
}