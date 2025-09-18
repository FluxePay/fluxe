use fluxe_core::{
    crypto::{
        pedersen::{PedersenCommitment, PedersenParams, PedersenRandomness},
        poseidon_hash,
    },
    data_structures::{ComplianceState, Note, ZkObject, CallbackEntry},
    merkle::{CommitmentTree, NullifierTree, IncrementalTree, SortedTree},
    state_manager::{StateManager, TransactionProcessor},
    types::*,
};
use ark_bls12_381::Fr as F;
use ark_ff::{UniformRand, Zero};
use rand::thread_rng;

#[test]
fn test_end_to_end_deposit_transfer_withdraw() {
    let mut rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    let mut state = StateManager::new();
    
    // Setup users
    let alice_addr = F::rand(&mut rng);
    let bob_addr = F::rand(&mut rng);
    let alice_nk = F::rand(&mut rng);
    
    // Step 1: Deposit (Mint)
    let deposit_amount = 10000u64;
    let asset_type = 1; // USDC
    
    let alice_rand = PedersenRandomness::new(&mut rng);
    let alice_comm = PedersenCommitment::commit(&params, deposit_amount, &alice_rand);
    let alice_note = Note::new(asset_type, alice_comm, alice_addr, [1u8; 32], 0);
    
    state.process_mint(asset_type, deposit_amount as u128, vec![alice_note.clone()])
        .expect("Mint failed");
    
    assert_eq!(state.get_supply(asset_type), deposit_amount as u128);
    
    // Step 2: Transfer
    let alice_nullifier = alice_note.nullifier(&alice_nk);
    
    // Create output notes
    let alice_change = 6000u64;
    let bob_payment = 4000u64;
    
    let alice_change_rand = PedersenRandomness::new(&mut rng);
    let alice_change_comm = PedersenCommitment::commit(&params, alice_change, &alice_change_rand);
    let alice_change_note = Note::new(asset_type, alice_change_comm, alice_addr, [2u8; 32], 0);
    
    let bob_rand = PedersenRandomness::new(&mut rng);
    let bob_comm = PedersenCommitment::commit(&params, bob_payment, &bob_rand);
    let bob_note = Note::new(asset_type, bob_comm, bob_addr, [3u8; 32], 0);
    
    state.process_transfer(
        vec![alice_nullifier],
        vec![alice_change_note, bob_note.clone()],
    ).expect("Transfer failed");
    
    // Supply should remain unchanged
    assert_eq!(state.get_supply(asset_type), deposit_amount as u128);
    
    // Step 3: Withdraw (Burn)
    let bob_nk = F::rand(&mut rng);
    let bob_nullifier = bob_note.nullifier(&bob_nk);
    let withdraw_amount = 2000u128;
    
    state.process_burn(asset_type, withdraw_amount, bob_nullifier)
        .expect("Burn failed");
    
    // Supply should decrease
    assert_eq!(state.get_supply(asset_type), (deposit_amount as u128) - withdraw_amount);
}

#[test]
fn test_double_spend_prevention() {
    let mut rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    let mut state = StateManager::new();
    
    // Create a note
    let owner = F::rand(&mut rng);
    let value_rand = PedersenRandomness::new(&mut rng);
    let v_comm = PedersenCommitment::commit(&params, 1000, &value_rand);
    let note = Note::new(1, v_comm, owner, [1u8; 32], 0);
    
    // Mint it
    state.process_mint(1, 1000, vec![note.clone()]).unwrap();
    
    // Spend it once
    let nk = F::rand(&mut rng);
    let nullifier = note.nullifier(&nk);
    
    let result1 = state.process_burn(1, 500, nullifier);
    assert!(result1.is_ok());
    
    // Try to spend again (should fail)
    let result2 = state.process_burn(1, 300, nullifier);
    assert!(matches!(result2, Err(FluxeError::DoubleSpend(_))));
}

#[test]
fn test_compliance_limits() {
    let mut compliance = ComplianceState::new_verified(1); // Basic KYC
    
    // Test within limits
    assert!(compliance.can_transact(5000, 0, 0, 0).is_ok());
    
    // Test exceeding daily limit
    assert!(compliance.can_transact(15000, 0, 0, 0).is_err());
    
    // Test with existing spending
    assert!(compliance.can_transact(3000, 8000, 8000, 8000).is_err()); // Would exceed daily
    
    // Test freeze
    compliance.freeze();
    assert!(compliance.can_transact(1, 0, 0, 0).is_err());
    
    // Test unfreeze with new limits
    compliance.unfreeze(20000, 100000, 500000);
    assert!(compliance.can_transact(15000, 0, 0, 0).is_ok());
}

#[test]
fn test_merkle_tree_operations() {
    let mut rng = thread_rng();
    
    // Test Incremental Tree
    let mut inc_tree = IncrementalTree::new(8);
    let values: Vec<F> = (0..10).map(|_| F::rand(&mut rng)).collect();
    
    let paths: Vec<_> = values.iter().map(|&v| inc_tree.append(v)).collect();
    
    // Verify all paths
    for path in &paths {
        assert!(path.verify(&inc_tree.root(), &inc_tree.params));
    }
    
    // Test Sorted Tree
    let mut sorted_tree = SortedTree::new(8);
    let keys: Vec<F> = (0..5).map(|i| F::from(i * 100)).collect();
    
    for key in &keys {
        sorted_tree.insert(*key).expect("Insert failed");
    }
    
    // Test membership
    for key in &keys {
        assert!(sorted_tree.contains(key));
    }
    
    // Test non-membership
    let non_member = F::from(150);
    assert!(!sorted_tree.contains(&non_member));
    
    let non_member_proof = sorted_tree.prove_non_membership(non_member)
        .expect("Non-membership proof failed");
    assert!(non_member_proof.verify(&sorted_tree.root(), &sorted_tree.params));
}

#[test]
fn test_callback_mechanism() {
    let mut rng = thread_rng();
    let mut compliance = ComplianceState::new_verified(2);
    let mut zk_obj = ZkObject::new(&compliance);
    
    // Create callback entry
    let provider_key = F::rand(&mut rng);
    let callback = CallbackEntry::new(
        1, // method_id for freeze
        1000, // expiry time
        provider_key,
    );
    
    let initial_serial = zk_obj.serial;
    zk_obj.add_callback(&callback);
    
    // Serial should increment
    assert_eq!(zk_obj.serial, initial_serial + 1);
    
    // Check expiry
    assert!(!callback.is_expired(999));
    assert!(!callback.is_expired(1000));
    assert!(callback.is_expired(1001));
}

#[test]
fn test_pool_policies() {
    use fluxe_core::data_structures::PoolRule;
    
    let mut rule = PoolRule::new(1);
    rule.outbound_allow = vec![2, 3];
    rule.inbound_allow = vec![2, 4];
    rule.max_per_tx = 10000;
    
    // Test allowed transfers
    assert!(rule.can_transfer(1, 2, 5000)); // Pool 1 -> 2, allowed outbound
    assert!(rule.can_transfer(2, 1, 5000)); // Pool 2 -> 1, allowed inbound
    
    // Test disallowed transfers
    assert!(!rule.can_transfer(1, 5, 5000)); // Pool 1 -> 5, not in outbound list
    assert!(!rule.can_transfer(3, 1, 5000)); // Pool 3 -> 1, not in inbound list
    
    // Test amount limit
    assert!(!rule.can_transfer(1, 2, 15000)); // Exceeds max_per_tx
}

#[test]
fn test_lineage_tracking() {
    let mut rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    
    // Create parent notes
    let parent1_comm = PedersenCommitment::commit(&params, 500, &PedersenRandomness::new(&mut rng));
    let parent1 = Note::new(1, parent1_comm, F::rand(&mut rng), [1u8; 32], 0);
    
    let parent2_comm = PedersenCommitment::commit(&params, 300, &PedersenRandomness::new(&mut rng));
    let parent2 = Note::new(1, parent2_comm, F::rand(&mut rng), [2u8; 32], 0);
    
    // Create child note with lineage
    let child_comm = PedersenCommitment::commit(&params, 800, &PedersenRandomness::new(&mut rng));
    let mut child = Note::new(1, child_comm, F::rand(&mut rng), [3u8; 32], 0);
    
    // Update lineage
    let context = F::from(12345); // Some context value
    child.update_lineage(&[parent1.lineage_hash, parent2.lineage_hash], &context);
    
    // Lineage should be updated
    assert_ne!(child.lineage_hash, F::zero());
}

#[test]
fn test_state_roots_consistency() {
    let mut state = StateManager::new();
    let initial_roots = state.roots.clone();
    
    // Any operation should change roots
    let mut rng = thread_rng();
    let params = PedersenParams::setup_value_commitment();
    
    let v_comm = PedersenCommitment::commit(&params, 100, &PedersenRandomness::new(&mut rng));
    let note = Note::new(1, v_comm, F::rand(&mut rng), [1u8; 32], 0);
    
    state.process_mint(1, 100, vec![note]).unwrap();
    
    let new_roots = state.roots.clone();
    
    // CMT_ROOT should change
    assert_ne!(initial_roots.cmt_root, new_roots.cmt_root);
    
    // INGRESS_ROOT should change
    assert_ne!(initial_roots.ingress_root, new_roots.ingress_root);
    
    // NFT_ROOT should remain same (no nullifiers added)
    assert_eq!(initial_roots.nft_root, new_roots.nft_root);
}