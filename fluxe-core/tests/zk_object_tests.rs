use fluxe_core::data_structures::{
    ZkObject, ComplianceState, CallbackEntry, CallbackMethod,
    CallbackInvocation, CallbackPackage
};
use fluxe_core::types::*;
use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;

#[test]
fn test_zk_object_creation() {
    let state = ComplianceState::new_verified(1);
    let obj = ZkObject::new(&state);
    
    assert_eq!(obj.serial, 0);
    assert_eq!(obj.state_hash, state.hash());
    assert_eq!(obj.cb_head_hash, F::from(0));
}

#[test]
fn test_zk_object_commitment() {
    let state = ComplianceState::new_verified(1);
    let obj = ZkObject::new(&state);
    let mut rng = thread_rng();
    
    // Generate commitment
    let commitment1 = obj.commitment(&mut rng);
    
    // Commitment should be different with different randomness
    let commitment2 = obj.commitment(&mut rng);
    assert_ne!(commitment1, commitment2);
    
    // Same randomness produces same commitment
    let r_obj = F::rand(&mut rng);
    let commitment3 = obj.commitment_with_randomness(&r_obj);
    let commitment4 = obj.commitment_with_randomness(&r_obj);
    assert_eq!(commitment3, commitment4);
}

#[test]
fn test_add_callback() {
    let state = ComplianceState::new_verified(1);
    let mut obj = ZkObject::new(&state);
    let mut rng = thread_rng();
    
    let initial_serial = obj.serial;
    let initial_cb_hash = obj.cb_head_hash;
    
    // Add a callback
    let callback = CallbackEntry::new(
        1, // method_id
        1000, // expiry
        F::rand(&mut rng), // provider_key
    );
    
    obj.add_callback(&callback);
    
    // Serial should increment
    assert_eq!(obj.serial, initial_serial + 1);
    
    // Callback hash should change
    assert_ne!(obj.cb_head_hash, initial_cb_hash);
}

#[test]
fn test_process_callback() {
    let mut state = ComplianceState::new_verified(1);
    let mut obj = ZkObject::new(&state);
    let mut rng = thread_rng();
    
    let callback = CallbackEntry::new(1, 1000, F::rand(&mut rng));
    
    // Process callback with new state
    state.risk_score = 50;
    let new_state_hash = state.hash();
    
    let initial_serial = obj.serial;
    obj.process_callback(new_state_hash, &callback);
    
    // Serial should increment
    assert_eq!(obj.serial, initial_serial + 1);
    
    // State hash should update
    assert_eq!(obj.state_hash, new_state_hash);
}

#[test]
fn test_can_spend_valid() {
    let state = ComplianceState::new_verified(1);
    let obj = ZkObject::new(&state);
    
    // Should be able to spend with matching state
    assert!(obj.can_spend(&state, 100).is_ok());
}

#[test]
fn test_can_spend_frozen() {
    let mut state = ComplianceState::new_verified(1);
    state.freeze();
    let obj = ZkObject::new(&state);
    
    // Cannot spend when frozen
    assert!(obj.can_spend(&state, 100).is_err());
}

#[test]
fn test_can_spend_state_mismatch() {
    let state1 = ComplianceState::new_verified(1);
    let obj = ZkObject::new(&state1);
    
    let mut state2 = ComplianceState::new_verified(1);
    state2.risk_score = 100;
    
    // Cannot spend with mismatched state
    assert!(obj.can_spend(&state2, 100).is_err());
}

#[test]
fn test_callback_entry() {
    let mut rng = thread_rng();
    let provider_key = F::rand(&mut rng);
    
    let entry = CallbackEntry::new(5, 2000, provider_key);
    
    assert_eq!(entry.method_id, 5);
    assert_eq!(entry.expiry, 2000);
    assert_eq!(entry.provider_key, provider_key);
    
    // Hash should be deterministic
    let hash1 = entry.hash();
    let hash2 = entry.hash();
    assert_eq!(hash1, hash2);
    
    // Ticket should be deterministic
    let ticket1 = entry.ticket();
    let ticket2 = entry.ticket();
    assert_eq!(ticket1, ticket2);
}

#[test]
fn test_callback_expiry() {
    let mut rng = thread_rng();
    let entry = CallbackEntry::new(1, 1000, F::rand(&mut rng));
    
    assert!(!entry.is_expired(999));
    assert!(!entry.is_expired(1000));
    assert!(entry.is_expired(1001));
}

#[test]
fn test_callback_methods() {
    let mut state = ComplianceState::new_verified(1);
    
    // Test freeze
    let freeze = CallbackMethod::FreezeAssets;
    assert_eq!(freeze.id(), 1);
    freeze.execute(&mut state).unwrap();
    assert!(state.frozen);
    
    // Test unfreeze
    let unfreeze = CallbackMethod::UnfreezeAssets {
        daily_limit: Amount::from(5000u128),
        monthly_limit: Amount::from(25000u128),
        yearly_limit: Amount::from(100000u128),
    };
    assert_eq!(unfreeze.id(), 2);
    unfreeze.execute(&mut state).unwrap();
    assert!(!state.frozen);
    assert_eq!(state.daily_limit, Amount::from(5000u128));
    
    // Test risk score update
    let update_risk = CallbackMethod::UpdateRiskScore(75);
    assert_eq!(update_risk.id(), 3);
    update_risk.execute(&mut state).unwrap();
    assert_eq!(state.risk_score, 75);
    
    // Test compliance level update
    let update_level = CallbackMethod::UpdateComplianceLevel(2);
    assert_eq!(update_level.id(), 4);
    update_level.execute(&mut state).unwrap();
    assert_eq!(state.level, 2);
    
    // Test document request
    let request_docs = CallbackMethod::RequestDocuments;
    assert_eq!(request_docs.id(), 5);
    assert!(request_docs.execute(&mut state).is_ok());
}

#[test]
fn test_callback_invocation() {
    use fluxe_core::crypto::SchnorrSecretKey;
    let mut rng = thread_rng();
    
    // Create provider key pair
    let provider_sk = SchnorrSecretKey::random(&mut rng);
    let provider_pk = provider_sk.public_key();
    let ticket = provider_pk.to_field();
    
    let payload = vec![1, 2, 3, 4, 5];
    let timestamp = 1234567890;
    
    let mut invocation = CallbackInvocation::new(ticket, payload.clone(), timestamp);
    
    assert_eq!(invocation.ticket, ticket);
    assert_eq!(invocation.payload, payload);
    assert_eq!(invocation.timestamp, timestamp);
    
    // Sign the invocation to make verification pass
    invocation.sign(&provider_sk);
    
    // Verify should return true with correct key
    assert!(invocation.verify(&provider_pk));
    
    // To field conversion should be deterministic
    let field1 = invocation.to_field();
    let field2 = invocation.to_field();
    assert_eq!(field1, field2);
}

#[test]
fn test_callback_package() {
    let package = CallbackPackage::new(3, 5000);
    
    assert_eq!(package.method_id, 3);
    assert_eq!(package.expiry, 5000);
    
    // Commitment should be deterministic
    let commitment1 = package.commitment();
    let commitment2 = package.commitment();
    assert_eq!(commitment1, commitment2);
}

#[test]
fn test_multiple_callbacks() {
    let state = ComplianceState::new_verified(1);
    let mut obj = ZkObject::new(&state);
    let mut rng = thread_rng();
    
    let initial_hash = obj.cb_head_hash;
    
    // Add multiple callbacks
    for i in 0..5 {
        let callback = CallbackEntry::new(
            i,
            1000 + i as u64,
            F::rand(&mut rng),
        );
        obj.add_callback(&callback);
        
        // Serial should increment each time
        assert_eq!(obj.serial, (i + 1) as u64);
        
        // Hash should change each time
        assert_ne!(obj.cb_head_hash, initial_hash);
    }
    
    assert_eq!(obj.serial, 5);
}

#[test]
fn test_callback_chain_consistency() {
    let state = ComplianceState::new_verified(1);
    let mut obj1 = ZkObject::new(&state);
    let mut obj2 = ZkObject::new(&state);
    let rng = thread_rng();
    
    // Add same callbacks to both objects
    let callbacks: Vec<CallbackEntry> = (0..3).map(|i| {
        CallbackEntry::new(i, 1000 + i as u64, F::from(i as u64))
    }).collect();
    
    for callback in &callbacks {
        obj1.add_callback(callback);
        obj2.add_callback(callback);
    }
    
    // Should have same state
    assert_eq!(obj1.serial, obj2.serial);
    assert_eq!(obj1.cb_head_hash, obj2.cb_head_hash);
}

#[test]
fn test_callback_entry_different_providers() {
    let entry1 = CallbackEntry::new(1, 1000, F::from(111u64));
    let entry2 = CallbackEntry::new(1, 1000, F::from(222u64));
    
    // Same method and expiry but different providers
    assert_ne!(entry1.hash(), entry2.hash());
    assert_ne!(entry1.ticket(), entry2.ticket());
}

#[test]
fn test_state_transitions_with_callbacks() {
    let mut state = ComplianceState::new_verified(1);
    let mut obj = ZkObject::new(&state);
    
    // Simulate compliance provider callback flow
    let callback = CallbackEntry::new(
        CallbackMethod::UpdateRiskScore(50).id(),
        2000,
        F::from(999u64),
    );
    
    obj.add_callback(&callback);
    
    // Later, process the callback
    state.risk_score = 50;
    obj.process_callback(state.hash(), &callback);
    
    // Object should reflect the update
    assert_eq!(obj.state_hash, state.hash());
    assert_eq!(obj.serial, 2); // Incremented twice
}