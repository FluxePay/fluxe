use fluxe_core::data_structures::{ComplianceState, PoolRule, SanctionedIdentifier};
use fluxe_core::types::*;
use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;

#[test]
fn test_compliance_state_new() {
    let state = ComplianceState::new();
    
    assert_eq!(state.level, 0);
    assert_eq!(state.risk_score, 0);
    assert!(!state.frozen);
    assert_eq!(state.daily_limit, Amount::zero());
    assert_eq!(state.monthly_limit, Amount::zero());
    assert_eq!(state.yearly_limit, Amount::zero());
}

#[test]
fn test_compliance_state_verified() {
    // Test different KYC levels
    let state1 = ComplianceState::new_verified(1);
    assert_eq!(state1.level, 1);
    assert_eq!(state1.daily_limit, Amount::from(10_000u128));
    assert_eq!(state1.monthly_limit, Amount::from(50_000u128));
    assert_eq!(state1.yearly_limit, Amount::from(200_000u128));
    
    let state2 = ComplianceState::new_verified(2);
    assert_eq!(state2.level, 2);
    assert_eq!(state2.daily_limit, Amount::from(100_000u128));
    assert_eq!(state2.monthly_limit, Amount::from(500_000u128));
    assert_eq!(state2.yearly_limit, Amount::from(2_000_000u128));
    
    let state3 = ComplianceState::new_verified(3);
    assert_eq!(state3.level, 3);
    assert_eq!(state3.daily_limit, Amount::from(u128::MAX));
    assert_eq!(state3.monthly_limit, Amount::from(u128::MAX));
    assert_eq!(state3.yearly_limit, Amount::from(u128::MAX));
}

#[test]
fn test_transaction_limits() {
    let state = ComplianceState::new_verified(1);
    
    // Within limits
    assert!(state.can_transact(Amount::from(5_000u128), Amount::zero(), Amount::zero(), Amount::zero()).is_ok());
    assert!(state.can_transact(Amount::from(10_000u128), Amount::zero(), Amount::zero(), Amount::zero()).is_ok());
    
    // Exceeds daily limit
    assert!(state.can_transact(Amount::from(15_000u128), Amount::zero(), Amount::zero(), Amount::zero()).is_err());
    
    // Already spent half of daily limit
    assert!(state.can_transact(Amount::from(5_000u128), Amount::from(5_000u128), Amount::zero(), Amount::zero()).is_ok());
    assert!(state.can_transact(Amount::from(6_000u128), Amount::from(5_000u128), Amount::zero(), Amount::zero()).is_err());
}

#[test]
fn test_freeze_status() {
    let mut state = ComplianceState::new_verified(1);
    assert!(!state.frozen);
    
    // Check can transact when not frozen
    assert!(state.can_transact(Amount::from(1_000u128), Amount::zero(), Amount::zero(), Amount::zero()).is_ok());
    
    // Freeze account
    state.freeze();
    assert!(state.frozen);
    
    // Check cannot transact when frozen
    assert!(state.can_transact(Amount::from(1_000u128), Amount::zero(), Amount::zero(), Amount::zero()).is_err());
    
    // Reset limits should also freeze
    state = ComplianceState::new_verified(1);
    state.reset_limits();
    assert!(state.frozen);
    assert_eq!(state.daily_limit, Amount::zero());
}

#[test]
fn test_limit_updates() {
    let mut state = ComplianceState::new_verified(1);
    
    // Update limits
    state.update_limits(Amount::from(5_000u128), Amount::from(20_000u128), Amount::from(100_000u128));
    assert_eq!(state.daily_limit, Amount::from(5_000u128));
    assert_eq!(state.monthly_limit, Amount::from(20_000u128));
    assert_eq!(state.yearly_limit, Amount::from(100_000u128));
}

#[test]
fn test_compliance_hash() {
    let state1 = ComplianceState::new_verified(1);
    let state2 = ComplianceState::new_verified(1);
    let state3 = ComplianceState::new_verified(2);
    
    // Same states should have same hash
    assert_eq!(state1.hash(), state2.hash());
    
    // Different states should have different hash
    assert_ne!(state1.hash(), state3.hash());
}

#[test]
fn test_pool_rule_creation() {
    let rule = PoolRule::new(
        1,
        vec![2, 3, 4],
        vec![5, 6],
        Amount::from(100_000u128),
        Amount::from(1_000_000u128),
        0b11,
    );
    
    assert_eq!(rule.pool_id, 1);
    assert_eq!(rule.inbound_allow, vec![2, 3, 4]);
    assert_eq!(rule.outbound_allow, vec![5, 6]);
    assert_eq!(rule.max_per_tx, Amount::from(100_000u128));
    assert_eq!(rule.max_per_day, Amount::from(1_000_000u128));
    assert_eq!(rule.flags, 0b11);
}

#[test]
fn test_pool_rule_flags() {
    let rule = PoolRule::new(
        1,
        vec![],
        vec![],
        Amount::from(100_000u128),
        Amount::from(1_000_000u128),
        0b1111,
    );
    
    assert!(rule.has_inbound_allowlist());
    assert!(rule.has_outbound_allowlist());
    assert!(rule.has_inbound_denylist());
    assert!(rule.has_outbound_denylist());
    
    let rule2 = PoolRule::new(
        1,
        vec![],
        vec![],
        Amount::from(100_000u128),
        Amount::from(1_000_000u128),
        0b0101,
    );
    
    assert!(rule2.has_inbound_allowlist());
    assert!(!rule2.has_outbound_allowlist());
    assert!(rule2.has_inbound_denylist());
    assert!(!rule2.has_outbound_denylist());
}

#[test]
fn test_pool_rule_checks() {
    let rule = PoolRule::new(
        1,
        vec![2, 3, 4],
        vec![5, 6, 7],
        Amount::from(100_000u128),
        Amount::from(1_000_000u128),
        0b0011, // inbound and outbound allowlists
    );
    
    // Check inbound transfers
    assert!(rule.allows_inbound_from(2));
    assert!(rule.allows_inbound_from(3));
    assert!(rule.allows_inbound_from(4));
    assert!(!rule.allows_inbound_from(5));
    assert!(!rule.allows_inbound_from(1));
    
    // Check outbound transfers
    assert!(rule.allows_outbound_to(5));
    assert!(rule.allows_outbound_to(6));
    assert!(rule.allows_outbound_to(7));
    assert!(!rule.allows_outbound_to(2));
    assert!(!rule.allows_outbound_to(1));
}

#[test]
fn test_sanctioned_identifier() {
    let mut rng = thread_rng();
    let address = F::rand(&mut rng);
    
    let id = SanctionedIdentifier::PubkeyHash(address);
    match id {
        SanctionedIdentifier::PubkeyHash(addr) => assert_eq!(addr, address),
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_compliance_state_can_transact_with_limits() {
    // Test with actual limit enforcement
    let state = ComplianceState::new_verified(2);
    
    // Test daily limit
    assert!(state.can_transact(
        Amount::from(50_000u128),
        Amount::from(50_000u128),
        Amount::from(100_000u128),
        Amount::from(500_000u128)
    ).is_ok());
    
    assert!(state.can_transact(
        Amount::from(50_001u128),
        Amount::from(50_000u128),
        Amount::from(100_000u128),
        Amount::from(500_000u128)
    ).is_err());
    
    // Test monthly limit
    assert!(state.can_transact(
        Amount::from(10_000u128),
        Amount::from(10_000u128),
        Amount::from(490_000u128),
        Amount::from(1_000_000u128)
    ).is_ok());
    
    assert!(state.can_transact(
        Amount::from(10_001u128),
        Amount::from(10_000u128),
        Amount::from(490_000u128),
        Amount::from(1_000_000u128)
    ).is_err());
    
    // Test yearly limit
    assert!(state.can_transact(
        Amount::from(10_000u128),
        Amount::from(10_000u128),
        Amount::from(100_000u128),
        Amount::from(1_990_000u128)
    ).is_ok());
    
    assert!(state.can_transact(
        Amount::from(10_001u128),
        Amount::from(10_000u128),
        Amount::from(100_000u128),
        Amount::from(1_990_000u128)
    ).is_err());
}

#[test]
fn test_compliance_state_update_flow() {
    let mut state = ComplianceState::new();
    
    // Start with unverified
    assert_eq!(state.level, 0);
    assert_eq!(state.daily_limit, Amount::zero());
    
    // Upgrade to level 1
    state.level = 1;
    state.daily_limit = Amount::from(10_000u128);
    state.monthly_limit = Amount::from(50_000u128);
    state.yearly_limit = Amount::from(200_000u128);
    
    // Update risk score
    state.risk_score = 50;
    
    // Upgrade to level 2
    state.level = 2;
    state.daily_limit = Amount::from(100_000u128);
    state.monthly_limit = Amount::from(500_000u128);
    state.yearly_limit = Amount::from(2_000_000u128);
    
    // Test freeze and reset
    state.freeze();
    assert!(state.frozen);
    
    state.reset_limits();
    assert_eq!(state.daily_limit, Amount::zero());
    assert_eq!(state.monthly_limit, Amount::zero());
    assert_eq!(state.yearly_limit, Amount::zero());
}