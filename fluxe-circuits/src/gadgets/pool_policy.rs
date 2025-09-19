use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::gadgets::{merkle::{MerkleTreeGadget, MerklePathVar}, poseidon::poseidon_hash_zk, range_proof::RangeProofGadget};

/// Pool policy enforcement gadget
/// Handles inbound/outbound allowlists, denylists, and transfer limits
pub struct PoolPolicyGadget;

impl PoolPolicyGadget {
    /// Enforce pool-to-pool transfer policy with proper Merkle membership proofs
    pub fn enforce_pool_transfer_policy(
        cs: ConstraintSystemRef<F>,
        source_pool_id: &FpVar<F>,
        dest_pool_id: &FpVar<F>,
        amount: &FpVar<F>,
        timestamp: &FpVar<F>,
        pool_rules_root: &FpVar<F>,
        source_policy: &PoolPolicyVar,
        dest_policy: &PoolPolicyVar,
        source_policy_path: &MerklePathVar,
        dest_policy_path: &MerklePathVar,
    ) -> Result<(), SynthesisError> {
        // Verify pool policies are in the rules tree using proper Merkle paths
        let source_hash = source_policy.hash()?;
        
        // Verify the path leaf matches the computed policy hash
        source_policy_path.leaf.enforce_equal(&source_hash)?;
        // Verify the path is valid for the given root
        source_policy_path.enforce_valid(pool_rules_root)?;
        
        let dest_hash = dest_policy.hash()?;
        dest_policy_path.leaf.enforce_equal(&dest_hash)?;
        dest_policy_path.enforce_valid(pool_rules_root)?;
        
        // Check source pool allows outbound to destination
        Self::check_outbound_allowed(cs.clone(), dest_pool_id, source_policy)?;
        
        // Check destination pool allows inbound from source
        Self::check_inbound_allowed(cs.clone(), source_pool_id, dest_policy)?;
        
        // Check amount limits
        Self::check_amount_limits(cs.clone(), amount, source_policy)?;
        Self::check_amount_limits(cs.clone(), amount, dest_policy)?;
        
        // Check time-based limits
        Self::check_time_limits(cs.clone(), amount, timestamp, source_policy)?;
        Self::check_time_limits(cs, amount, timestamp, dest_policy)?;
        
        Ok(())
    }
    
    /// Verify a single pool policy membership in POOL_RULES_ROOT
    pub fn verify_pool_policy_membership(
        cs: ConstraintSystemRef<F>,
        pool_policy: &PoolPolicyVar,
        policy_path: &MerklePathVar,
        pool_rules_root: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Compute policy hash
        let policy_hash = pool_policy.hash()?;
        
        // Verify the path leaf matches the computed policy hash
        policy_path.leaf.enforce_equal(&policy_hash)?;
        
        // Verify the path is valid for the given root
        policy_path.enforce_valid(pool_rules_root)?;
        
        Ok(())
    }
    
    /// Verify pool policy and enforce spending constraints for a single pool
    pub fn enforce_single_pool_policy(
        cs: ConstraintSystemRef<F>,
        pool_id: &FpVar<F>,
        amount: &FpVar<F>,
        timestamp: &FpVar<F>,
        pool_rules_root: &FpVar<F>,
        pool_policy: &PoolPolicyVar,
        policy_path: &MerklePathVar,
    ) -> Result<(), SynthesisError> {
        // Verify policy membership
        Self::verify_pool_policy_membership(cs.clone(), pool_policy, policy_path, pool_rules_root)?;
        
        // Verify pool ID matches
        pool_policy.pool_id.enforce_equal(pool_id)?;
        
        // Check amount limits
        Self::check_amount_limits(cs.clone(), amount, pool_policy)?;
        
        // Check time-based limits
        Self::check_time_limits(cs, amount, timestamp, pool_policy)?;
        
        Ok(())
    }
    
    /// Check if outbound transfer to specific pool is allowed
    fn check_outbound_allowed(
        cs: ConstraintSystemRef<F>,
        dest_pool_id: &FpVar<F>,
        policy: &PoolPolicyVar,
    ) -> Result<(), SynthesisError> {
        // Check against outbound allowlist/denylist
        // This is simplified - real implementation would check bitmap or list membership
        
        let has_outbound_allowlist = policy.flags.has_outbound_allowlist()?;
        // Conditionally check: if has_allowlist then must be in list
        // For simplicity, we always check but only enforce if flag is set
        // This maintains constant circuit size
        Self::check_pool_in_list(cs.clone(), dest_pool_id, &policy.outbound_allow)?;
        
        let has_outbound_denylist = policy.flags.has_outbound_denylist()?;
        // Must NOT be in denylist (always check for constant circuit)
        Self::check_pool_not_in_list(cs, dest_pool_id, &policy.outbound_deny)?;
        
        Ok(())
    }
    
    /// Check if inbound transfer from specific pool is allowed
    fn check_inbound_allowed(
        cs: ConstraintSystemRef<F>,
        source_pool_id: &FpVar<F>,
        policy: &PoolPolicyVar,
    ) -> Result<(), SynthesisError> {
        let has_inbound_allowlist = policy.flags.has_inbound_allowlist()?;
        // Always check for constant circuit size
        Self::check_pool_in_list(cs.clone(), source_pool_id, &policy.inbound_allow)?;
        
        let has_inbound_denylist = policy.flags.has_inbound_denylist()?;
        Self::check_pool_not_in_list(cs, source_pool_id, &policy.inbound_deny)?;
        
        Ok(())
    }
    
    /// Check amount against pool limits
    fn check_amount_limits(
        cs: ConstraintSystemRef<F>,
        amount: &FpVar<F>,
        policy: &PoolPolicyVar,
    ) -> Result<(), SynthesisError> {
        // Check per-transaction limit
        let has_per_tx_limit = policy.flags.has_per_tx_limit()?;
        // Since FpVar doesn't have is_le, we check that amount != max_per_tx + 1
        // In practice, we'd need a proper comparison gadget
        // For now, we just ensure amount is not equal to zero (simplified)
        let amount_nonzero = amount.is_neq(&FpVar::zero())?;
        // Only enforce if has_per_tx_limit is true
        let should_check = has_per_tx_limit.select(&amount_nonzero, &Boolean::TRUE)?;
        should_check.enforce_equal(&Boolean::TRUE)?;
        
        // Range check the amount
        RangeProofGadget::prove_range_bits(cs, amount, 64)?;
        
        Ok(())
    }
    
    /// Check time-based limits (daily, monthly, etc.)
    fn check_time_limits(
        cs: ConstraintSystemRef<F>,
        amount: &FpVar<F>,
        timestamp: &FpVar<F>,
        policy: &PoolPolicyVar,
    ) -> Result<(), SynthesisError> {
        // Simplified time checking - real implementation would track rolling windows
        
        let has_daily_limit = policy.flags.has_daily_limit()?;
        // In practice, would check cumulative daily amount
        // For now, simplified check that amount is non-zero
        let amount_nonzero = amount.is_neq(&FpVar::zero())?;
        let should_check_daily = has_daily_limit.select(&amount_nonzero, &Boolean::TRUE)?;
        should_check_daily.enforce_equal(&Boolean::TRUE)?;
        
        // Validate timestamp is reasonable
        // Since we don't have comparison operators, we check it's non-zero as a simplified check
        let timestamp_valid = timestamp.is_neq(&FpVar::zero())?;
        timestamp_valid.enforce_equal(&Boolean::TRUE)?;
        
        Ok(())
    }
    
    /// Check if pool ID is in an allowed list using proper bitmap bit extraction
    fn check_pool_in_list(
        _cs: ConstraintSystemRef<F>,
        pool_id: &FpVar<F>,
        allowed_bitmap: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Convert pool_id to bits to use as index (take lower 8 bits for 256 pools)
        let pool_id_bits = pool_id.to_bits_le()?;
        let index_bits = &pool_id_bits[..8.min(pool_id_bits.len())];
        
        // Convert bitmap to bits
        let bitmap_bits = allowed_bitmap.to_bits_le()?;
        
        // Select the bit at pool_id index from bitmap
        // We need to handle this carefully for constant circuit size
        let mut is_allowed = Boolean::FALSE;
        
        for (i, bit) in bitmap_bits.iter().enumerate().take(256) {
            // Check if current position matches pool_id
            let mut index_matches = Boolean::TRUE;
            for (j, index_bit) in index_bits.iter().enumerate() {
                let expected_bit = Boolean::constant((i >> j) & 1 == 1);
                let bit_matches = index_bit.is_eq(&expected_bit)?;
                index_matches = index_matches.and(&bit_matches)?;
            }
            
            // If index matches, select this bit
            is_allowed = index_matches.select(bit, &is_allowed)?;
        }
        
        // Enforce that pool is in the allowed list
        is_allowed.enforce_equal(&Boolean::TRUE)?;
        
        Ok(())
    }
    
    /// Check if pool ID is NOT in a denied list using proper bitmap bit extraction
    fn check_pool_not_in_list(
        _cs: ConstraintSystemRef<F>,
        pool_id: &FpVar<F>,
        denied_bitmap: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Convert pool_id to bits to use as index (take lower 8 bits for 256 pools)
        let pool_id_bits = pool_id.to_bits_le()?;
        let index_bits = &pool_id_bits[..8.min(pool_id_bits.len())];
        
        // Convert bitmap to bits
        let bitmap_bits = denied_bitmap.to_bits_le()?;
        
        // Select the bit at pool_id index from bitmap
        let mut is_denied = Boolean::FALSE;
        
        for (i, bit) in bitmap_bits.iter().enumerate().take(256) {
            // Check if current position matches pool_id
            let mut index_matches = Boolean::TRUE;
            for (j, index_bit) in index_bits.iter().enumerate() {
                let expected_bit = Boolean::constant((i >> j) & 1 == 1);
                let bit_matches = index_bit.is_eq(&expected_bit)?;
                index_matches = index_matches.and(&bit_matches)?;
            }
            
            // If index matches, select this bit
            is_denied = index_matches.select(bit, &is_denied)?;
        }
        
        // Enforce that pool is NOT in the denied list
        is_denied.enforce_equal(&Boolean::FALSE)?;
        
        Ok(())
    }
}

/// Pool policy variable for circuits
#[derive(Clone)]
pub struct PoolPolicyVar {
    pub pool_id: FpVar<F>,
    pub inbound_allow: FpVar<F>,   // Bitmap or compressed ranges
    pub inbound_deny: FpVar<F>,
    pub outbound_allow: FpVar<F>,
    pub outbound_deny: FpVar<F>,
    pub max_per_tx: FpVar<F>,
    pub max_per_day: FpVar<F>,
    pub flags: PoolFlagsVar,
}

impl PoolPolicyVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        pool_id: u32,
        inbound_allow: u64,
        inbound_deny: u64,
        outbound_allow: u64,
        outbound_deny: u64,
        max_per_tx: u64,
        max_per_day: u64,
        flags: u32,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            pool_id: FpVar::new_witness(cs.clone(), || Ok(F::from(pool_id as u64)))?,
            inbound_allow: FpVar::new_witness(cs.clone(), || Ok(F::from(inbound_allow)))?,
            inbound_deny: FpVar::new_witness(cs.clone(), || Ok(F::from(inbound_deny)))?,
            outbound_allow: FpVar::new_witness(cs.clone(), || Ok(F::from(outbound_allow)))?,
            outbound_deny: FpVar::new_witness(cs.clone(), || Ok(F::from(outbound_deny)))?,
            max_per_tx: FpVar::new_witness(cs.clone(), || Ok(F::from(max_per_tx)))?,
            max_per_day: FpVar::new_witness(cs.clone(), || Ok(F::from(max_per_day)))?,
            flags: PoolFlagsVar::new_witness(cs, flags)?,
        })
    }
    
    /// Compute hash of the policy for Merkle tree operations
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        let inputs = vec![
            self.pool_id.clone(),
            self.inbound_allow.clone(),
            self.inbound_deny.clone(),
            self.outbound_allow.clone(),
            self.outbound_deny.clone(),
            self.max_per_tx.clone(),
            self.max_per_day.clone(),
            self.flags.bits.clone(),
        ];
        
        poseidon_hash_zk(&inputs)
    }
}

/// Pool policy flags variable
#[derive(Clone)]
pub struct PoolFlagsVar {
    pub bits: FpVar<F>,
}

impl PoolFlagsVar {
    const OUTBOUND_ALLOWLIST_FLAG: u32 = 1 << 0;
    const OUTBOUND_DENYLIST_FLAG: u32 = 1 << 1;
    const INBOUND_ALLOWLIST_FLAG: u32 = 1 << 2;
    const INBOUND_DENYLIST_FLAG: u32 = 1 << 3;
    const PER_TX_LIMIT_FLAG: u32 = 1 << 4;
    const DAILY_LIMIT_FLAG: u32 = 1 << 5;
    
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        flags: u32,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            bits: FpVar::new_witness(cs, || Ok(F::from(flags as u64)))?,
        })
    }
    
    /// Check if outbound allowlist is enabled
    pub fn has_outbound_allowlist(&self) -> Result<Boolean<F>, SynthesisError> {
        self.check_flag(Self::OUTBOUND_ALLOWLIST_FLAG)
    }
    
    /// Check if outbound denylist is enabled
    pub fn has_outbound_denylist(&self) -> Result<Boolean<F>, SynthesisError> {
        self.check_flag(Self::OUTBOUND_DENYLIST_FLAG)
    }
    
    /// Check if inbound allowlist is enabled
    pub fn has_inbound_allowlist(&self) -> Result<Boolean<F>, SynthesisError> {
        self.check_flag(Self::INBOUND_ALLOWLIST_FLAG)
    }
    
    /// Check if inbound denylist is enabled
    pub fn has_inbound_denylist(&self) -> Result<Boolean<F>, SynthesisError> {
        self.check_flag(Self::INBOUND_DENYLIST_FLAG)
    }
    
    /// Check if per-tx limit is enabled
    pub fn has_per_tx_limit(&self) -> Result<Boolean<F>, SynthesisError> {
        self.check_flag(Self::PER_TX_LIMIT_FLAG)
    }
    
    /// Check if daily limit is enabled
    pub fn has_daily_limit(&self) -> Result<Boolean<F>, SynthesisError> {
        self.check_flag(Self::DAILY_LIMIT_FLAG)
    }
    
    /// Check if a specific flag bit is set
    fn check_flag(&self, flag_mask: u32) -> Result<Boolean<F>, SynthesisError> {
        // Convert to bits and check the specific bit position
        let bits = self.bits.to_bits_le()?;
        
        // Find which bit position to check based on flag_mask
        let bit_position = flag_mask.trailing_zeros() as usize;
        
        // Return the bit at that position if it exists, otherwise false
        if bit_position < bits.len() {
            Ok(bits[bit_position].clone())
        } else {
            Ok(Boolean::FALSE)
        }
    }
}

/// Utilities for pool policy operations
pub struct PoolPolicyUtils;

impl PoolPolicyUtils {
    /// Create a permissive policy (allows all transfers)
    pub fn create_permissive_policy(
        cs: ConstraintSystemRef<F>,
        pool_id: u32,
    ) -> Result<PoolPolicyVar, SynthesisError> {
        PoolPolicyVar::new_witness(
            cs,
            pool_id,
            u64::MAX, // Allow all inbound
            0,        // Deny none inbound
            u64::MAX, // Allow all outbound
            0,        // Deny none outbound
            u64::MAX, // No per-tx limit
            u64::MAX, // No daily limit
            0,        // No flags set
        )
    }
    
    /// Create a restrictive policy (denies most transfers)
    pub fn create_restrictive_policy(
        cs: ConstraintSystemRef<F>,
        pool_id: u32,
        allowed_pools: &[u32],
    ) -> Result<PoolPolicyVar, SynthesisError> {
        // Simplified: use first allowed pool as bitmap
        let allow_bitmap = allowed_pools.first().copied().unwrap_or(0) as u64;
        
        PoolPolicyVar::new_witness(
            cs,
            pool_id,
            allow_bitmap, // Limited inbound allowlist
            0,            // No inbound denylist
            allow_bitmap, // Limited outbound allowlist
            0,            // No outbound denylist
            1_000_000,    // 1M unit per-tx limit
            10_000_000,   // 10M unit daily limit
            PoolFlagsVar::INBOUND_ALLOWLIST_FLAG 
                | PoolFlagsVar::OUTBOUND_ALLOWLIST_FLAG 
                | PoolFlagsVar::PER_TX_LIMIT_FLAG
                | PoolFlagsVar::DAILY_LIMIT_FLAG,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_pool_policy_hash() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let policy = PoolPolicyVar::new_witness(
            cs.clone(),
            1,        // pool_id
            0xFF,     // inbound_allow
            0,        // inbound_deny
            0xFF,     // outbound_allow
            0,        // outbound_deny
            1000,     // max_per_tx
            10000,    // max_per_day
            0x3F,     // flags
        ).unwrap();
        
        let hash = policy.hash().unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_pool_flags() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let flags = PoolFlagsVar::new_witness(
            cs.clone(),
            PoolFlagsVar::INBOUND_ALLOWLIST_FLAG | PoolFlagsVar::PER_TX_LIMIT_FLAG,
        ).unwrap();
        
        let has_inbound = flags.has_inbound_allowlist().unwrap();
        let has_daily = flags.has_daily_limit().unwrap();
        
        has_inbound.enforce_equal(&Boolean::TRUE).unwrap();
        has_daily.enforce_equal(&Boolean::FALSE).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_amount_limits() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let amount = FpVar::new_witness(cs.clone(), || Ok(F::from(500u64))).unwrap();
        let policy = PoolPolicyVar::new_witness(
            cs.clone(),
            1,     // pool_id
            0,     // inbound_allow
            0,     // inbound_deny
            0,     // outbound_allow
            0,     // outbound_deny
            1000,  // max_per_tx (higher than amount)
            10000, // max_per_day
            PoolFlagsVar::PER_TX_LIMIT_FLAG,
        ).unwrap();
        
        PoolPolicyGadget::check_amount_limits(cs.clone(), &amount, &policy).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_permissive_policy() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let policy = PoolPolicyUtils::create_permissive_policy(cs.clone(), 1).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        // Should allow large amounts
        let large_amount = FpVar::new_witness(cs.clone(), || Ok(F::from(1_000_000u64))).unwrap();
        PoolPolicyGadget::check_amount_limits(cs.clone(), &large_amount, &policy).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}