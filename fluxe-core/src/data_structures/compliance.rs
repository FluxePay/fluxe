use crate::crypto::poseidon_hash;
use crate::types::*;
use ark_bls12_381::Fr as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Removed serde - using ark_serialize instead

/// Compliance state for a user
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ComplianceState {
    /// Compliance level (0=unverified, 1=basic KYC, 2=enhanced, 3=institutional)
    pub level: u8,
    
    /// Risk score (0 to 2^32-1, higher = riskier)
    pub risk_score: RiskScore,
    
    /// Whether assets are frozen
    pub frozen: bool,
    
    /// Last compliance review timestamp
    pub last_review_time: Time,
    
    /// Jurisdiction bitfield for allowed regions
    pub jurisdiction_bits: JurisdictionBits,
    
    /// Daily transaction limit
    pub daily_limit: Amount,
    
    /// Monthly transaction limit
    pub monthly_limit: Amount,
    
    /// Yearly transaction limit
    pub yearly_limit: Amount,
    
    /// Commitment to reputation vector
    pub rep_hash: F,
}

impl ComplianceState {
    /// Create a new default compliance state
    pub fn new() -> Self {
        Self {
            level: 0,
            risk_score: 0,
            frozen: false,
            last_review_time: 0,
            jurisdiction_bits: [0u8; 32],
            daily_limit: Amount::zero(),
            monthly_limit: Amount::zero(),
            yearly_limit: Amount::zero(),
            rep_hash: F::from(0),
        }
    }

    /// Create initial state for verified user
    pub fn new_verified(level: u8) -> Self {
        let (daily, monthly, yearly) = match level {
            1 => (Amount::from(10_000u128), Amount::from(50_000u128), Amount::from(200_000u128)),     // Basic KYC limits
            2 => (Amount::from(100_000u128), Amount::from(500_000u128), Amount::from(2_000_000u128)), // Enhanced KYC
            3 => (Amount::from(u128::MAX), Amount::from(u128::MAX), Amount::from(u128::MAX)), // Institutional (unlimited)
            _ => (Amount::zero(), Amount::zero(), Amount::zero()),
        };

        Self {
            level,
            risk_score: 0,
            frozen: false,
            last_review_time: 0,
            jurisdiction_bits: [0xff; 32], // All jurisdictions allowed by default
            daily_limit: daily,
            monthly_limit: monthly,
            yearly_limit: yearly,
            rep_hash: F::from(0),
        }
    }

    /// Compute hash of the compliance state
    pub fn hash(&self) -> F {
        let mut input = Vec::new();
        
        input.push(F::from(self.level as u64));
        input.push(F::from(self.risk_score as u64));
        input.push(F::from(self.frozen as u64));
        input.push(F::from(self.last_review_time));
        input.push(crate::utils::bytes_to_field(&self.jurisdiction_bits));
        input.push(self.daily_limit.to_field());
        input.push(self.monthly_limit.to_field());
        input.push(self.yearly_limit.to_field());
        input.push(self.rep_hash);
        
        poseidon_hash(&input)
    }

    /// Check if user can perform transaction of given amount
    pub fn can_transact(&self, amount: Amount, daily_spent: Amount, monthly_spent: Amount, yearly_spent: Amount) -> Result<(), String> {
        if self.frozen {
            return Err("Account is frozen".to_string());
        }

        if daily_spent + amount > self.daily_limit {
            return Err(format!("Exceeds daily limit of {}", self.daily_limit));
        }

        if monthly_spent + amount > self.monthly_limit {
            return Err(format!("Exceeds monthly limit of {}", self.monthly_limit));
        }

        if yearly_spent + amount > self.yearly_limit {
            return Err(format!("Exceeds yearly limit of {}", self.yearly_limit));
        }

        Ok(())
    }

    /// Freeze assets
    pub fn freeze(&mut self) {
        self.frozen = true;
        self.daily_limit = Amount::zero();
        self.monthly_limit = Amount::zero();
        self.yearly_limit = Amount::zero();
    }

    /// Unfreeze assets with new limits
    pub fn unfreeze(&mut self, daily: Amount, monthly: Amount, yearly: Amount) {
        self.frozen = false;
        self.daily_limit = daily;
        self.monthly_limit = monthly;
        self.yearly_limit = yearly;
    }
    
    /// Reset limits and freeze account
    pub fn reset_limits(&mut self) {
        self.freeze();
    }
    
    /// Update limits
    pub fn update_limits(&mut self, daily: Amount, monthly: Amount, yearly: Amount) {
        self.daily_limit = daily;
        self.monthly_limit = monthly;
        self.yearly_limit = yearly;
    }
}

/// Pool policy rules
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoolRule {
    /// Pool identifier
    pub pool_id: PoolId,
    
    /// Bitmap of allowed inbound pools
    pub inbound_allow: Vec<PoolId>,
    
    /// Bitmap of allowed outbound pools
    pub outbound_allow: Vec<PoolId>,
    
    /// Maximum amount per transaction
    pub max_per_tx: Amount,
    
    /// Maximum amount per day
    pub max_per_day: Amount,
    
    /// Additional flags
    pub flags: u32,
}

impl PoolRule {
    pub fn new(
        pool_id: PoolId,
        inbound_allow: Vec<PoolId>,
        outbound_allow: Vec<PoolId>,
        max_per_tx: Amount,
        max_per_day: Amount,
        flags: u32,
    ) -> Self {
        Self {
            pool_id,
            inbound_allow,
            outbound_allow,
            max_per_tx,
            max_per_day,
            flags,
        }
    }
    
    pub fn new_default(pool_id: PoolId) -> Self {
        Self {
            pool_id,
            inbound_allow: Vec::new(),
            outbound_allow: Vec::new(),
            max_per_tx: Amount::from(u128::MAX),
            max_per_day: Amount::from(u128::MAX),
            flags: 0,
        }
    }

    /// Check if transfer between pools is allowed
    pub fn can_transfer(&self, from_pool: PoolId, to_pool: PoolId, amount: Amount) -> bool {
        if from_pool == self.pool_id {
            // Outbound check
            if !self.outbound_allow.contains(&to_pool) && !self.outbound_allow.is_empty() {
                return false;
            }
        }
        
        if to_pool == self.pool_id {
            // Inbound check
            if !self.inbound_allow.contains(&from_pool) && !self.inbound_allow.is_empty() {
                return false;
            }
        }
        
        amount <= self.max_per_tx
    }
    
    /// Check if has inbound allowlist flag
    pub fn has_inbound_allowlist(&self) -> bool {
        self.flags & 0b0001 != 0
    }
    
    /// Check if has outbound allowlist flag
    pub fn has_outbound_allowlist(&self) -> bool {
        self.flags & 0b0010 != 0
    }
    
    /// Check if has inbound denylist flag
    pub fn has_inbound_denylist(&self) -> bool {
        self.flags & 0b0100 != 0
    }
    
    /// Check if has outbound denylist flag
    pub fn has_outbound_denylist(&self) -> bool {
        self.flags & 0b1000 != 0
    }
    
    /// Check if inbound transfer is allowed from a specific pool
    pub fn allows_inbound_from(&self, from_pool: PoolId) -> bool {
        if self.has_inbound_allowlist() {
            self.inbound_allow.contains(&from_pool)
        } else {
            true // No allowlist means all are allowed
        }
    }
    
    /// Check if outbound transfer is allowed to a specific pool
    pub fn allows_outbound_to(&self, to_pool: PoolId) -> bool {
        if self.has_outbound_allowlist() {
            self.outbound_allow.contains(&to_pool)
        } else {
            true // No allowlist means all are allowed
        }
    }

    /// Compute hash of pool rule
    pub fn hash(&self) -> F {
        let mut input = Vec::new();
        
        input.push(F::from(self.pool_id));
        
        // Hash allow lists
        let mut inbound_hash = F::from(0);
        for pool in &self.inbound_allow {
            inbound_hash = poseidon_hash(&[inbound_hash, F::from(*pool)]);
        }
        input.push(inbound_hash);
        
        let mut outbound_hash = F::from(0);
        for pool in &self.outbound_allow {
            outbound_hash = poseidon_hash(&[outbound_hash, F::from(*pool)]);
        }
        input.push(outbound_hash);
        
        input.push(self.max_per_tx.to_field());
        input.push(self.max_per_day.to_field());
        input.push(F::from(self.flags as u64));
        
        poseidon_hash(&input)
    }
}

/// Sanctions list entry
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SanctionedIdentifier {
    /// Ethereum address
    EthAddress([u8; 20]),
    
    /// Public key hash
    PubkeyHash(F),
    
    /// Institution ID
    InstitutionId(u64),
}

impl SanctionedIdentifier {
    /// Convert to field element for Merkle tree
    pub fn to_field(&self) -> F {
        match self {
            SanctionedIdentifier::EthAddress(addr) => {
                let mut bytes = [0u8; 32];
                bytes[..20].copy_from_slice(addr);
                crate::utils::bytes_to_field(&bytes)
            }
            SanctionedIdentifier::PubkeyHash(hash) => *hash,
            SanctionedIdentifier::InstitutionId(id) => F::from(*id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_state() {
        let mut state = ComplianceState::new_verified(1);
        assert_eq!(state.level, 1);
        assert!(!state.frozen);
        
        // Test transaction limits
        assert!(state.can_transact(Amount::from(5_000u128), Amount::zero(), Amount::zero(), Amount::zero()).is_ok());
        assert!(state.can_transact(Amount::from(15_000u128), Amount::zero(), Amount::zero(), Amount::zero()).is_err());
        
        // Test freeze/unfreeze
        state.freeze();
        assert!(state.frozen);
        assert!(state.can_transact(Amount::from(1u128), Amount::zero(), Amount::zero(), Amount::zero()).is_err());
        
        state.unfreeze(Amount::from(1_000u128), Amount::from(5_000u128), Amount::from(20_000u128));
        assert!(!state.frozen);
        assert!(state.can_transact(Amount::from(500u128), Amount::zero(), Amount::zero(), Amount::zero()).is_ok());
    }

    #[test]
    fn test_pool_rules() {
        let mut rule = PoolRule::new_default(1);
        rule.outbound_allow = vec![2, 3];
        rule.max_per_tx = Amount::from(10_000u128);
        
        // Test allowed transfer
        assert!(rule.can_transfer(1, 2, Amount::from(5_000u128)));
        
        // Test disallowed transfer
        assert!(!rule.can_transfer(1, 4, Amount::from(5_000u128)));
        
        // Test amount limit
        assert!(!rule.can_transfer(1, 2, Amount::from(15_000u128)));
    }
}