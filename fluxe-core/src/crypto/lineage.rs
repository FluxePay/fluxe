use ark_bls12_381::Fr as F;
use crate::crypto::poseidon_hash;

/// Bounded horizon lineage accumulator
/// Tracks transaction history with automatic reset after a certain depth
pub struct LineageAccumulator {
    /// Current lineage hash
    pub hash: F,
    /// Depth counter (resets at horizon)
    pub depth: u32,
    /// Maximum depth before reset
    pub horizon: u32,
}

impl LineageAccumulator {
    /// Create a new lineage accumulator with specified horizon
    pub fn new(horizon: u32) -> Self {
        Self {
            hash: F::from(0),
            depth: 0,
            horizon,
        }
    }

    /// Update lineage with parent hashes
    pub fn update(&mut self, parent_lineages: &[F]) -> F {
        // If we've reached the horizon, reset
        if self.depth >= self.horizon {
            self.hash = F::from(0);
            self.depth = 0;
        }

        // Compute new lineage hash
        // H(lineage) = H(parent_1 || parent_2 || ... || context)
        let mut input = vec![];
        
        // Add parent lineages
        for parent in parent_lineages {
            input.push(*parent);
        }
        
        // Add current accumulator state
        input.push(self.hash);
        
        // Add depth as context
        input.push(F::from(self.depth as u64));
        
        // Compute new hash
        self.hash = poseidon_hash(&input);
        self.depth += 1;
        
        self.hash
    }

    /// Get current lineage hash
    pub fn current(&self) -> F {
        self.hash
    }

    /// Check if accumulator needs reset
    pub fn needs_reset(&self) -> bool {
        self.depth >= self.horizon
    }

    /// Force reset the accumulator
    pub fn reset(&mut self) {
        self.hash = F::from(0);
        self.depth = 0;
    }
}

/// Compute lineage hash for a new note given parent notes
pub fn compute_lineage_hash(
    parent_lineages: &[F],
    horizon: u32,
    current_depth: u32,
) -> F {
    // If depth exceeds horizon, start fresh
    if current_depth >= horizon {
        return F::from(0);
    }

    // Otherwise compute accumulated hash
    let mut input = vec![];
    
    // Add all parent lineages
    for parent in parent_lineages {
        input.push(*parent);
    }
    
    // Add depth context
    input.push(F::from(current_depth as u64));
    
    poseidon_hash(&input)
}

/// Verify lineage is valid (within horizon)
pub fn verify_lineage(
    lineage_hash: F,
    depth: u32,
    horizon: u32,
) -> bool {
    // Lineage should be zero if depth >= horizon
    if depth >= horizon {
        lineage_hash == F::from(0)
    } else {
        // Otherwise it should be non-zero (unless it's the genesis)
        true // More complex verification would check the chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lineage_accumulator() {
        let mut acc = LineageAccumulator::new(3);
        
        // Initial state
        assert_eq!(acc.current(), F::from(0));
        assert_eq!(acc.depth, 0);
        
        // First update
        let parent1 = F::from(100u64);
        let hash1 = acc.update(&[parent1]);
        assert_ne!(hash1, F::from(0));
        assert_eq!(acc.depth, 1);
        
        // Second update
        let parent2 = F::from(200u64);
        let hash2 = acc.update(&[parent2]);
        assert_ne!(hash2, hash1);
        assert_eq!(acc.depth, 2);
        
        // Third update (at horizon)
        let parent3 = F::from(300u64);
        let hash3 = acc.update(&[parent3]);
        assert_ne!(hash3, hash2);
        assert_eq!(acc.depth, 3);
        
        // Fourth update (should reset)
        let parent4 = F::from(400u64);
        let hash4 = acc.update(&[parent4]);
        assert_eq!(acc.depth, 1); // Reset to 1
    }

    #[test]
    fn test_compute_lineage_hash() {
        let parents = vec![F::from(1u64), F::from(2u64)];
        
        // Within horizon
        let hash1 = compute_lineage_hash(&parents, 10, 5);
        assert_ne!(hash1, F::from(0));
        
        // At horizon - should reset
        let hash2 = compute_lineage_hash(&parents, 10, 10);
        assert_eq!(hash2, F::from(0));
        
        // Beyond horizon - should reset
        let hash3 = compute_lineage_hash(&parents, 10, 15);
        assert_eq!(hash3, F::from(0));
    }

    #[test]
    fn test_verify_lineage() {
        // Valid lineage within horizon
        assert!(verify_lineage(F::from(123u64), 5, 10));
        
        // Zero lineage at genesis is valid
        assert!(verify_lineage(F::from(0), 0, 10));
        
        // At horizon should be zero
        assert!(verify_lineage(F::from(0), 10, 10));
        
        // Non-zero at horizon is invalid
        assert!(!verify_lineage(F::from(123u64), 10, 10));
    }
}