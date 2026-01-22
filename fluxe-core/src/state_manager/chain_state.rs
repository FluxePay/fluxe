use crate::crypto::poseidon_hash;
use crate::data_structures::{IngressReceipt, ExitReceipt};
use crate::errors::StateError;
use crate::merkle::{IncrementalTree, TreeParams};
use crate::types::{*, Amount, AssetType, ChainId, ChainStateRoots, TransitionProof, ChainStateOperation};
use ark_bn254::Fr as F;
use std::collections::HashMap;

/// Per-chain state manager for ingress/exit tracking
///
/// Each external chain (e.g., Ethereum, Base, Solana) has its own ChainState
/// that tracks deposits (ingress) and withdrawals (exit) specific to that chain.
/// This enables proper accounting of cross-chain flows and supply invariants.
#[derive(Clone, Debug)]
pub struct ChainState {
    /// Chain identifier
    pub chain_id: ChainId,

    /// Chain type (EVM, SVM, etc.)
    pub chain_type: ChainType,

    /// Ingress tree (append-only) for deposits from this chain
    pub ingress_tree: IncrementalTree,

    /// Exit tree (append-only) for withdrawals to this chain
    pub exit_tree: IncrementalTree,

    /// Per-asset supply tracking for this chain
    /// Tracks how much has been deposited vs withdrawn
    pub deposited: HashMap<AssetType, Amount>,
    pub withdrawn: HashMap<AssetType, Amount>,

    /// Tree parameters
    pub params: TreeParams,
}

impl ChainState {
    /// Create a new chain state
    ///
    /// # Arguments
    /// * `chain_id` - Unique identifier for the chain
    /// * `chain_type` - Type of chain (EVM, SVM, etc.)
    /// * `tree_depth` - Depth of Merkle trees
    pub fn new(chain_id: ChainId, chain_type: ChainType, tree_depth: usize) -> Self {
        let params = TreeParams::new(tree_depth);

        Self {
            chain_id,
            chain_type,
            ingress_tree: IncrementalTree::new(tree_depth),
            exit_tree: IncrementalTree::new(tree_depth),
            deposited: HashMap::new(),
            withdrawn: HashMap::new(),
            params,
        }
    }

    /// Get current state roots
    pub fn get_roots(&self) -> ChainStateRoots {
        ChainStateRoots {
            ingress_root: self.ingress_tree.root(),
            exit_root: self.exit_tree.root(),
        }
    }

    /// Process an ingress receipt (deposit from external chain)
    ///
    /// This records a deposit event from the external chain. The receipt
    /// contains proof that assets were locked on the external chain and
    /// should be minted within the protocol.
    ///
    /// # Arguments
    /// * `receipt` - Ingress receipt proving the deposit
    ///
    /// # Returns
    /// TransitionProof showing the state change
    pub fn process_ingress(
        &mut self,
        receipt: &IngressReceipt,
    ) -> Result<TransitionProof, StateError> {
        let old_roots = self.get_roots();

        // Add receipt to ingress tree
        let receipt_hash = receipt.hash();
        self.ingress_tree.append(receipt_hash);

        // Update deposited supply
        let deposited = self.deposited.entry(receipt.asset_type).or_insert(Amount::zero());
        *deposited = deposited.saturating_add(receipt.amount);

        let new_roots = self.get_roots();

        Ok(TransitionProof {
            old_roots,
            new_roots,
            operations: vec![ChainStateOperation::IngressAppend {
                chain_id: self.chain_id,
                receipt_hash,
            }],
        })
    }

    /// Process an exit receipt (withdrawal to external chain)
    ///
    /// This records a withdrawal event to the external chain. The receipt
    /// contains proof that assets were burned within the protocol and
    /// should be released on the external chain.
    ///
    /// # Arguments
    /// * `receipt` - Exit receipt proving the withdrawal
    ///
    /// # Returns
    /// TransitionProof showing the state change
    pub fn process_exit(
        &mut self,
        receipt: &ExitReceipt,
    ) -> Result<TransitionProof, StateError> {
        let old_roots = self.get_roots();

        // Verify sufficient deposited supply exists
        let deposited = self.deposited.get(&receipt.asset_type).copied().unwrap_or(Amount::zero());
        let withdrawn = self.withdrawn.get(&receipt.asset_type).copied().unwrap_or(Amount::zero());
        let net_supply = deposited.saturating_sub(withdrawn);

        if net_supply < receipt.amount {
            return Err(StateError::InsufficientSupply);
        }

        // Add receipt to exit tree
        let receipt_hash = receipt.hash();
        self.exit_tree.append(receipt_hash);

        // Update withdrawn supply
        let withdrawn_entry = self.withdrawn.entry(receipt.asset_type).or_insert(Amount::zero());
        *withdrawn_entry = withdrawn_entry.saturating_add(receipt.amount);

        let new_roots = self.get_roots();

        Ok(TransitionProof {
            old_roots,
            new_roots,
            operations: vec![ChainStateOperation::ExitAppend {
                chain_id: self.chain_id,
                receipt_hash,
            }],
        })
    }

    /// Get net supply for an asset on this chain
    ///
    /// Net supply = deposited - withdrawn
    /// This represents how much of the asset is "in flight" from this chain.
    pub fn get_net_supply(&self, asset_type: AssetType) -> Amount {
        let deposited = self.deposited.get(&asset_type).copied().unwrap_or(Amount::zero());
        let withdrawn = self.withdrawn.get(&asset_type).copied().unwrap_or(Amount::zero());
        deposited.saturating_sub(withdrawn)
    }

    /// Get total deposited for an asset
    pub fn get_deposited(&self, asset_type: AssetType) -> Amount {
        self.deposited.get(&asset_type).copied().unwrap_or(Amount::zero())
    }

    /// Get total withdrawn for an asset
    pub fn get_withdrawn(&self, asset_type: AssetType) -> Amount {
        self.withdrawn.get(&asset_type).copied().unwrap_or(Amount::zero())
    }

    /// Check supply invariant for an asset
    ///
    /// Invariant: deposited >= withdrawn (always)
    pub fn check_supply_invariant(&self, asset_type: AssetType) -> Result<(), StateError> {
        let deposited = self.get_deposited(asset_type);
        let withdrawn = self.get_withdrawn(asset_type);

        if withdrawn > deposited {
            return Err(StateError::SupplyInvariantViolated {
                minted: deposited.value(),
                burned: withdrawn.value(),
                expected: deposited.value(),
                actual: withdrawn.value(),
            });
        }

        Ok(())
    }

    /// Get all asset types tracked on this chain
    pub fn get_tracked_assets(&self) -> Vec<AssetType> {
        let mut assets: Vec<AssetType> = self.deposited.keys()
            .chain(self.withdrawn.keys())
            .copied()
            .collect();
        assets.sort_unstable();
        assets.dedup();
        assets
    }

    /// Get summary of supply for all assets
    pub fn get_supply_summary(&self) -> Vec<(AssetType, Amount, Amount, Amount)> {
        let assets = self.get_tracked_assets();
        assets.iter().map(|&asset_type| {
            let deposited = self.get_deposited(asset_type);
            let withdrawn = self.get_withdrawn(asset_type);
            let net = self.get_net_supply(asset_type);
            (asset_type, deposited, withdrawn, net)
        }).collect()
    }

    /// Get the size of the ingress tree
    pub fn ingress_size(&self) -> usize {
        self.ingress_tree.num_leaves()
    }

    /// Get the size of the exit tree
    pub fn exit_size(&self) -> usize {
        self.exit_tree.num_leaves()
    }

    /// Compute commitment to this chain's state
    pub fn commitment(&self) -> F {
        let roots = self.get_roots();
        poseidon_hash(&[
            F::from(self.chain_id as u64),
            roots.ingress_root,
            roots.exit_root,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_chain_state_creation() {
        let chain = ChainState::new(1, ChainType::EVM, 32);
        assert_eq!(chain.chain_id, 1);
        assert_eq!(chain.chain_type, ChainType::EVM);
        assert_eq!(chain.ingress_size(), 0);
        assert_eq!(chain.exit_size(), 0);
    }

    #[test]
    fn test_process_ingress() {
        let mut chain = ChainState::new(1, ChainType::EVM, 32);
        let mut rng = thread_rng();

        let receipt = IngressReceipt {
            source_chain: 1,
            asset_type: 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 1,
            aux: F::from(0),
        };

        let proof = chain.process_ingress(&receipt).unwrap();

        assert_eq!(chain.ingress_size(), 1);
        assert_eq!(chain.get_deposited(1), Amount::from(1000u64));
        assert_eq!(chain.get_net_supply(1), Amount::from(1000u64));
        assert_ne!(proof.old_roots, proof.new_roots);
    }

    #[test]
    fn test_process_exit() {
        let mut chain = ChainState::new(1, ChainType::EVM, 32);
        let mut rng = thread_rng();

        // First deposit
        let ingress = IngressReceipt {
            source_chain: 1,
            asset_type: 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 1,
            aux: F::from(0),
        };
        chain.process_ingress(&ingress).unwrap();

        // Then withdraw
        let exit = ExitReceipt {
            destination_chain: 1,
            asset_type: 1,
            amount: Amount::from(300u64),
            burned_nf: F::rand(&mut rng),
            nonce: 2,
            aux: F::from(0),
        };

        let proof = chain.process_exit(&exit).unwrap();

        assert_eq!(chain.exit_size(), 1);
        assert_eq!(chain.get_withdrawn(1), Amount::from(300u64));
        assert_eq!(chain.get_net_supply(1), Amount::from(700u64));
        assert_ne!(proof.old_roots, proof.new_roots);
    }

    #[test]
    fn test_insufficient_supply() {
        let mut chain = ChainState::new(1, ChainType::EVM, 32);
        let mut rng = thread_rng();

        // Try to withdraw without deposit
        let exit = ExitReceipt {
            destination_chain: 1,
            asset_type: 1,
            amount: Amount::from(100u64),
            burned_nf: F::rand(&mut rng),
            nonce: 1,
            aux: F::from(0),
        };

        let result = chain.process_exit(&exit);
        assert!(matches!(result, Err(StateError::InsufficientSupply)));
    }

    #[test]
    fn test_supply_invariant() {
        let mut chain = ChainState::new(1, ChainType::EVM, 32);
        let mut rng = thread_rng();

        let ingress = IngressReceipt {
            source_chain: 1,
            asset_type: 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 1,
            aux: F::from(0),
        };
        chain.process_ingress(&ingress).unwrap();

        // Invariant should hold
        assert!(chain.check_supply_invariant(1).is_ok());

        // Artificially break invariant
        *chain.withdrawn.entry(1).or_insert(Amount::zero()) = Amount::from(2000u64);
        assert!(chain.check_supply_invariant(1).is_err());
    }

    #[test]
    fn test_supply_summary() {
        let mut chain = ChainState::new(1, ChainType::EVM, 32);
        let mut rng = thread_rng();

        // Add multiple assets
        for asset_id in 1..=3 {
            let ingress = IngressReceipt {
                source_chain: 1,
                asset_type: asset_id,
                amount: Amount::from((asset_id * 1000) as u64),
                beneficiary_cm: F::rand(&mut rng),
                nonce: asset_id as u64,
                aux: F::from(0),
            };
            chain.process_ingress(&ingress).unwrap();
        }

        let summary = chain.get_supply_summary();
        assert_eq!(summary.len(), 3);
        assert_eq!(summary[0].0, 1); // asset_type
        assert_eq!(summary[0].1, Amount::from(1000u64)); // deposited
    }
}
