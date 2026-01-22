use crate::data_structures::{IngressReceipt, ExitReceipt, CallbackInvocation};
use crate::errors::StateError;
use crate::merkle::{IncrementalTree, SortedTree, MerklePath, TreeParams, SortedLeaf};
use crate::state_manager::chain_state::ChainState;
use crate::types::*;
use ark_bn254::Fr as F;
use ark_ff::Zero;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Global state manager for the unified Fluxe protocol
///
/// The GlobalStateManager maintains the canonical protocol state across all chains.
/// It manages:
/// - Global commitment tree (all note commitments)
/// - Global nullifier tree (all spent nullifiers)
/// - Global object board (zk-objects)
/// - Global callback board (callback invocations)
/// - Per-chain ingress/exit tracking via ChainState
/// - Global supply invariants
///
/// Thread Safety:
/// This struct is designed to be wrapped in Arc<RwLock<>> for multi-threaded access.
/// Use the Handle wrapper for convenient thread-safe access.
#[derive(Clone, Debug)]
pub struct GlobalStateManager {
    /// Global commitment tree (append-only) for all note commitments
    pub cmt_tree: IncrementalTree,

    /// Global nullifier tree (sorted) for all spent nullifiers
    pub nft_tree: SortedTree,

    /// Global object board (append-only) for zk-objects
    pub obj_tree: IncrementalTree,

    /// Global callback board (sorted) for callback invocations
    pub cb_tree: SortedTree,

    /// Reference roots (updated out-of-band)
    pub sanctions_root: MerkleRoot,
    pub pool_rules_root: MerkleRoot,

    /// Per-chain state managers
    pub chain_states: HashMap<ChainId, ChainState>,

    /// Global supply accounting per asset type
    /// This tracks the total supply across all chains
    pub supply: HashMap<AssetType, Supply>,

    /// Tree parameters
    pub params: TreeParams,
}

impl GlobalStateManager {
    /// Create a new global state manager
    ///
    /// # Arguments
    /// * `tree_depth` - Depth of Merkle trees
    pub fn new(tree_depth: usize) -> Self {
        let params = TreeParams::new(tree_depth);

        Self {
            cmt_tree: IncrementalTree::new(tree_depth),
            nft_tree: SortedTree::new(tree_depth),
            obj_tree: IncrementalTree::new(tree_depth),
            cb_tree: SortedTree::new(tree_depth),
            sanctions_root: F::zero(),
            pool_rules_root: F::zero(),
            chain_states: HashMap::new(),
            supply: HashMap::new(),
            params,
        }
    }

    /// Get current global state roots
    pub fn get_global_roots(&self) -> GlobalRoots {
        GlobalRoots {
            cmt_root: self.cmt_tree.root(),
            nft_root: self.nft_tree.root(),
            obj_root: self.obj_tree.root(),
            cb_root: self.cb_tree.root(),
            sanctions_root: self.sanctions_root,
            pool_rules_root: self.pool_rules_root,
        }
    }

    /// Get state roots for a specific chain
    pub fn get_chain_roots(&self, chain_id: ChainId) -> Option<ChainStateRoots> {
        self.chain_states.get(&chain_id).map(|cs| cs.get_roots())
    }

    /// Register a new chain
    ///
    /// # Arguments
    /// * `chain_id` - Unique identifier for the chain
    /// * `chain_type` - Type of chain (EVM, SVM, etc.)
    pub fn register_chain(&mut self, chain_id: ChainId, chain_type: ChainType) -> Result<(), StateError> {
        if self.chain_states.contains_key(&chain_id) {
            return Err(StateError::InvalidTransition {
                from: "registered".to_string(),
                to: "registered".to_string(),
            });
        }

        let chain_state = ChainState::new(chain_id, chain_type, self.params.height);
        self.chain_states.insert(chain_id, chain_state);
        Ok(())
    }

    /// Process a mint transaction (boundary-in from external chain)
    ///
    /// A mint occurs when assets are deposited from an external chain.
    /// This updates both the chain-specific state and the global state.
    ///
    /// # Arguments
    /// * `chain_id` - Source chain where deposit occurred
    /// * `ingress_receipt` - Receipt proving the deposit
    /// * `output_commitments` - New note commitments being created
    ///
    /// # Returns
    /// GlobalTransitionProof showing all state changes
    pub fn process_mint(
        &mut self,
        chain_id: ChainId,
        ingress_receipt: &IngressReceipt,
        output_commitments: &[Commitment],
    ) -> Result<GlobalTransitionProof, StateError> {
        let old_roots = self.get_global_roots();

        // Update chain state
        let chain_state = self.chain_states.get_mut(&chain_id)
            .ok_or_else(|| StateError::InvalidTransition {
                from: "unknown chain".to_string(),
                to: "mint".to_string(),
            })?;

        chain_state.process_ingress(ingress_receipt)?;

        // Add output commitments to global CMT tree
        for &cm in output_commitments {
            self.cmt_tree.append(cm);
        }

        // Update global supply
        let supply_entry = self.supply.entry(ingress_receipt.asset_type).or_insert(Supply::new());
        supply_entry.mint(ingress_receipt.amount);

        let new_roots = self.get_global_roots();

        Ok(GlobalTransitionProof {
            old_roots,
            new_roots,
            operations: vec![
                GlobalStateOperation::CmtAppend(output_commitments.to_vec()),
            ],
        })
    }

    /// Process a burn transaction (boundary-out to external chain)
    ///
    /// A burn occurs when assets are withdrawn to an external chain.
    /// This updates both the global state and the chain-specific state.
    ///
    /// # Arguments
    /// * `chain_id` - Destination chain for withdrawal
    /// * `exit_receipt` - Receipt proving the withdrawal
    /// * `nullifier` - Nullifier of the burned note
    ///
    /// # Returns
    /// GlobalTransitionProof showing all state changes
    pub fn process_burn(
        &mut self,
        chain_id: ChainId,
        exit_receipt: &ExitReceipt,
        nullifier: Nullifier,
    ) -> Result<GlobalTransitionProof, StateError> {
        let old_roots = self.get_global_roots();

        // Check nullifier doesn't exist (prevent double spend)
        if self.nft_tree.contains(&nullifier) {
            return Err(StateError::DoubleSpend(format!("{:?}", nullifier)));
        }

        // Add nullifier to global NFT tree
        self.nft_tree.insert(nullifier)?;

        // Update chain state
        let chain_state = self.chain_states.get_mut(&chain_id)
            .ok_or_else(|| StateError::InvalidTransition {
                from: "unknown chain".to_string(),
                to: "burn".to_string(),
            })?;

        chain_state.process_exit(exit_receipt)?;

        // Update global supply
        let supply_entry = self.supply.get_mut(&exit_receipt.asset_type)
            .ok_or(StateError::InsufficientSupply)?;

        supply_entry.burn(exit_receipt.amount)
            .map_err(|_| StateError::InsufficientSupply)?;

        let new_roots = self.get_global_roots();

        Ok(GlobalTransitionProof {
            old_roots,
            new_roots,
            operations: vec![
                GlobalStateOperation::NftInsert(nullifier),
            ],
        })
    }

    /// Process a transfer transaction (in-protocol)
    ///
    /// A transfer occurs entirely within the protocol, moving value between notes.
    /// This only affects the global state, not any chain-specific state.
    ///
    /// # Arguments
    /// * `input_nullifiers` - Nullifiers of spent input notes
    /// * `output_commitments` - Commitments of new output notes
    ///
    /// # Returns
    /// GlobalTransitionProof showing all state changes
    pub fn process_transfer(
        &mut self,
        input_nullifiers: &[Nullifier],
        output_commitments: &[Commitment],
    ) -> Result<GlobalTransitionProof, StateError> {
        let old_roots = self.get_global_roots();

        // Check all nullifiers are fresh
        for &nf in input_nullifiers {
            if self.nft_tree.contains(&nf) {
                return Err(StateError::DoubleSpend(format!("{:?}", nf)));
            }
        }

        // Add nullifiers to global NFT tree
        for &nf in input_nullifiers {
            self.nft_tree.insert(nf)?;
        }

        // Add output commitments to global CMT tree
        for &cm in output_commitments {
            self.cmt_tree.append(cm);
        }

        let new_roots = self.get_global_roots();

        Ok(GlobalTransitionProof {
            old_roots,
            new_roots,
            operations: vec![
                GlobalStateOperation::NftBatchInsert(input_nullifiers.to_vec()),
                GlobalStateOperation::CmtAppend(output_commitments.to_vec()),
            ],
        })
    }

    /// Process an object update
    ///
    /// Updates a zk-object on the global object board, optionally with a callback.
    ///
    /// # Arguments
    /// * `new_object_commitment` - Commitment to the new object state
    /// * `callback_invocation` - Optional callback invocation to add
    ///
    /// # Returns
    /// GlobalTransitionProof showing all state changes
    pub fn process_object_update(
        &mut self,
        new_object_commitment: Commitment,
        callback_invocation: Option<&CallbackInvocation>,
    ) -> Result<GlobalTransitionProof, StateError> {
        let old_roots = self.get_global_roots();

        // Add new object commitment
        self.obj_tree.append(new_object_commitment);

        // If there's a callback invocation, add it to CB tree
        let mut operations = vec![GlobalStateOperation::ObjAppend(new_object_commitment)];
        if let Some(invocation) = callback_invocation {
            let cb_hash = invocation.hash();
            self.cb_tree.insert(cb_hash)?;
            operations.push(GlobalStateOperation::CbInsert(cb_hash));
        }

        let new_roots = self.get_global_roots();

        Ok(GlobalTransitionProof {
            old_roots,
            new_roots,
            operations,
        })
    }

    /// Get Merkle proof for a commitment in the global tree
    pub fn get_commitment_proof(&self, commitment: Commitment) -> Option<MerklePath> {
        self.cmt_tree.get_proof(commitment)
    }

    /// Get non-membership proof for a nullifier
    pub fn get_nullifier_non_membership_proof(&self, nullifier: Nullifier) -> Option<NonMembershipProof> {
        self.nft_tree.get_non_membership_proof(nullifier)
    }

    /// Check if a nullifier exists
    pub fn nullifier_exists(&self, nullifier: Nullifier) -> bool {
        self.nft_tree.contains(&nullifier)
    }

    /// Get global supply for an asset type
    pub fn get_supply(&self, asset_type: AssetType) -> Amount {
        self.supply.get(&asset_type)
            .map(|s| s.current_supply())
            .unwrap_or(Amount::zero())
    }

    /// Get detailed supply info for an asset
    pub fn get_supply_info(&self, asset_type: AssetType) -> Supply {
        self.supply.get(&asset_type).cloned().unwrap_or(Supply::new())
    }

    /// Check global supply invariant
    ///
    /// Invariant: Sum of all chain net supplies == global supply
    ///
    /// For each asset:
    /// global_supply = sum(chain_deposited) - sum(chain_withdrawn)
    pub fn check_supply_invariant(&self, asset_type: AssetType) -> Result<(), StateError> {
        let global_supply = self.get_supply(asset_type);

        // Calculate total from all chains
        let mut total_deposited = Amount::zero();
        let mut total_withdrawn = Amount::zero();

        for chain_state in self.chain_states.values() {
            total_deposited = total_deposited.saturating_add(chain_state.get_deposited(asset_type));
            total_withdrawn = total_withdrawn.saturating_add(chain_state.get_withdrawn(asset_type));
        }

        let calculated_supply = total_deposited.saturating_sub(total_withdrawn);

        if calculated_supply != global_supply {
            return Err(StateError::SupplyInvariantViolated {
                minted: total_deposited.as_u128(),
                burned: total_withdrawn.as_u128(),
                expected: global_supply.as_u128(),
                actual: calculated_supply.as_u128(),
            });
        }

        Ok(())
    }

    /// Check all supply invariants across all tracked assets
    pub fn check_all_supply_invariants(&self) -> Result<(), StateError> {
        let mut all_assets: Vec<AssetType> = self.supply.keys().copied().collect();

        // Also check chain-tracked assets
        for chain_state in self.chain_states.values() {
            all_assets.extend(chain_state.get_tracked_assets());
        }

        all_assets.sort_unstable();
        all_assets.dedup();

        for asset_type in all_assets {
            self.check_supply_invariant(asset_type)?;
        }

        Ok(())
    }

    /// Update sanctions root (admin operation)
    pub fn update_sanctions_root(&mut self, new_root: MerkleRoot) {
        self.sanctions_root = new_root;
    }

    /// Update pool rules root (admin operation)
    pub fn update_pool_rules_root(&mut self, new_root: MerkleRoot) {
        self.pool_rules_root = new_root;
    }

    /// Get list of registered chains
    pub fn get_registered_chains(&self) -> Vec<ChainId> {
        let mut chains: Vec<ChainId> = self.chain_states.keys().copied().collect();
        chains.sort_unstable();
        chains
    }

    /// Get chain state reference
    pub fn get_chain_state(&self, chain_id: ChainId) -> Option<&ChainState> {
        self.chain_states.get(&chain_id)
    }

    /// Get mutable chain state reference
    pub fn get_chain_state_mut(&mut self, chain_id: ChainId) -> Option<&mut ChainState> {
        self.chain_states.get_mut(&chain_id)
    }
}

/// Non-membership proof for nullifiers
#[derive(Clone, Debug)]
pub struct NonMembershipProof {
    /// The leaf with key less than target
    pub low_leaf: SortedLeaf,
    /// Merkle path for the low leaf
    pub low_path: MerklePath,
}

/// Thread-safe handle to GlobalStateManager
///
/// This wrapper provides convenient thread-safe access to the global state.
/// Multiple threads can read concurrently, but writes are exclusive.
///
/// # Example
/// ```ignore
/// let manager = GlobalStateManager::new(32);
/// let handle = GlobalStateManagerHandle::new(manager);
///
/// // Clone handle for another thread
/// let handle_clone = handle.clone();
///
/// // Read access
/// {
///     let state = handle.read();
///     let roots = state.get_global_roots();
/// }
///
/// // Write access
/// {
///     let mut state = handle.write();
///     state.register_chain(1, ChainType::EVM).unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct GlobalStateManagerHandle {
    inner: Arc<RwLock<GlobalStateManager>>,
}

impl GlobalStateManagerHandle {
    /// Create a new handle wrapping a GlobalStateManager
    pub fn new(manager: GlobalStateManager) -> Self {
        Self {
            inner: Arc::new(RwLock::new(manager)),
        }
    }

    /// Get read access to the state manager
    ///
    /// This will block if a writer is active.
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, GlobalStateManager> {
        self.inner.read().expect("RwLock poisoned")
    }

    /// Get write access to the state manager
    ///
    /// This will block if any readers or writers are active.
    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, GlobalStateManager> {
        self.inner.write().expect("RwLock poisoned")
    }

    /// Try to get read access without blocking
    pub fn try_read(&self) -> Option<std::sync::RwLockReadGuard<'_, GlobalStateManager>> {
        self.inner.try_read().ok()
    }

    /// Try to get write access without blocking
    pub fn try_write(&self) -> Option<std::sync::RwLockWriteGuard<'_, GlobalStateManager>> {
        self.inner.try_write().ok()
    }
}

impl std::fmt::Debug for GlobalStateManagerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalStateManagerHandle")
            .field("inner", &"Arc<RwLock<GlobalStateManager>>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_global_state_manager_creation() {
        let manager = GlobalStateManager::new(32);
        assert_eq!(manager.chain_states.len(), 0);
        let roots = manager.get_global_roots();
        // Empty tree roots are non-zero (they are hashes of empty values)
        assert_ne!(roots.cmt_root, F::zero());
    }

    #[test]
    fn test_register_chain() {
        let mut manager = GlobalStateManager::new(32);
        manager.register_chain(1, ChainType::EVM).unwrap();
        assert_eq!(manager.chain_states.len(), 1);

        // Duplicate registration should fail
        let result = manager.register_chain(1, ChainType::EVM);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_mint() {
        let mut manager = GlobalStateManager::new(32);
        manager.register_chain(1, ChainType::EVM).unwrap();

        let mut rng = thread_rng();
        let receipt = IngressReceipt {
            source_chain: 1,
            asset_type: 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 1,
            aux: F::zero(),
        };

        let commitments = vec![F::rand(&mut rng), F::rand(&mut rng)];

        let proof = manager.process_mint(1, &receipt, &commitments).unwrap();

        // Check global supply updated
        assert_eq!(manager.get_supply(1), Amount::from(1000u64));

        // Check chain state updated
        let chain = manager.get_chain_state(1).unwrap();
        assert_eq!(chain.get_deposited(1), Amount::from(1000u64));

        // Check roots changed
        assert_ne!(proof.old_roots, proof.new_roots);
    }

    #[test]
    fn test_process_burn() {
        let mut manager = GlobalStateManager::new(32);
        manager.register_chain(1, ChainType::EVM).unwrap();

        let mut rng = thread_rng();

        // First mint
        let ingress = IngressReceipt {
            source_chain: 1,
            asset_type: 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 1,
            aux: F::zero(),
        };
        manager.process_mint(1, &ingress, &[F::rand(&mut rng)]).unwrap();

        // Then burn
        let nullifier = F::rand(&mut rng);
        let exit = ExitReceipt {
            destination_chain: 1,
            asset_type: 1,
            amount: Amount::from(300u64),
            burned_nf: nullifier,
            nonce: 2,
            aux: F::zero(),
        };

        let proof = manager.process_burn(1, &exit, nullifier).unwrap();

        // Check global supply updated
        assert_eq!(manager.get_supply(1), Amount::from(700u64));

        // Check nullifier added
        assert!(manager.nullifier_exists(nullifier));

        // Check roots changed
        assert_ne!(proof.old_roots, proof.new_roots);
    }

    #[test]
    fn test_process_transfer() {
        let mut manager = GlobalStateManager::new(32);
        let mut rng = thread_rng();

        let nullifiers = vec![F::rand(&mut rng), F::rand(&mut rng)];
        let commitments = vec![F::rand(&mut rng), F::rand(&mut rng)];

        let proof = manager.process_transfer(&nullifiers, &commitments).unwrap();

        // Check nullifiers added
        for nf in &nullifiers {
            assert!(manager.nullifier_exists(*nf));
        }

        // Check roots changed
        assert_ne!(proof.old_roots, proof.new_roots);

        // Double spend should fail
        let result = manager.process_transfer(&nullifiers, &commitments);
        assert!(matches!(result, Err(StateError::DoubleSpend(_))));
    }

    #[test]
    fn test_supply_invariant() {
        let mut manager = GlobalStateManager::new(32);
        manager.register_chain(1, ChainType::EVM).unwrap();
        manager.register_chain(2, ChainType::SVM).unwrap();

        let mut rng = thread_rng();

        // Mint on chain 1
        let ingress1 = IngressReceipt {
            source_chain: 1,
            asset_type: 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 1,
            aux: F::zero(),
        };
        manager.process_mint(1, &ingress1, &[F::rand(&mut rng)]).unwrap();

        // Mint on chain 2
        let ingress2 = IngressReceipt {
            source_chain: 2,
            asset_type: 1,
            amount: Amount::from(500u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 2,
            aux: F::zero(),
        };
        manager.process_mint(2, &ingress2, &[F::rand(&mut rng)]).unwrap();

        // Check global supply
        assert_eq!(manager.get_supply(1), Amount::from(1500u64));

        // Invariant should hold
        assert!(manager.check_supply_invariant(1).is_ok());
        assert!(manager.check_all_supply_invariants().is_ok());
    }

    #[test]
    fn test_handle_thread_safety() {
        let manager = GlobalStateManager::new(32);
        let handle = GlobalStateManagerHandle::new(manager);

        // Clone for another "thread"
        let handle_clone = handle.clone();

        // Write access
        {
            let mut state = handle.write();
            state.register_chain(1, ChainType::EVM).unwrap();
        }

        // Read access from clone
        {
            let state = handle_clone.read();
            assert_eq!(state.chain_states.len(), 1);
        }
    }
}
