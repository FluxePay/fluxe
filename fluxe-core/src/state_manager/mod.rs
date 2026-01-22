/// State management for the Fluxe protocol
///
/// This module provides state management functionality at multiple levels:
///
/// ## Global State Management
/// - `GlobalStateManager`: Manages the canonical protocol state across all chains
/// - `GlobalStateManagerHandle`: Thread-safe wrapper for concurrent access
///
/// ## Per-Chain State Management
/// - `ChainState`: Tracks ingress/exit for a specific external chain
///
/// ## Legacy State Management
/// - `StateManager`: Original single-chain state manager (for backward compatibility)
///
/// ## Architecture
///
/// The state management is organized in a hierarchical structure:
///
/// ```text
/// GlobalStateManager
/// ├── Global Trees (cross-chain)
/// │   ├── Commitment Tree (CMT)
/// │   ├── Nullifier Tree (NFT)
/// │   ├── Object Board (OBJ)
/// │   └── Callback Board (CB)
/// │
/// └── Per-Chain States
///     ├── Chain 1 (Ethereum)
///     │   ├── Ingress Tree
///     │   └── Exit Tree
///     ├── Chain 2 (Base)
///     │   ├── Ingress Tree
///     │   └── Exit Tree
///     └── ...
/// ```
///
/// ## Usage Example
///
/// ```ignore
/// use fluxe_core::state_manager::{GlobalStateManager, GlobalStateManagerHandle};
/// use fluxe_core::types::ChainType;
///
/// // Create global state manager
/// let mut manager = GlobalStateManager::new(32);
///
/// // Register chains
/// manager.register_chain(1, ChainType::EVM).unwrap();
/// manager.register_chain(2, ChainType::SVM).unwrap();
///
/// // Process mint from chain 1
/// let receipt = IngressReceipt { /* ... */ };
/// let commitments = vec![/* ... */];
/// let proof = manager.process_mint(1, &receipt, &commitments).unwrap();
///
/// // For multi-threaded access, use handle
/// let handle = GlobalStateManagerHandle::new(manager);
/// let handle_clone = handle.clone();
///
/// // Thread 1: Read
/// let state = handle.read();
/// let roots = state.get_global_roots();
///
/// // Thread 2: Write
/// let mut state = handle_clone.write();
/// state.process_transfer(&nullifiers, &commitments).unwrap();
/// ```

// Public modules
pub mod global;
pub mod chain_state;

// Legacy module (backward compatibility)
pub mod legacy;

// Re-export main types from global module
pub use global::{
    GlobalStateManager,
    GlobalStateManagerHandle,
    NonMembershipProof,
};

// Re-export chain state types
pub use chain_state::ChainState;

// Re-export legacy types for backward compatibility
// Note: The legacy module exports StateManager with the original API
pub use legacy::StateManager;
