/// Multi-chain sequencer for FLUXE L2
///
/// This module provides the production sequencer implementation that:
/// - Manages transaction queues for multiple chains
/// - Automatically creates batches based on time/size thresholds
/// - Coordinates cross-chain state updates
/// - Ensures global nullifier/commitment consistency

pub mod chain_sequencer;
pub mod multi_chain;
pub mod config;

pub use chain_sequencer::ChainSequencer;
pub use multi_chain::MultiChainSequencer;
pub use config::SequencerConfig;
