// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/ISP1Verifier.sol";

/// @title FluxeRollup - State root commitment contract for FLUXE L2
/// @notice Manages batch submissions and state root finalization using SP1 ZK proofs
/// @dev Only the sequencer can submit batches; anyone can verify state
///
/// ## IVC (Incrementally Verifiable Computation) Architecture
///
/// FLUXE uses IVC where each block proof recursively verifies the previous block:
/// 1. Genesis block (batch_id=0) establishes initial state with no transactions
/// 2. Each subsequent block proof includes verification of previous block proof
/// 3. The latest proof cryptographically guarantees ALL history validity
/// 4. This contract only verifies the latest proof - IVC ensures chain integrity
///
/// ## Historical Root Buffer
///
/// A 64-slot circular buffer stores recent state root hashes, enabling:
/// - UTXO spending proofs to reference historical states
/// - ~10 minutes of history at 10-second block intervals
///
/// ## Public Values Format (from SP1 BatchOutput)
///
/// The SP1 program commits the following public values (serialized):
/// - old_roots_hash: bytes32 - SHA256 of previous state tree roots
/// - new_roots_hash: bytes32 - SHA256 of new state tree roots
/// - batch_id: uint64 - Sequential batch identifier
/// - chain_id: uint32 - Target chain identifier
/// - proof_count: uint32 - Number of individual proofs verified
contract FluxeRollup {
    /// @notice State roots structure matching FLUXE core types
    struct StateRoots {
        bytes32 cmtRoot;        // Global commitment tree root
        bytes32 nftRoot;        // Global nullifier tree root
        bytes32 objRoot;        // Global object tree root
        bytes32 cbRoot;         // Global callback tree root
        bytes32 ingressRoot;    // Chain-specific ingress tree root
        bytes32 exitRoot;       // Chain-specific exit tree root
        bytes32 sanctionsRoot;  // Sanctions list root
        bytes32 poolRulesRoot;  // Pool rules root
    }

    /// @notice Batch metadata
    struct BatchMetadata {
        uint64 batchId;
        uint64 timestamp;
        uint32 txCount;
        bytes32 stateRootsHash;
    }

    // ============ Constants ============

    /// @notice FLUXE block program verification key (IVC-enabled)
    /// @dev Generated from SP1 program ELF. Same vkey used for genesis and all blocks.
    /// To regenerate: cargo run --release --bin extract_vk -p fluxe-aggregation-script
    bytes32 public constant FLUXE_BLOCK_VKEY = 0x00331d2a466af052f5758e7029f9980698a09eb91384bac07237461fe1d81645;

    /// @notice FLUXE L2 network identifier
    /// @dev This is the L2 chain ID, NOT the settlement chain (Ethereum/Solana)
    /// All settlement contracts verify the same L2 chain ID
    uint32 public constant FLUXE_L2_CHAIN_ID = 0xF1C5E; // "FLUXE" = 989278

    /// @notice Size of historical roots circular buffer
    /// @dev Stores ~10 minutes of history at 10-second block intervals
    uint8 public constant HISTORICAL_ROOTS_SIZE = 64;

    // ============ State Variables ============

    /// @notice SP1 proof verifier (gateway or direct verifier)
    ISP1Verifier public immutable verifier;

    /// @notice Authorized sequencer address
    address public sequencer;

    /// @notice Pending sequencer for two-step transfer
    address public pendingSequencer;

    /// @notice Owner address for administrative functions
    address public owner;

    /// @notice Last finalized batch ID
    uint64 public lastFinalizedBatchId;

    /// @notice Hash of the last finalized state roots
    /// @dev Used for state continuity checks with IVC
    bytes32 public lastFinalizedRootsHash;

    /// @notice Mapping of batch ID to finalized state roots
    mapping(uint64 => StateRoots) public finalizedBatches;

    /// @notice Mapping of batch ID to metadata
    mapping(uint64 => BatchMetadata) public batchMetadata;

    /// @notice Historical roots circular buffer for UTXO spending proofs
    /// @dev Stores recent state root hashes; transactions can reference any of these
    bytes32[64] public historicalRoots;

    /// @notice Next write index in historical roots buffer
    uint8 public nextRootIndex;

    /// @notice Whether genesis block has been finalized
    /// @dev Genesis must be finalized before any regular batches
    bool public genesisFinalized;

    /// @notice Whether the contract is paused
    bool public paused;

    // ============ Events ============

    event GenesisFinalized(
        bytes32 indexed stateRootsHash,
        uint64 timestamp
    );

    event BatchSubmitted(
        uint64 indexed batchId,
        bytes32 indexed stateRootsHash,
        uint32 txCount,
        uint64 timestamp
    );

    event SequencerTransferInitiated(
        address indexed currentSequencer,
        address indexed pendingSequencer
    );

    event SequencerTransferred(
        address indexed previousSequencer,
        address indexed newSequencer
    );

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    event Paused(address indexed account);
    event Unpaused(address indexed account);

    // ============ Errors ============

    error InvalidBatchId(uint64 expected, uint64 received);
    error InvalidPreviousRoots();
    error InvalidProof();
    error InvalidChainId(uint32 expected, uint32 received);
    error InvalidPublicValues();
    error OnlySequencer();
    error OnlyOwner();
    error OnlyPendingSequencer();
    error ContractPaused();
    error ZeroAddress();
    error NoPendingSequencer();
    error GenesisAlreadyFinalized();
    error GenesisNotFinalized();
    error InvalidGenesisState();

    // ============ Modifiers ============

    modifier onlySequencer() {
        if (msg.sender != sequencer) revert OnlySequencer();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    // ============ Constructor ============

    /// @notice Initialize the rollup contract
    /// @param _verifier Address of the SP1 verifier (use SP1VerifierGateway for automatic routing)
    /// @param _sequencer Initial sequencer address
    constructor(address _verifier, address _sequencer) {
        if (_verifier == address(0)) revert ZeroAddress();
        if (_sequencer == address(0)) revert ZeroAddress();

        verifier = ISP1Verifier(_verifier);
        sequencer = _sequencer;
        owner = msg.sender;
        // Note: genesisFinalized defaults to false
        // Genesis must be submitted via finalizeGenesis() before any batches
    }

    // ============ External Functions ============

    /// @notice Finalize genesis block (batch_id = 0) with SP1 proof
    /// @dev Genesis has no transactions and old_roots == new_roots
    /// Must be called before any regular batch submissions
    /// @param publicValues SP1 public values (serialized BatchOutput)
    /// @param proofBytes SP1 proof bytes (Groth16 or PLONK wrapped)
    function finalizeGenesis(
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external onlySequencer whenNotPaused {
        // Can only finalize genesis once
        if (genesisFinalized) revert GenesisAlreadyFinalized();

        // Decode and validate public values
        if (publicValues.length != 80) revert InvalidPublicValues();

        bytes32 proofOldRootsHash;
        bytes32 proofNewRootsHash;
        uint64 proofBatchId;
        uint32 proofChainId;
        uint32 proofCount;

        assembly {
            let ptr := publicValues.offset
            proofOldRootsHash := calldataload(ptr)
            proofNewRootsHash := calldataload(add(ptr, 32))
            proofBatchId := shr(192, calldataload(add(ptr, 64)))
            proofChainId := shr(224, calldataload(add(ptr, 72)))
            proofCount := shr(224, calldataload(add(ptr, 76)))
        }

        // Genesis constraints
        if (proofBatchId != 0) revert InvalidBatchId(0, proofBatchId);
        if (proofChainId != FLUXE_L2_CHAIN_ID) revert InvalidChainId(FLUXE_L2_CHAIN_ID, proofChainId);
        if (proofCount != 0) revert InvalidGenesisState(); // No transactions in genesis
        if (proofOldRootsHash != proofNewRootsHash) revert InvalidGenesisState(); // No state change

        // Verify the SP1 proof
        try verifier.verifyProof(FLUXE_BLOCK_VKEY, publicValues, proofBytes) {
            // Verification succeeded
        } catch {
            revert InvalidProof();
        }

        // Finalize genesis state
        lastFinalizedBatchId = 0;
        lastFinalizedRootsHash = proofNewRootsHash;
        genesisFinalized = true;

        // Add genesis root to historical buffer
        _addHistoricalRoot(proofNewRootsHash);

        // Store metadata
        batchMetadata[0] = BatchMetadata({
            batchId: 0,
            timestamp: uint64(block.timestamp),
            txCount: 0,
            stateRootsHash: proofNewRootsHash
        });

        emit GenesisFinalized(proofNewRootsHash, uint64(block.timestamp));
    }

    /// @notice Submit a new batch with SP1 state transition proof (IVC-enabled)
    /// @dev IVC guarantees previous block validity - we only verify the latest proof
    /// @param publicValues SP1 public values (serialized BatchOutput from SP1 program)
    /// @param proofBytes SP1 proof bytes (Groth16 or PLONK wrapped)
    function submitBatch(
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external onlySequencer whenNotPaused {
        // Genesis must be finalized first
        if (!genesisFinalized) revert GenesisNotFinalized();

        // Decode and validate public values from SP1 proof
        // Format: old_roots_hash (32) | new_roots_hash (32) | batch_id (8) | chain_id (4) | proof_count (4)
        if (publicValues.length != 80) revert InvalidPublicValues();

        bytes32 proofOldRootsHash;
        bytes32 proofNewRootsHash;
        uint64 proofBatchId;
        uint32 proofChainId;
        uint32 proofCount;

        assembly {
            let ptr := publicValues.offset
            proofOldRootsHash := calldataload(ptr)
            proofNewRootsHash := calldataload(add(ptr, 32))
            proofBatchId := shr(192, calldataload(add(ptr, 64)))
            proofChainId := shr(224, calldataload(add(ptr, 72)))
            proofCount := shr(224, calldataload(add(ptr, 76)))
        }

        // Validate chain ID matches FLUXE L2
        if (proofChainId != FLUXE_L2_CHAIN_ID) {
            revert InvalidChainId(FLUXE_L2_CHAIN_ID, proofChainId);
        }

        // Validate batch ID is sequential
        if (proofBatchId != lastFinalizedBatchId + 1) {
            revert InvalidBatchId(lastFinalizedBatchId + 1, proofBatchId);
        }

        // Validate state continuity: old_roots_hash must match last finalized
        // IVC guarantees this is valid if proof verifies, but we check for defense-in-depth
        if (proofOldRootsHash != lastFinalizedRootsHash) {
            revert InvalidPreviousRoots();
        }

        // Verify the SP1 proof
        // This is the ONLY verification needed - IVC guarantees all prior blocks
        try verifier.verifyProof(FLUXE_BLOCK_VKEY, publicValues, proofBytes) {
            // Verification succeeded
        } catch {
            revert InvalidProof();
        }

        // Update finalized state
        lastFinalizedBatchId = proofBatchId;
        lastFinalizedRootsHash = proofNewRootsHash;

        // Add new root to historical buffer
        _addHistoricalRoot(proofNewRootsHash);

        // Store batch metadata
        batchMetadata[proofBatchId] = BatchMetadata({
            batchId: proofBatchId,
            timestamp: uint64(block.timestamp),
            txCount: proofCount,
            stateRootsHash: proofNewRootsHash
        });

        emit BatchSubmitted(proofBatchId, proofNewRootsHash, proofCount, uint64(block.timestamp));
    }

    /// @notice Get current finalized state roots hash
    /// @return Hash of current state roots
    function getCurrentRootsHash() external view returns (bytes32) {
        return lastFinalizedRootsHash;
    }

    /// @notice Get batch metadata
    /// @param batchId Batch ID to query
    /// @return Batch metadata
    function getBatchMetadata(uint64 batchId) external view returns (BatchMetadata memory) {
        return batchMetadata[batchId];
    }

    /// @notice Check if a root hash exists in the historical roots buffer
    /// @dev Zero hash is always valid (used for empty/padding slots)
    /// @param rootHash Root hash to check
    /// @return True if root exists in buffer
    function containsHistoricalRoot(bytes32 rootHash) external view returns (bool) {
        if (rootHash == bytes32(0)) return true;
        for (uint8 i = 0; i < HISTORICAL_ROOTS_SIZE; i++) {
            if (historicalRoots[i] == rootHash) return true;
        }
        return false;
    }

    /// @notice Get all historical roots
    /// @return Array of 64 historical root hashes
    function getHistoricalRoots() external view returns (bytes32[64] memory) {
        return historicalRoots;
    }

    // ============ Admin Functions ============

    /// @notice Initiate sequencer transfer (two-step process)
    /// @param newSequencer Address of new sequencer
    function initiateSequencerTransfer(address newSequencer) external onlyOwner {
        if (newSequencer == address(0)) revert ZeroAddress();
        pendingSequencer = newSequencer;
        emit SequencerTransferInitiated(sequencer, newSequencer);
    }

    /// @notice Accept sequencer role (called by pending sequencer)
    function acceptSequencer() external {
        if (msg.sender != pendingSequencer) revert OnlyPendingSequencer();
        if (pendingSequencer == address(0)) revert NoPendingSequencer();

        address oldSequencer = sequencer;
        sequencer = pendingSequencer;
        pendingSequencer = address(0);

        emit SequencerTransferred(oldSequencer, sequencer);
    }

    /// @notice Transfer ownership
    /// @param newOwner Address of new owner
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /// @notice Pause the contract
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause the contract
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ============ Internal Functions ============

    /// @notice Add a root hash to the historical roots circular buffer
    /// @param rootHash Hash to add
    function _addHistoricalRoot(bytes32 rootHash) internal {
        historicalRoots[nextRootIndex] = rootHash;
        nextRootIndex = (nextRootIndex + 1) % HISTORICAL_ROOTS_SIZE;
    }
}
