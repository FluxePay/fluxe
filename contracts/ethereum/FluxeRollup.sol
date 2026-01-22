// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IGroth16Verifier.sol";

/// @title FluxeRollup - State root commitment contract for FLUXE L2
/// @notice Manages batch submissions and state root finalization
/// @dev Only the sequencer can submit batches; anyone can verify state
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

    // ============ State Variables ============

    /// @notice Groth16 proof verifier contract
    IGroth16Verifier public immutable verifier;

    /// @notice Authorized sequencer address
    address public sequencer;

    /// @notice Pending sequencer for two-step transfer
    address public pendingSequencer;

    /// @notice Owner address for administrative functions
    address public owner;

    /// @notice Last finalized batch ID
    uint64 public lastFinalizedBatchId;

    /// @notice Mapping of batch ID to finalized state roots
    mapping(uint64 => StateRoots) public finalizedBatches;

    /// @notice Mapping of batch ID to metadata
    mapping(uint64 => BatchMetadata) public batchMetadata;

    /// @notice Whether the contract is paused
    bool public paused;

    // ============ Events ============

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
    error OnlySequencer();
    error OnlyOwner();
    error OnlyPendingSequencer();
    error ContractPaused();
    error ZeroAddress();
    error NoPendingSequencer();

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
    /// @param _verifier Address of the Groth16 verifier contract
    /// @param _sequencer Initial sequencer address
    constructor(address _verifier, address _sequencer) {
        if (_verifier == address(0)) revert ZeroAddress();
        if (_sequencer == address(0)) revert ZeroAddress();

        verifier = IGroth16Verifier(_verifier);
        sequencer = _sequencer;
        owner = msg.sender;
        lastFinalizedBatchId = 0;

        // Initialize genesis state roots (all zeros)
        finalizedBatches[0] = StateRoots({
            cmtRoot: bytes32(0),
            nftRoot: bytes32(0),
            objRoot: bytes32(0),
            cbRoot: bytes32(0),
            ingressRoot: bytes32(0),
            exitRoot: bytes32(0),
            sanctionsRoot: bytes32(0),
            poolRulesRoot: bytes32(0)
        });
    }

    // ============ External Functions ============

    /// @notice Submit a new batch with state transition proof
    /// @param batchId Sequential batch identifier
    /// @param prevRoots Previous state roots (must match last finalized)
    /// @param newRoots New state roots after batch execution
    /// @param proof Groth16 proof of valid state transition
    /// @param txCount Number of transactions in the batch
    function submitBatch(
        uint64 batchId,
        StateRoots calldata prevRoots,
        StateRoots calldata newRoots,
        bytes calldata proof,
        uint32 txCount
    ) external onlySequencer whenNotPaused {
        // Validate batch ID is sequential
        if (batchId != lastFinalizedBatchId + 1) {
            revert InvalidBatchId(lastFinalizedBatchId + 1, batchId);
        }

        // Validate previous roots match last finalized state
        StateRoots storage lastRoots = finalizedBatches[lastFinalizedBatchId];
        if (!_rootsMatch(prevRoots, lastRoots)) {
            revert InvalidPreviousRoots();
        }

        // Construct public inputs for proof verification
        uint256[] memory publicInputs = _constructPublicInputs(prevRoots, newRoots);

        // Verify the aggregated proof
        if (!verifier.verifyProof(proof, publicInputs)) {
            revert InvalidProof();
        }

        // Store new finalized state
        finalizedBatches[batchId] = newRoots;
        lastFinalizedBatchId = batchId;

        // Store batch metadata
        bytes32 rootsHash = keccak256(abi.encode(newRoots));
        batchMetadata[batchId] = BatchMetadata({
            batchId: batchId,
            timestamp: uint64(block.timestamp),
            txCount: txCount,
            stateRootsHash: rootsHash
        });

        emit BatchSubmitted(batchId, rootsHash, txCount, uint64(block.timestamp));
    }

    /// @notice Get current finalized state roots
    /// @return Current state roots
    function getCurrentRoots() external view returns (StateRoots memory) {
        return finalizedBatches[lastFinalizedBatchId];
    }

    /// @notice Get state roots for a specific batch
    /// @param batchId Batch ID to query
    /// @return State roots for the batch
    function getRoots(uint64 batchId) external view returns (StateRoots memory) {
        return finalizedBatches[batchId];
    }

    /// @notice Get batch metadata
    /// @param batchId Batch ID to query
    /// @return Batch metadata
    function getBatchMetadata(uint64 batchId) external view returns (BatchMetadata memory) {
        return batchMetadata[batchId];
    }

    /// @notice Verify a state root exists in a finalized batch
    /// @param batchId Batch ID to check
    /// @param rootType Type of root (0=cmt, 1=nft, 2=obj, 3=cb, 4=ingress, 5=exit)
    /// @param root Root value to verify
    /// @return True if root matches
    function verifyRoot(uint64 batchId, uint8 rootType, bytes32 root) external view returns (bool) {
        StateRoots storage roots = finalizedBatches[batchId];

        if (rootType == 0) return roots.cmtRoot == root;
        if (rootType == 1) return roots.nftRoot == root;
        if (rootType == 2) return roots.objRoot == root;
        if (rootType == 3) return roots.cbRoot == root;
        if (rootType == 4) return roots.ingressRoot == root;
        if (rootType == 5) return roots.exitRoot == root;
        if (rootType == 6) return roots.sanctionsRoot == root;
        if (rootType == 7) return roots.poolRulesRoot == root;

        return false;
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

    /// @notice Check if two StateRoots match
    function _rootsMatch(StateRoots calldata a, StateRoots storage b) internal view returns (bool) {
        return a.cmtRoot == b.cmtRoot &&
               a.nftRoot == b.nftRoot &&
               a.objRoot == b.objRoot &&
               a.cbRoot == b.cbRoot &&
               a.ingressRoot == b.ingressRoot &&
               a.exitRoot == b.exitRoot &&
               a.sanctionsRoot == b.sanctionsRoot &&
               a.poolRulesRoot == b.poolRulesRoot;
    }

    /// @notice Construct public inputs array for proof verification
    function _constructPublicInputs(
        StateRoots calldata prevRoots,
        StateRoots calldata newRoots
    ) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](16);

        // Previous roots
        inputs[0] = uint256(prevRoots.cmtRoot);
        inputs[1] = uint256(prevRoots.nftRoot);
        inputs[2] = uint256(prevRoots.objRoot);
        inputs[3] = uint256(prevRoots.cbRoot);
        inputs[4] = uint256(prevRoots.ingressRoot);
        inputs[5] = uint256(prevRoots.exitRoot);
        inputs[6] = uint256(prevRoots.sanctionsRoot);
        inputs[7] = uint256(prevRoots.poolRulesRoot);

        // New roots
        inputs[8] = uint256(newRoots.cmtRoot);
        inputs[9] = uint256(newRoots.nftRoot);
        inputs[10] = uint256(newRoots.objRoot);
        inputs[11] = uint256(newRoots.cbRoot);
        inputs[12] = uint256(newRoots.ingressRoot);
        inputs[13] = uint256(newRoots.exitRoot);
        inputs[14] = uint256(newRoots.sanctionsRoot);
        inputs[15] = uint256(newRoots.poolRulesRoot);

        return inputs;
    }
}
