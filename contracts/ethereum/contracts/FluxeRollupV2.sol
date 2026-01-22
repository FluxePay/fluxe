// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IGroth16Verifier.sol";

/// @title FluxeRollupV2 - Enhanced state root commitment contract with three-phase lifecycle
/// @notice Implements zkSync-style commit -> prove -> execute batch lifecycle
/// @dev Supports batch commitment, proof verification, and finalization with priority queue
contract FluxeRollupV2 {
    // ============ Type Definitions ============

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

    /// @notice Batch data submitted during commit phase
    struct CommitBatchInfo {
        uint64 batchId;
        uint64 timestamp;
        uint32 txCount;
        StateRoots newStateRoots;
        bytes32 l2LogsTreeRoot;
        bytes32 priorityOperationsHash;
    }

    /// @notice Stored batch info after commitment
    struct StoredBatchInfo {
        uint64 batchId;
        bytes32 stateRootsHash;
        uint64 timestamp;
        uint32 txCount;
        bytes32 l2LogsTreeRoot;
        bytes32 priorityOperationsHash;
        bytes32 commitment;
    }

    /// @notice Priority operation structure for L1 -> L2 transactions
    struct PriorityOperation {
        bytes32 canonicalTxHash;
        uint64 expirationTimestamp;
        uint192 layer2Tip;
    }

    // ============ Constants ============

    /// @notice Empty string keccak hash used for priority operations chain
    bytes32 internal constant EMPTY_STRING_KECCAK = keccak256("");

    // ============ State Variables ============

    /// @notice Groth16 proof verifier contract
    IGroth16Verifier public immutable verifier;

    /// @notice Authorized sequencer address
    address public sequencer;

    /// @notice Pending sequencer for two-step transfer
    address public pendingSequencer;

    /// @notice Owner address for administrative functions
    address public owner;

    /// @notice Whether the contract is paused
    bool public paused;

    /// @notice Total number of batches committed
    uint64 public totalBatchesCommitted;

    /// @notice Total number of batches proved
    uint64 public totalBatchesProved;

    /// @notice Total number of batches executed
    uint64 public totalBatchesExecuted;

    /// @notice Mapping of batch ID to stored batch hash
    mapping(uint64 => bytes32) public storedBatchHashes;

    /// @notice Mapping of batch ID to L2 logs root hash
    mapping(uint64 => bytes32) public l2LogsRootHashes;

    /// @notice Mapping of batch ID to finalized state roots
    mapping(uint64 => StateRoots) public finalizedBatches;

    /// @notice Priority operations queue
    PriorityOperation[] public priorityQueue;
    uint64 public priorityQueueHead;
    uint64 public priorityQueueTail;

    // ============ Events ============

    event BatchCommitted(
        uint64 indexed batchId,
        bytes32 indexed commitment,
        bytes32 stateRootsHash,
        uint64 timestamp
    );

    event BatchProved(
        uint64 indexed batchId,
        bytes32 indexed commitment
    );

    event BatchExecuted(
        uint64 indexed batchId,
        bytes32 indexed commitment,
        bytes32 l2LogsTreeRoot
    );

    event BatchesReverted(
        uint64 totalBatchesCommitted,
        uint64 totalBatchesProved,
        uint64 totalBatchesExecuted
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

    event NewPriorityRequest(
        uint64 indexed priorityOpId,
        bytes32 canonicalTxHash,
        uint64 expirationTimestamp
    );

    // ============ Errors ============

    error InvalidBatchId(uint64 expected, uint64 received);
    error InvalidPreviousBatch();
    error InvalidProof();
    error InvalidBatchHash();
    error InvalidPriorityOperationsHash();
    error BatchNotCommitted();
    error BatchNotProved();
    error BatchAlreadyProved();
    error BatchAlreadyExecuted();
    error CannotRevertExecutedBatch();
    error OnlySequencer();
    error OnlyOwner();
    error OnlyPendingSequencer();
    error ContractPaused();
    error ZeroAddress();
    error NoPendingSequencer();
    error EmptyBatchArray();
    error ProofBatchMismatch();

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

        // Initialize genesis batch
        StateRoots memory genesisRoots = StateRoots({
            cmtRoot: bytes32(0),
            nftRoot: bytes32(0),
            objRoot: bytes32(0),
            cbRoot: bytes32(0),
            ingressRoot: bytes32(0),
            exitRoot: bytes32(0),
            sanctionsRoot: bytes32(0),
            poolRulesRoot: bytes32(0)
        });

        StoredBatchInfo memory genesisBatch = StoredBatchInfo({
            batchId: 0,
            stateRootsHash: keccak256(abi.encode(genesisRoots)),
            timestamp: uint64(block.timestamp),
            txCount: 0,
            l2LogsTreeRoot: bytes32(0),
            priorityOperationsHash: EMPTY_STRING_KECCAK,
            commitment: bytes32(0)
        });

        storedBatchHashes[0] = _hashStoredBatchInfo(genesisBatch);
        finalizedBatches[0] = genesisRoots;
    }

    // ============ Phase 1: Commit Batches ============

    /// @notice Commit new batches (Phase 1)
    /// @dev Sequencer submits batch data, stores commitment hash
    /// @param _lastCommittedBatch Previous committed batch info for validation
    /// @param _newBatches Array of new batches to commit
    function commitBatches(
        StoredBatchInfo calldata _lastCommittedBatch,
        CommitBatchInfo[] calldata _newBatches
    ) external onlySequencer whenNotPaused {
        if (_newBatches.length == 0) revert EmptyBatchArray();

        // Verify the previous batch hash matches
        if (storedBatchHashes[totalBatchesCommitted] != _hashStoredBatchInfo(_lastCommittedBatch)) {
            revert InvalidPreviousBatch();
        }

        StoredBatchInfo memory lastBatch = _lastCommittedBatch;

        for (uint256 i = 0; i < _newBatches.length; i++) {
            lastBatch = _commitOneBatch(lastBatch, _newBatches[i]);
            storedBatchHashes[lastBatch.batchId] = _hashStoredBatchInfo(lastBatch);

            emit BatchCommitted(
                lastBatch.batchId,
                lastBatch.commitment,
                lastBatch.stateRootsHash,
                lastBatch.timestamp
            );
        }

        totalBatchesCommitted += uint64(_newBatches.length);
    }

    /// @dev Process one batch commit
    function _commitOneBatch(
        StoredBatchInfo memory _previousBatch,
        CommitBatchInfo calldata _newBatch
    ) internal pure returns (StoredBatchInfo memory) {
        // Validate batch ID is sequential
        if (_newBatch.batchId != _previousBatch.batchId + 1) {
            revert InvalidBatchId(_previousBatch.batchId + 1, _newBatch.batchId);
        }

        bytes32 stateRootsHash = keccak256(abi.encode(_newBatch.newStateRoots));

        // Create commitment from batch data
        bytes32 commitment = _createBatchCommitment(
            _previousBatch.commitment,
            stateRootsHash,
            _newBatch.l2LogsTreeRoot,
            _newBatch.priorityOperationsHash,
            _newBatch.timestamp,
            _newBatch.txCount
        );

        return StoredBatchInfo({
            batchId: _newBatch.batchId,
            stateRootsHash: stateRootsHash,
            timestamp: _newBatch.timestamp,
            txCount: _newBatch.txCount,
            l2LogsTreeRoot: _newBatch.l2LogsTreeRoot,
            priorityOperationsHash: _newBatch.priorityOperationsHash,
            commitment: commitment
        });
    }

    /// @dev Create batch commitment hash
    function _createBatchCommitment(
        bytes32 _previousCommitment,
        bytes32 _stateRootsHash,
        bytes32 _l2LogsTreeRoot,
        bytes32 _priorityOperationsHash,
        uint64 _timestamp,
        uint32 _txCount
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            _previousCommitment,
            _stateRootsHash,
            _l2LogsTreeRoot,
            _priorityOperationsHash,
            _timestamp,
            _txCount
        ));
    }

    // ============ Phase 2: Prove Batches ============

    /// @notice Prove committed batches with Groth16 proof (Phase 2)
    /// @param _previousBatch The last proved batch
    /// @param _committedBatches Array of committed batches to prove
    /// @param _proof Groth16 proof data
    function proveBatches(
        StoredBatchInfo calldata _previousBatch,
        StoredBatchInfo[] calldata _committedBatches,
        bytes calldata _proof
    ) external onlySequencer whenNotPaused {
        if (_committedBatches.length == 0) revert EmptyBatchArray();

        uint64 currentTotalProved = totalBatchesProved;

        // Verify the previous batch is the last proved batch
        if (storedBatchHashes[currentTotalProved] != _hashStoredBatchInfo(_previousBatch)) {
            revert InvalidPreviousBatch();
        }

        // Build public inputs for proof verification
        uint256[] memory publicInputs = _buildProofPublicInputs(_previousBatch, _committedBatches);

        // Verify all committed batches exist and are in order
        for (uint256 i = 0; i < _committedBatches.length; i++) {
            uint64 expectedBatchId = currentTotalProved + uint64(i) + 1;

            if (_committedBatches[i].batchId != expectedBatchId) {
                revert InvalidBatchId(expectedBatchId, _committedBatches[i].batchId);
            }

            if (storedBatchHashes[_committedBatches[i].batchId] != _hashStoredBatchInfo(_committedBatches[i])) {
                revert InvalidBatchHash();
            }
        }

        // Cannot prove more than committed
        if (currentTotalProved + uint64(_committedBatches.length) > totalBatchesCommitted) {
            revert BatchNotCommitted();
        }

        // Verify the aggregated proof
        if (!verifier.verifyProof(_proof, publicInputs)) {
            revert InvalidProof();
        }

        // Update proved count and emit events
        for (uint256 i = 0; i < _committedBatches.length; i++) {
            emit BatchProved(
                _committedBatches[i].batchId,
                _committedBatches[i].commitment
            );
        }

        totalBatchesProved = currentTotalProved + uint64(_committedBatches.length);
    }

    /// @dev Build public inputs array for proof verification
    function _buildProofPublicInputs(
        StoredBatchInfo calldata _previousBatch,
        StoredBatchInfo[] calldata _committedBatches
    ) internal pure returns (uint256[] memory) {
        // Public inputs: previous commitment + all batch commitments
        uint256[] memory inputs = new uint256[](_committedBatches.length + 1);

        inputs[0] = uint256(_previousBatch.commitment);

        for (uint256 i = 0; i < _committedBatches.length; i++) {
            inputs[i + 1] = uint256(_committedBatches[i].commitment);
        }

        return inputs;
    }

    // ============ Phase 3: Execute Batches ============

    /// @notice Execute proved batches, finalize state (Phase 3)
    /// @dev Processes priority queue and stores final state roots
    /// @param _batchesData Array of proved batches to execute
    function executeBatches(
        StoredBatchInfo[] calldata _batchesData
    ) external onlySequencer whenNotPaused {
        if (_batchesData.length == 0) revert EmptyBatchArray();

        uint64 currentTotalExecuted = totalBatchesExecuted;

        for (uint256 i = 0; i < _batchesData.length; i++) {
            _executeOneBatch(_batchesData[i], i);
        }

        // Cannot execute more than proved
        if (currentTotalExecuted + uint64(_batchesData.length) > totalBatchesProved) {
            revert BatchNotProved();
        }

        totalBatchesExecuted = currentTotalExecuted + uint64(_batchesData.length);
    }

    /// @dev Execute one batch
    function _executeOneBatch(
        StoredBatchInfo calldata _storedBatch,
        uint256 _executedBatchIdx
    ) internal {
        uint64 expectedBatchId = totalBatchesExecuted + uint64(_executedBatchIdx) + 1;

        // Verify batch is in order
        if (_storedBatch.batchId != expectedBatchId) {
            revert InvalidBatchId(expectedBatchId, _storedBatch.batchId);
        }

        // Verify batch hash matches stored
        if (storedBatchHashes[_storedBatch.batchId] != _hashStoredBatchInfo(_storedBatch)) {
            revert InvalidBatchHash();
        }

        // Process priority operations
        bytes32 priorityOpsHash = _collectPriorityOperations(_storedBatch.priorityOperationsHash);
        if (priorityOpsHash != _storedBatch.priorityOperationsHash) {
            revert InvalidPriorityOperationsHash();
        }

        // Store L2 logs root hash for merkle proof verification
        l2LogsRootHashes[_storedBatch.batchId] = _storedBatch.l2LogsTreeRoot;

        emit BatchExecuted(
            _storedBatch.batchId,
            _storedBatch.commitment,
            _storedBatch.l2LogsTreeRoot
        );
    }

    /// @dev Process priority operations from queue
    function _collectPriorityOperations(bytes32 _expectedHash) internal returns (bytes32) {
        bytes32 concatHash = EMPTY_STRING_KECCAK;

        while (priorityQueueHead < priorityQueueTail) {
            bytes32 newHash = keccak256(abi.encode(
                concatHash,
                priorityQueue[priorityQueueHead].canonicalTxHash
            ));

            if (keccak256(abi.encode(newHash)) == keccak256(abi.encode(_expectedHash))) {
                priorityQueueHead++;
                return newHash;
            }

            concatHash = newHash;
            priorityQueueHead++;

            if (concatHash == _expectedHash) {
                return concatHash;
            }
        }

        return concatHash;
    }

    // ============ Revert Batches ============

    /// @notice Revert uncommitted/unproved batches
    /// @param _newLastBatch The new last valid batch ID
    function revertBatches(uint64 _newLastBatch) external onlyOwner {
        if (_newLastBatch < totalBatchesExecuted) {
            revert CannotRevertExecutedBatch();
        }

        uint64 newTotalCommitted = _newLastBatch > totalBatchesExecuted
            ? _newLastBatch
            : totalBatchesExecuted;

        if (newTotalCommitted < totalBatchesProved) {
            totalBatchesProved = newTotalCommitted;
        }

        totalBatchesCommitted = newTotalCommitted;

        emit BatchesReverted(
            totalBatchesCommitted,
            totalBatchesProved,
            totalBatchesExecuted
        );
    }

    // ============ View Functions ============

    /// @notice Get current finalized state roots
    function getCurrentRoots() external view returns (StateRoots memory) {
        return finalizedBatches[totalBatchesExecuted];
    }

    /// @notice Get state roots for a specific batch
    function getRoots(uint64 batchId) external view returns (StateRoots memory) {
        return finalizedBatches[batchId];
    }

    /// @notice Get stored batch hash
    function getStoredBatchHash(uint64 batchId) external view returns (bytes32) {
        return storedBatchHashes[batchId];
    }

    /// @notice Get L2 logs root hash for a batch
    function getL2LogsRootHash(uint64 batchId) external view returns (bytes32) {
        return l2LogsRootHashes[batchId];
    }

    /// @notice Verify a state root exists in a finalized batch
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

    /// @notice Get number of pending priority operations
    function getPriorityQueueSize() external view returns (uint64) {
        return priorityQueueTail - priorityQueueHead;
    }

    // ============ Priority Queue Functions ============

    /// @notice Add a priority operation to the queue
    /// @dev Called by bridge contracts for L1 -> L2 transactions
    function addPriorityRequest(
        bytes32 _canonicalTxHash,
        uint64 _expirationTimestamp
    ) external onlyOwner {
        priorityQueue.push(PriorityOperation({
            canonicalTxHash: _canonicalTxHash,
            expirationTimestamp: _expirationTimestamp,
            layer2Tip: 0
        }));

        emit NewPriorityRequest(
            priorityQueueTail,
            _canonicalTxHash,
            _expirationTimestamp
        );

        priorityQueueTail++;
    }

    // ============ Admin Functions ============

    /// @notice Initiate sequencer transfer (two-step process)
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

    /// @notice Hash a StoredBatchInfo struct
    function _hashStoredBatchInfo(StoredBatchInfo memory _storedBatch) internal pure returns (bytes32) {
        return keccak256(abi.encode(_storedBatch));
    }

    /// @notice Store state roots for executed batch
    /// @dev Called internally after batch execution
    function _storeStateRoots(uint64 batchId, StateRoots memory roots) internal {
        finalizedBatches[batchId] = roots;
    }
}
