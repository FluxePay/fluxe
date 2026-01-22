// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "contracts/FluxeRollupV2.sol";
import "interfaces/IGroth16Verifier.sol";

/// @title MockGroth16Verifier - Mock verifier for testing FluxeRollupV2
/// @notice Configurable mock that can be set to pass or fail verification
contract MockGroth16Verifier is IGroth16Verifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function setShouldPass(bool _shouldPass) external {
        shouldPass = _shouldPass;
    }

    function verifyProof(
        bytes calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        return shouldPass;
    }

    function verifyProofParsed(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        return shouldPass;
    }
}

/// @title FluxeRollupV2Test
/// @notice Comprehensive tests for FluxeRollupV2 three-phase lifecycle
contract FluxeRollupV2Test is Test {
    FluxeRollupV2 public rollup;
    MockGroth16Verifier public verifier;

    address public sequencer = address(0x1);
    address public owner;
    address public user = address(0x2);
    address public newSequencer = address(0x3);

    bytes32 internal constant EMPTY_STRING_KECCAK = keccak256("");

    // Events for testing
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

    event Paused(address indexed account);
    event Unpaused(address indexed account);

    // ============ Setup ============

    function setUp() public {
        owner = address(this);
        verifier = new MockGroth16Verifier(true);
        rollup = new FluxeRollupV2(address(verifier), sequencer);
    }

    // ============ Helper Functions ============

    function _createStateRoots(uint256 seed) internal pure returns (FluxeRollupV2.StateRoots memory) {
        return FluxeRollupV2.StateRoots({
            cmtRoot: bytes32(seed),
            nftRoot: bytes32(seed + 1),
            objRoot: bytes32(seed + 2),
            cbRoot: bytes32(seed + 3),
            ingressRoot: bytes32(seed + 4),
            exitRoot: bytes32(seed + 5),
            sanctionsRoot: bytes32(seed + 6),
            poolRulesRoot: bytes32(seed + 7)
        });
    }

    function _createGenesisStoredBatchInfo() internal view returns (FluxeRollupV2.StoredBatchInfo memory) {
        FluxeRollupV2.StateRoots memory genesisRoots = FluxeRollupV2.StateRoots({
            cmtRoot: bytes32(0),
            nftRoot: bytes32(0),
            objRoot: bytes32(0),
            cbRoot: bytes32(0),
            ingressRoot: bytes32(0),
            exitRoot: bytes32(0),
            sanctionsRoot: bytes32(0),
            poolRulesRoot: bytes32(0)
        });

        return FluxeRollupV2.StoredBatchInfo({
            batchId: 0,
            stateRootsHash: keccak256(abi.encode(genesisRoots)),
            timestamp: uint64(block.timestamp),
            txCount: 0,
            l2LogsTreeRoot: bytes32(0),
            priorityOperationsHash: EMPTY_STRING_KECCAK,
            commitment: bytes32(0)
        });
    }

    function _createCommitBatchInfo(
        uint64 batchId,
        FluxeRollupV2.StateRoots memory newRoots
    ) internal view returns (FluxeRollupV2.CommitBatchInfo memory) {
        return FluxeRollupV2.CommitBatchInfo({
            batchId: batchId,
            timestamp: uint64(block.timestamp),
            txCount: 10,
            newStateRoots: newRoots,
            l2LogsTreeRoot: keccak256(abi.encodePacked("l2logs", batchId)),
            priorityOperationsHash: EMPTY_STRING_KECCAK
        });
    }

    function _hashStoredBatchInfo(FluxeRollupV2.StoredBatchInfo memory batch) internal pure returns (bytes32) {
        return keccak256(abi.encode(batch));
    }

    function _createBatchCommitment(
        bytes32 prevCommitment,
        bytes32 stateRootsHash,
        bytes32 l2LogsTreeRoot,
        bytes32 priorityOperationsHash,
        uint64 timestamp,
        uint32 txCount
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            prevCommitment,
            stateRootsHash,
            l2LogsTreeRoot,
            priorityOperationsHash,
            timestamp,
            txCount
        ));
    }

    function _commitBatch(uint64 batchId) internal returns (FluxeRollupV2.StoredBatchInfo memory) {
        FluxeRollupV2.StoredBatchInfo memory prevBatch;
        if (batchId == 1) {
            prevBatch = _createGenesisStoredBatchInfo();
        } else {
            // Get previous batch info
            FluxeRollupV2.StateRoots memory prevRoots = _createStateRoots(batchId - 1);
            bytes32 prevStateRootsHash = keccak256(abi.encode(prevRoots));
            bytes32 prevL2LogsRoot = keccak256(abi.encodePacked("l2logs", batchId - 1));

            bytes32 prevPrevCommitment = batchId == 2 ? bytes32(0) : _getPrevCommitment(batchId - 1);
            bytes32 prevCommitment = _createBatchCommitment(
                prevPrevCommitment,
                prevStateRootsHash,
                prevL2LogsRoot,
                EMPTY_STRING_KECCAK,
                uint64(block.timestamp),
                10
            );

            prevBatch = FluxeRollupV2.StoredBatchInfo({
                batchId: batchId - 1,
                stateRootsHash: prevStateRootsHash,
                timestamp: uint64(block.timestamp),
                txCount: 10,
                l2LogsTreeRoot: prevL2LogsRoot,
                priorityOperationsHash: EMPTY_STRING_KECCAK,
                commitment: prevCommitment
            });
        }

        FluxeRollupV2.StateRoots memory newRoots = _createStateRoots(batchId);
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(batchId, newRoots);

        vm.prank(sequencer);
        rollup.commitBatches(prevBatch, newBatches);

        bytes32 stateRootsHash = keccak256(abi.encode(newRoots));
        bytes32 commitment = _createBatchCommitment(
            prevBatch.commitment,
            stateRootsHash,
            newBatches[0].l2LogsTreeRoot,
            EMPTY_STRING_KECCAK,
            uint64(block.timestamp),
            10
        );

        return FluxeRollupV2.StoredBatchInfo({
            batchId: batchId,
            stateRootsHash: stateRootsHash,
            timestamp: uint64(block.timestamp),
            txCount: 10,
            l2LogsTreeRoot: newBatches[0].l2LogsTreeRoot,
            priorityOperationsHash: EMPTY_STRING_KECCAK,
            commitment: commitment
        });
    }

    function _getPrevCommitment(uint64 batchId) internal pure returns (bytes32) {
        if (batchId <= 1) return bytes32(0);
        // Recursively calculate commitment chain
        FluxeRollupV2.StateRoots memory roots = FluxeRollupV2.StateRoots({
            cmtRoot: bytes32(uint256(batchId)),
            nftRoot: bytes32(uint256(batchId) + 1),
            objRoot: bytes32(uint256(batchId) + 2),
            cbRoot: bytes32(uint256(batchId) + 3),
            ingressRoot: bytes32(uint256(batchId) + 4),
            exitRoot: bytes32(uint256(batchId) + 5),
            sanctionsRoot: bytes32(uint256(batchId) + 6),
            poolRulesRoot: bytes32(uint256(batchId) + 7)
        });
        bytes32 stateRootsHash = keccak256(abi.encode(roots));
        bytes32 l2LogsRoot = keccak256(abi.encodePacked("l2logs", batchId));
        bytes32 prevCommitment = _getPrevCommitment(batchId - 1);
        return keccak256(abi.encode(
            prevCommitment,
            stateRootsHash,
            l2LogsRoot,
            EMPTY_STRING_KECCAK,
            uint64(1), // timestamp placeholder
            uint32(10)
        ));
    }

    // ============ Initial State Tests ============

    function test_InitialState() public view {
        assertEq(rollup.sequencer(), sequencer);
        assertEq(rollup.owner(), owner);
        assertEq(rollup.totalBatchesCommitted(), 0);
        assertEq(rollup.totalBatchesProved(), 0);
        assertEq(rollup.totalBatchesExecuted(), 0);
        assertFalse(rollup.paused());
    }

    function test_GenesisRoots() public view {
        FluxeRollupV2.StateRoots memory roots = rollup.getCurrentRoots();
        assertEq(roots.cmtRoot, bytes32(0));
        assertEq(roots.nftRoot, bytes32(0));
        assertEq(roots.exitRoot, bytes32(0));
    }

    function test_Constructor_RevertOnZeroVerifier() public {
        vm.expectRevert(FluxeRollupV2.ZeroAddress.selector);
        new FluxeRollupV2(address(0), sequencer);
    }

    function test_Constructor_RevertOnZeroSequencer() public {
        vm.expectRevert(FluxeRollupV2.ZeroAddress.selector);
        new FluxeRollupV2(address(verifier), address(0));
    }

    // ============ Phase 1: Commit Tests ============

    function test_CommitBatch_Single() public {
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StateRoots memory newRoots = _createStateRoots(1);

        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(1, newRoots);

        vm.prank(sequencer);
        vm.expectEmit(true, true, false, true);
        bytes32 stateRootsHash = keccak256(abi.encode(newRoots));
        bytes32 expectedCommitment = _createBatchCommitment(
            prevBatch.commitment,
            stateRootsHash,
            newBatches[0].l2LogsTreeRoot,
            EMPTY_STRING_KECCAK,
            uint64(block.timestamp),
            10
        );
        emit BatchCommitted(1, expectedCommitment, stateRootsHash, uint64(block.timestamp));

        rollup.commitBatches(prevBatch, newBatches);

        assertEq(rollup.totalBatchesCommitted(), 1);
    }

    function test_CommitBatch_Multiple() public {
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();

        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](3);
        for (uint64 i = 0; i < 3; i++) {
            newBatches[i] = _createCommitBatchInfo(i + 1, _createStateRoots(i + 1));
        }

        vm.prank(sequencer);
        rollup.commitBatches(prevBatch, newBatches);

        assertEq(rollup.totalBatchesCommitted(), 3);
    }

    function test_CommitBatch_RevertOnlySequencer() public {
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(1, _createStateRoots(1));

        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlySequencer.selector);
        rollup.commitBatches(prevBatch, newBatches);
    }

    function test_CommitBatch_RevertOnEmptyBatches() public {
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](0);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.EmptyBatchArray.selector);
        rollup.commitBatches(prevBatch, newBatches);
    }

    function test_CommitBatch_RevertOnInvalidPreviousBatch() public {
        FluxeRollupV2.StoredBatchInfo memory wrongPrevBatch = FluxeRollupV2.StoredBatchInfo({
            batchId: 0,
            stateRootsHash: bytes32(uint256(999)),
            timestamp: uint64(block.timestamp),
            txCount: 0,
            l2LogsTreeRoot: bytes32(0),
            priorityOperationsHash: EMPTY_STRING_KECCAK,
            commitment: bytes32(0)
        });

        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(1, _createStateRoots(1));

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.InvalidPreviousBatch.selector);
        rollup.commitBatches(wrongPrevBatch, newBatches);
    }

    function test_CommitBatch_RevertOnInvalidBatchId() public {
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(5, _createStateRoots(5)); // Wrong ID

        vm.prank(sequencer);
        vm.expectRevert(abi.encodeWithSelector(FluxeRollupV2.InvalidBatchId.selector, 1, 5));
        rollup.commitBatches(prevBatch, newBatches);
    }

    function test_CommitBatch_RevertWhenPaused() public {
        rollup.pause();

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(1, _createStateRoots(1));

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.ContractPaused.selector);
        rollup.commitBatches(prevBatch, newBatches);
    }

    // ============ Phase 2: Prove Tests ============

    function test_ProveBatch_Single() public {
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batchesToProve = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToProve[0] = batch1;

        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectEmit(true, true, false, false);
        emit BatchProved(1, batch1.commitment);

        rollup.proveBatches(prevBatch, batchesToProve, proof);

        assertEq(rollup.totalBatchesProved(), 1);
    }

    function test_ProveBatch_VerifiesProof() public {
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);

        verifier.setShouldPass(false);

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batchesToProve = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToProve[0] = batch1;

        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.InvalidProof.selector);
        rollup.proveBatches(prevBatch, batchesToProve, proof);
    }

    function test_ProveBatch_RevertOnEmptyBatches() public {
        _commitBatch(1);

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batchesToProve = new FluxeRollupV2.StoredBatchInfo[](0);

        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.EmptyBatchArray.selector);
        rollup.proveBatches(prevBatch, batchesToProve, proof);
    }

    function test_ProveBatch_RevertOnInvalidBatchHash() public {
        _commitBatch(1);

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batchesToProve = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToProve[0] = FluxeRollupV2.StoredBatchInfo({
            batchId: 1,
            stateRootsHash: bytes32(uint256(999)), // Wrong hash
            timestamp: uint64(block.timestamp),
            txCount: 10,
            l2LogsTreeRoot: bytes32(0),
            priorityOperationsHash: EMPTY_STRING_KECCAK,
            commitment: bytes32(0)
        });

        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.InvalidBatchHash.selector);
        rollup.proveBatches(prevBatch, batchesToProve, proof);
    }

    function test_ProveBatch_RevertOnBatchNotCommitted() public {
        // Don't commit any batches, try to prove
        // The contract first checks if the batch hash matches stored hash
        // which will fail with InvalidBatchHash since no batch was committed

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batchesToProve = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToProve[0] = FluxeRollupV2.StoredBatchInfo({
            batchId: 1,
            stateRootsHash: bytes32(uint256(1)),
            timestamp: uint64(block.timestamp),
            txCount: 10,
            l2LogsTreeRoot: bytes32(0),
            priorityOperationsHash: EMPTY_STRING_KECCAK,
            commitment: bytes32(0)
        });

        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.InvalidBatchHash.selector);
        rollup.proveBatches(prevBatch, batchesToProve, proof);
    }

    // ============ Phase 3: Execute Tests ============

    function test_ExecuteBatch_Single() public {
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);

        // Prove batch
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batchesToProve = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToProve[0] = batch1;
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        rollup.proveBatches(prevBatch, batchesToProve, proof);

        // Execute batch
        FluxeRollupV2.StoredBatchInfo[] memory batchesToExecute = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToExecute[0] = batch1;

        vm.prank(sequencer);
        vm.expectEmit(true, true, false, true);
        emit BatchExecuted(1, batch1.commitment, batch1.l2LogsTreeRoot);

        rollup.executeBatches(batchesToExecute);

        assertEq(rollup.totalBatchesExecuted(), 1);
        assertEq(rollup.getL2LogsRootHash(1), batch1.l2LogsTreeRoot);
    }

    function test_ExecuteBatch_RevertOnBatchNotProved() public {
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);

        // Skip proving, try to execute
        FluxeRollupV2.StoredBatchInfo[] memory batchesToExecute = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToExecute[0] = batch1;

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.BatchNotProved.selector);
        rollup.executeBatches(batchesToExecute);
    }

    function test_ExecuteBatch_RevertOnEmptyBatches() public {
        FluxeRollupV2.StoredBatchInfo[] memory batchesToExecute = new FluxeRollupV2.StoredBatchInfo[](0);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.EmptyBatchArray.selector);
        rollup.executeBatches(batchesToExecute);
    }

    // ============ Three-Phase Lifecycle Tests ============

    function test_FullLifecycle_SingleBatch() public {
        // Phase 1: Commit
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);
        assertEq(rollup.totalBatchesCommitted(), 1);
        assertEq(rollup.totalBatchesProved(), 0);
        assertEq(rollup.totalBatchesExecuted(), 0);

        // Phase 2: Prove
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batchesToProve = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToProve[0] = batch1;
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        rollup.proveBatches(prevBatch, batchesToProve, proof);

        assertEq(rollup.totalBatchesCommitted(), 1);
        assertEq(rollup.totalBatchesProved(), 1);
        assertEq(rollup.totalBatchesExecuted(), 0);

        // Phase 3: Execute
        FluxeRollupV2.StoredBatchInfo[] memory batchesToExecute = new FluxeRollupV2.StoredBatchInfo[](1);
        batchesToExecute[0] = batch1;

        vm.prank(sequencer);
        rollup.executeBatches(batchesToExecute);

        assertEq(rollup.totalBatchesCommitted(), 1);
        assertEq(rollup.totalBatchesProved(), 1);
        assertEq(rollup.totalBatchesExecuted(), 1);
    }

    // ============ Batch Ordering Tests ============

    function test_BatchOrdering_MustBeSequential() public {
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();

        // Try to commit batch 2 before batch 1
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(2, _createStateRoots(2));

        vm.prank(sequencer);
        vm.expectRevert(abi.encodeWithSelector(FluxeRollupV2.InvalidBatchId.selector, 1, 2));
        rollup.commitBatches(prevBatch, newBatches);
    }

    // ============ Revert Tests ============

    function test_RevertBatches_UnprovedBatches() public {
        // Commit a single batch
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StateRoots memory newRoots = _createStateRoots(1);

        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(1, newRoots);

        vm.prank(sequencer);
        rollup.commitBatches(prevBatch, newBatches);

        assertEq(rollup.totalBatchesCommitted(), 1);

        // Revert to genesis (batch 0)
        rollup.revertBatches(0);

        assertEq(rollup.totalBatchesCommitted(), 0);
        assertEq(rollup.totalBatchesProved(), 0);
    }

    function test_RevertBatches_CannotRevertExecuted() public {
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);

        // Prove and execute
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batches = new FluxeRollupV2.StoredBatchInfo[](1);
        batches[0] = batch1;

        vm.prank(sequencer);
        rollup.proveBatches(prevBatch, batches, new bytes(256));

        vm.prank(sequencer);
        rollup.executeBatches(batches);

        // Try to revert below executed
        vm.expectRevert(FluxeRollupV2.CannotRevertExecutedBatch.selector);
        rollup.revertBatches(0);
    }

    function test_RevertBatches_EmitsEvent() public {
        _commitBatch(1);
        _commitBatch(2);

        vm.expectEmit(false, false, false, true);
        emit BatchesReverted(1, 0, 0);

        rollup.revertBatches(1);
    }

    function test_RevertBatches_OnlyOwner() public {
        _commitBatch(1);

        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlyOwner.selector);
        rollup.revertBatches(0);
    }

    // ============ Sequencer Access Tests ============

    function test_SequencerOnly_CommitBatches() public {
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(1, _createStateRoots(1));

        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlySequencer.selector);
        rollup.commitBatches(prevBatch, newBatches);
    }

    function test_SequencerOnly_ProveBatches() public {
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batches = new FluxeRollupV2.StoredBatchInfo[](1);
        batches[0] = batch1;

        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlySequencer.selector);
        rollup.proveBatches(prevBatch, batches, new bytes(256));
    }

    function test_SequencerOnly_ExecuteBatches() public {
        FluxeRollupV2.StoredBatchInfo memory batch1 = _commitBatch(1);

        // Prove as sequencer
        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.StoredBatchInfo[] memory batches = new FluxeRollupV2.StoredBatchInfo[](1);
        batches[0] = batch1;

        vm.prank(sequencer);
        rollup.proveBatches(prevBatch, batches, new bytes(256));

        // Try to execute as user
        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlySequencer.selector);
        rollup.executeBatches(batches);
    }

    // ============ Sequencer Transfer Tests ============

    function test_SequencerTransfer_TwoStep() public {
        vm.expectEmit(true, true, false, false);
        emit SequencerTransferInitiated(sequencer, newSequencer);

        rollup.initiateSequencerTransfer(newSequencer);
        assertEq(rollup.pendingSequencer(), newSequencer);

        vm.prank(newSequencer);
        vm.expectEmit(true, true, false, false);
        emit SequencerTransferred(sequencer, newSequencer);

        rollup.acceptSequencer();

        assertEq(rollup.sequencer(), newSequencer);
        assertEq(rollup.pendingSequencer(), address(0));
    }

    function test_SequencerTransfer_RevertOnZeroAddress() public {
        vm.expectRevert(FluxeRollupV2.ZeroAddress.selector);
        rollup.initiateSequencerTransfer(address(0));
    }

    function test_SequencerTransfer_RevertOnNonPending() public {
        rollup.initiateSequencerTransfer(newSequencer);

        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlyPendingSequencer.selector);
        rollup.acceptSequencer();
    }

    // ============ Pause/Unpause Tests ============

    function test_Pause() public {
        vm.expectEmit(true, false, false, false);
        emit Paused(owner);

        rollup.pause();
        assertTrue(rollup.paused());
    }

    function test_Unpause() public {
        rollup.pause();

        vm.expectEmit(true, false, false, false);
        emit Unpaused(owner);

        rollup.unpause();
        assertFalse(rollup.paused());
    }

    function test_Pause_OnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlyOwner.selector);
        rollup.pause();
    }

    function test_Unpause_OnlyOwner() public {
        rollup.pause();

        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlyOwner.selector);
        rollup.unpause();
    }

    function test_WhenPaused_AllPhasesFail() public {
        rollup.pause();

        FluxeRollupV2.StoredBatchInfo memory prevBatch = _createGenesisStoredBatchInfo();
        FluxeRollupV2.CommitBatchInfo[] memory newBatches = new FluxeRollupV2.CommitBatchInfo[](1);
        newBatches[0] = _createCommitBatchInfo(1, _createStateRoots(1));

        // Commit should fail
        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.ContractPaused.selector);
        rollup.commitBatches(prevBatch, newBatches);

        // Prove should fail
        FluxeRollupV2.StoredBatchInfo[] memory batches = new FluxeRollupV2.StoredBatchInfo[](1);
        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.ContractPaused.selector);
        rollup.proveBatches(prevBatch, batches, new bytes(256));

        // Execute should fail
        vm.prank(sequencer);
        vm.expectRevert(FluxeRollupV2.ContractPaused.selector);
        rollup.executeBatches(batches);
    }

    // ============ View Function Tests ============

    function test_GetCurrentRoots() public view {
        FluxeRollupV2.StateRoots memory roots = rollup.getCurrentRoots();
        // Genesis roots should all be zero
        assertEq(roots.cmtRoot, bytes32(0));
    }

    function test_GetRoots() public view {
        FluxeRollupV2.StateRoots memory roots = rollup.getRoots(0);
        assertEq(roots.cmtRoot, bytes32(0));
    }

    function test_VerifyRoot() public view {
        // Verify genesis roots
        assertTrue(rollup.verifyRoot(0, 0, bytes32(0))); // cmtRoot
        assertTrue(rollup.verifyRoot(0, 1, bytes32(0))); // nftRoot
        assertTrue(rollup.verifyRoot(0, 5, bytes32(0))); // exitRoot

        // Invalid root type returns false
        assertFalse(rollup.verifyRoot(0, 8, bytes32(0)));
    }

    function test_GetStoredBatchHash() public view {
        bytes32 genesisHash = rollup.getStoredBatchHash(0);
        assertTrue(genesisHash != bytes32(0));
    }

    function test_GetPriorityQueueSize() public view {
        assertEq(rollup.getPriorityQueueSize(), 0);
    }

    // ============ Priority Queue Tests ============

    function test_AddPriorityRequest() public {
        bytes32 txHash = keccak256("priorityTx");
        uint64 expiration = uint64(block.timestamp + 1000);

        rollup.addPriorityRequest(txHash, expiration);

        assertEq(rollup.getPriorityQueueSize(), 1);
    }

    function test_AddPriorityRequest_OnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlyOwner.selector);
        rollup.addPriorityRequest(bytes32(0), 0);
    }

    // ============ Ownership Transfer Tests ============

    function test_TransferOwnership() public {
        address newOwner = address(0x5);

        rollup.transferOwnership(newOwner);
        assertEq(rollup.owner(), newOwner);
    }

    function test_TransferOwnership_RevertOnZeroAddress() public {
        vm.expectRevert(FluxeRollupV2.ZeroAddress.selector);
        rollup.transferOwnership(address(0));
    }

    function test_TransferOwnership_OnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(FluxeRollupV2.OnlyOwner.selector);
        rollup.transferOwnership(user);
    }
}
