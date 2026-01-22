// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../FluxeRollup.sol";
import "../interfaces/IGroth16Verifier.sol";

/// @title MockVerifier - Mock verifier for testing
contract MockVerifier is IGroth16Verifier {
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

contract FluxeRollupTest is Test {
    FluxeRollup public rollup;
    MockVerifier public verifier;

    address public sequencer = address(0x1);
    address public owner;
    address public user = address(0x2);

    function setUp() public {
        owner = address(this);
        verifier = new MockVerifier(true);
        rollup = new FluxeRollup(address(verifier), sequencer);
    }

    function test_InitialState() public view {
        assertEq(rollup.sequencer(), sequencer);
        assertEq(rollup.owner(), owner);
        assertEq(rollup.lastFinalizedBatchId(), 0);
        assertEq(rollup.paused(), false);
    }

    function test_GetGenesisRoots() public view {
        FluxeRollup.StateRoots memory roots = rollup.getCurrentRoots();
        assertEq(roots.cmtRoot, bytes32(0));
        assertEq(roots.nftRoot, bytes32(0));
        assertEq(roots.exitRoot, bytes32(0));
    }

    function test_SubmitBatch() public {
        FluxeRollup.StateRoots memory prevRoots = FluxeRollup.StateRoots({
            cmtRoot: bytes32(0),
            nftRoot: bytes32(0),
            objRoot: bytes32(0),
            cbRoot: bytes32(0),
            ingressRoot: bytes32(0),
            exitRoot: bytes32(0),
            sanctionsRoot: bytes32(0),
            poolRulesRoot: bytes32(0)
        });

        FluxeRollup.StateRoots memory newRoots = FluxeRollup.StateRoots({
            cmtRoot: bytes32(uint256(1)),
            nftRoot: bytes32(uint256(2)),
            objRoot: bytes32(uint256(3)),
            cbRoot: bytes32(uint256(4)),
            ingressRoot: bytes32(uint256(5)),
            exitRoot: bytes32(uint256(6)),
            sanctionsRoot: bytes32(uint256(7)),
            poolRulesRoot: bytes32(uint256(8))
        });

        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        rollup.submitBatch(1, prevRoots, newRoots, proof, 10);

        assertEq(rollup.lastFinalizedBatchId(), 1);

        FluxeRollup.StateRoots memory storedRoots = rollup.getRoots(1);
        assertEq(storedRoots.cmtRoot, newRoots.cmtRoot);
        assertEq(storedRoots.exitRoot, newRoots.exitRoot);
    }

    function test_SubmitBatchOnlySequencer() public {
        FluxeRollup.StateRoots memory prevRoots;
        FluxeRollup.StateRoots memory newRoots;
        bytes memory proof = new bytes(256);

        vm.prank(user);
        vm.expectRevert(FluxeRollup.OnlySequencer.selector);
        rollup.submitBatch(1, prevRoots, newRoots, proof, 10);
    }

    function test_SubmitBatchInvalidBatchId() public {
        FluxeRollup.StateRoots memory prevRoots;
        FluxeRollup.StateRoots memory newRoots;
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectRevert(abi.encodeWithSelector(
            FluxeRollup.InvalidBatchId.selector,
            1,
            5
        ));
        rollup.submitBatch(5, prevRoots, newRoots, proof, 10);
    }

    function test_SubmitBatchInvalidPreviousRoots() public {
        // First submit batch 1
        FluxeRollup.StateRoots memory prevRoots;
        FluxeRollup.StateRoots memory newRoots = FluxeRollup.StateRoots({
            cmtRoot: bytes32(uint256(1)),
            nftRoot: bytes32(0),
            objRoot: bytes32(0),
            cbRoot: bytes32(0),
            ingressRoot: bytes32(0),
            exitRoot: bytes32(0),
            sanctionsRoot: bytes32(0),
            poolRulesRoot: bytes32(0)
        });
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        rollup.submitBatch(1, prevRoots, newRoots, proof, 10);

        // Try to submit batch 2 with wrong prevRoots
        FluxeRollup.StateRoots memory wrongPrevRoots = FluxeRollup.StateRoots({
            cmtRoot: bytes32(uint256(999)),
            nftRoot: bytes32(0),
            objRoot: bytes32(0),
            cbRoot: bytes32(0),
            ingressRoot: bytes32(0),
            exitRoot: bytes32(0),
            sanctionsRoot: bytes32(0),
            poolRulesRoot: bytes32(0)
        });

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollup.InvalidPreviousRoots.selector);
        rollup.submitBatch(2, wrongPrevRoots, newRoots, proof, 10);
    }

    function test_SubmitBatchInvalidProof() public {
        verifier.setShouldPass(false);

        FluxeRollup.StateRoots memory prevRoots;
        FluxeRollup.StateRoots memory newRoots;
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollup.InvalidProof.selector);
        rollup.submitBatch(1, prevRoots, newRoots, proof, 10);
    }

    function test_Pause() public {
        rollup.pause();
        assertTrue(rollup.paused());

        FluxeRollup.StateRoots memory prevRoots;
        FluxeRollup.StateRoots memory newRoots;
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        vm.expectRevert(FluxeRollup.ContractPaused.selector);
        rollup.submitBatch(1, prevRoots, newRoots, proof, 10);
    }

    function test_Unpause() public {
        rollup.pause();
        assertTrue(rollup.paused());

        rollup.unpause();
        assertFalse(rollup.paused());
    }

    function test_SequencerTransfer() public {
        address newSequencer = address(0x3);

        rollup.initiateSequencerTransfer(newSequencer);
        assertEq(rollup.pendingSequencer(), newSequencer);

        vm.prank(newSequencer);
        rollup.acceptSequencer();

        assertEq(rollup.sequencer(), newSequencer);
        assertEq(rollup.pendingSequencer(), address(0));
    }

    function test_SequencerTransferOnlyPending() public {
        address newSequencer = address(0x3);
        rollup.initiateSequencerTransfer(newSequencer);

        vm.prank(user);
        vm.expectRevert(FluxeRollup.OnlyPendingSequencer.selector);
        rollup.acceptSequencer();
    }

    function test_VerifyRoot() public {
        FluxeRollup.StateRoots memory prevRoots;
        FluxeRollup.StateRoots memory newRoots = FluxeRollup.StateRoots({
            cmtRoot: bytes32(uint256(123)),
            nftRoot: bytes32(uint256(456)),
            objRoot: bytes32(0),
            cbRoot: bytes32(0),
            ingressRoot: bytes32(0),
            exitRoot: bytes32(uint256(789)),
            sanctionsRoot: bytes32(0),
            poolRulesRoot: bytes32(0)
        });
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        rollup.submitBatch(1, prevRoots, newRoots, proof, 10);

        // Verify correct roots
        assertTrue(rollup.verifyRoot(1, 0, bytes32(uint256(123)))); // cmt
        assertTrue(rollup.verifyRoot(1, 1, bytes32(uint256(456)))); // nft
        assertTrue(rollup.verifyRoot(1, 5, bytes32(uint256(789)))); // exit

        // Verify incorrect root
        assertFalse(rollup.verifyRoot(1, 0, bytes32(uint256(999))));
    }

    function test_GetBatchMetadata() public {
        FluxeRollup.StateRoots memory prevRoots;
        FluxeRollup.StateRoots memory newRoots;
        bytes memory proof = new bytes(256);

        vm.prank(sequencer);
        rollup.submitBatch(1, prevRoots, newRoots, proof, 42);

        FluxeRollup.BatchMetadata memory meta = rollup.getBatchMetadata(1);
        assertEq(meta.batchId, 1);
        assertEq(meta.txCount, 42);
        assertTrue(meta.timestamp > 0);
    }
}
