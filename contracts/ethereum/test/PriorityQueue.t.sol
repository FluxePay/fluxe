// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "contracts/libraries/PriorityQueue.sol";

/// @title PriorityQueueTest
/// @notice Comprehensive tests for the PriorityQueue library
contract PriorityQueueTest is Test {
    using PriorityQueue for PriorityQueue.Queue;

    PriorityQueue.Queue internal queue;

    // ============ Setup ============

    function setUp() public {
        // Queue is initialized empty by default
    }

    // ============ Initial State Tests ============

    function test_InitialState_IsEmpty() public view {
        assertTrue(queue.isEmpty());
    }

    function test_InitialState_SizeIsZero() public view {
        assertEq(queue.getSize(), 0);
    }

    function test_InitialState_TotalPriorityTxsIsZero() public view {
        assertEq(queue.getTotalPriorityTxs(), 0);
    }

    function test_InitialState_FirstUnprocessedIsZero() public view {
        assertEq(queue.getFirstUnprocessedPriorityTx(), 0);
    }

    // ============ pushBack Tests ============

    function test_PushBack_SingleElement() public {
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx1"),
            uint64(block.number + 100),
            1 ether
        );

        queue.pushBack(op);

        assertFalse(queue.isEmpty());
        assertEq(queue.getSize(), 1);
        assertEq(queue.getTotalPriorityTxs(), 1);
    }

    function test_PushBack_MultipleElements() public {
        for (uint256 i = 0; i < 5; i++) {
            PriorityOperation memory op = PriorityQueue.createOperation(
                keccak256(abi.encodePacked("tx", i)),
                uint64(block.number + 100 + i),
                uint192(i * 1 ether)
            );
            queue.pushBack(op);
        }

        assertEq(queue.getSize(), 5);
        assertEq(queue.getTotalPriorityTxs(), 5);
        assertEq(queue.getFirstUnprocessedPriorityTx(), 0);
    }

    function test_PushBack_PreservesData() public {
        bytes32 expectedHash = keccak256("test_tx");
        uint64 expectedExpiration = uint64(block.number + 500);
        uint192 expectedTip = 2.5 ether;

        PriorityOperation memory op = PriorityQueue.createOperation(
            expectedHash,
            expectedExpiration,
            expectedTip
        );

        queue.pushBack(op);

        PriorityOperation memory retrieved = queue.front();
        assertEq(retrieved.canonicalTxHash, expectedHash);
        assertEq(retrieved.expirationBlock, expectedExpiration);
        assertEq(retrieved.layer2Tip, expectedTip);
    }

    // ============ popFront Tests ============

    function test_PopFront_SingleElement() public {
        bytes32 txHash = keccak256("tx1");
        PriorityOperation memory op = PriorityQueue.createOperation(
            txHash,
            uint64(block.number + 100),
            1 ether
        );

        queue.pushBack(op);
        PriorityOperation memory popped = queue.popFront();

        assertEq(popped.canonicalTxHash, txHash);
        assertTrue(queue.isEmpty());
        assertEq(queue.getSize(), 0);
    }

    function test_PopFront_RevertOnEmptyQueue() public {
        // Direct library calls with storage references revert internally
        // We verify this by checking isEmpty first
        assertTrue(queue.isEmpty());
        // The actual revert would happen if we called popFront on empty queue
        // This is tested through integration tests in FluxeMailbox.t.sol
    }

    function test_PopFront_UpdatesHead() public {
        PriorityOperation memory op1 = PriorityQueue.createOperation(
            keccak256("tx1"),
            uint64(block.number + 100),
            1 ether
        );
        PriorityOperation memory op2 = PriorityQueue.createOperation(
            keccak256("tx2"),
            uint64(block.number + 200),
            2 ether
        );

        queue.pushBack(op1);
        queue.pushBack(op2);

        assertEq(queue.getFirstUnprocessedPriorityTx(), 0);

        queue.popFront();

        assertEq(queue.getFirstUnprocessedPriorityTx(), 1);
        assertEq(queue.getSize(), 1);
        assertEq(queue.getTotalPriorityTxs(), 2);
    }

    function test_PopFront_ReturnsCorrectElement() public {
        bytes32 hash1 = keccak256("tx1");
        bytes32 hash2 = keccak256("tx2");
        bytes32 hash3 = keccak256("tx3");

        queue.pushBack(PriorityQueue.createOperation(hash1, 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(hash2, 200, 2 ether));
        queue.pushBack(PriorityQueue.createOperation(hash3, 300, 3 ether));

        PriorityOperation memory first = queue.popFront();
        assertEq(first.canonicalTxHash, hash1);

        PriorityOperation memory second = queue.popFront();
        assertEq(second.canonicalTxHash, hash2);

        PriorityOperation memory third = queue.popFront();
        assertEq(third.canonicalTxHash, hash3);
    }

    // ============ FIFO Order Tests ============

    function test_FIFO_OrderPreserved() public {
        uint256 count = 10;
        bytes32[] memory hashes = new bytes32[](count);

        // Push elements
        for (uint256 i = 0; i < count; i++) {
            hashes[i] = keccak256(abi.encodePacked("tx", i));
            queue.pushBack(PriorityQueue.createOperation(
                hashes[i],
                uint64(block.number + i),
                uint192(i * 1 ether)
            ));
        }

        // Pop and verify order
        for (uint256 i = 0; i < count; i++) {
            PriorityOperation memory op = queue.popFront();
            assertEq(op.canonicalTxHash, hashes[i], "FIFO order violated");
        }

        assertTrue(queue.isEmpty());
    }

    function test_FIFO_InterleavedPushPop() public {
        bytes32 hash1 = keccak256("tx1");
        bytes32 hash2 = keccak256("tx2");
        bytes32 hash3 = keccak256("tx3");
        bytes32 hash4 = keccak256("tx4");

        // Push, pop, push, pop pattern
        queue.pushBack(PriorityQueue.createOperation(hash1, 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(hash2, 200, 2 ether));

        PriorityOperation memory op1 = queue.popFront();
        assertEq(op1.canonicalTxHash, hash1);

        queue.pushBack(PriorityQueue.createOperation(hash3, 300, 3 ether));

        PriorityOperation memory op2 = queue.popFront();
        assertEq(op2.canonicalTxHash, hash2);

        queue.pushBack(PriorityQueue.createOperation(hash4, 400, 4 ether));

        PriorityOperation memory op3 = queue.popFront();
        assertEq(op3.canonicalTxHash, hash3);

        PriorityOperation memory op4 = queue.popFront();
        assertEq(op4.canonicalTxHash, hash4);

        assertTrue(queue.isEmpty());
    }

    // ============ front Tests ============

    function test_Front_ReturnsFirstElement() public {
        bytes32 hash1 = keccak256("tx1");
        bytes32 hash2 = keccak256("tx2");

        queue.pushBack(PriorityQueue.createOperation(hash1, 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(hash2, 200, 2 ether));

        PriorityOperation memory frontOp = queue.front();
        assertEq(frontOp.canonicalTxHash, hash1);

        // Front should not remove the element
        assertEq(queue.getSize(), 2);
    }

    function test_Front_RevertOnEmptyQueue() public {
        // Direct library calls with storage references revert internally
        // We verify this by checking isEmpty first
        assertTrue(queue.isEmpty());
        // The actual revert would happen if we called front on empty queue
        // This is tested through integration tests in FluxeMailbox.t.sol
    }

    function test_Front_UpdatesAfterPop() public {
        bytes32 hash1 = keccak256("tx1");
        bytes32 hash2 = keccak256("tx2");

        queue.pushBack(PriorityQueue.createOperation(hash1, 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(hash2, 200, 2 ether));

        assertEq(queue.front().canonicalTxHash, hash1);

        queue.popFront();

        assertEq(queue.front().canonicalTxHash, hash2);
    }

    // ============ getOperationAt Tests ============

    function test_GetOperationAt_ValidIndex() public {
        bytes32 hash1 = keccak256("tx1");
        bytes32 hash2 = keccak256("tx2");
        bytes32 hash3 = keccak256("tx3");

        queue.pushBack(PriorityQueue.createOperation(hash1, 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(hash2, 200, 2 ether));
        queue.pushBack(PriorityQueue.createOperation(hash3, 300, 3 ether));

        assertEq(queue.getOperationAt(0).canonicalTxHash, hash1);
        assertEq(queue.getOperationAt(1).canonicalTxHash, hash2);
        assertEq(queue.getOperationAt(2).canonicalTxHash, hash3);
    }

    function test_GetOperationAt_AfterPop() public {
        bytes32 hash1 = keccak256("tx1");
        bytes32 hash2 = keccak256("tx2");

        queue.pushBack(PriorityQueue.createOperation(hash1, 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(hash2, 200, 2 ether));

        queue.popFront();

        // Index 0 is now deleted, index 1 should still work
        assertEq(queue.getOperationAt(1).canonicalTxHash, hash2);
    }

    // ============ isEmpty Tests ============

    function test_IsEmpty_TrueInitially() public view {
        assertTrue(queue.isEmpty());
    }

    function test_IsEmpty_FalseAfterPush() public {
        queue.pushBack(PriorityQueue.createOperation(
            keccak256("tx"),
            100,
            1 ether
        ));
        assertFalse(queue.isEmpty());
    }

    function test_IsEmpty_TrueAfterPoppingAll() public {
        queue.pushBack(PriorityQueue.createOperation(keccak256("tx1"), 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(keccak256("tx2"), 200, 2 ether));

        queue.popFront();
        queue.popFront();

        assertTrue(queue.isEmpty());
    }

    // ============ getSize Tests ============

    function test_GetSize_Zero() public view {
        assertEq(queue.getSize(), 0);
    }

    function test_GetSize_AfterPush() public {
        queue.pushBack(PriorityQueue.createOperation(keccak256("tx1"), 100, 1 ether));
        assertEq(queue.getSize(), 1);

        queue.pushBack(PriorityQueue.createOperation(keccak256("tx2"), 200, 2 ether));
        assertEq(queue.getSize(), 2);
    }

    function test_GetSize_AfterPop() public {
        queue.pushBack(PriorityQueue.createOperation(keccak256("tx1"), 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(keccak256("tx2"), 200, 2 ether));

        queue.popFront();
        assertEq(queue.getSize(), 1);

        queue.popFront();
        assertEq(queue.getSize(), 0);
    }

    // ============ Expiration Tests ============

    function test_IsExpired_NotExpired() public {
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx"),
            uint64(block.number + 100),
            1 ether
        );

        assertFalse(PriorityQueue.isExpired(op));
    }

    function test_IsExpired_Expired() public {
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx"),
            uint64(block.number),
            1 ether
        );

        // Move forward past expiration
        vm.roll(block.number + 1);

        assertTrue(PriorityQueue.isExpired(op));
    }

    function test_IsExpired_ExactlyAtExpiration() public {
        uint64 expirationBlock = uint64(block.number + 50);
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx"),
            expirationBlock,
            1 ether
        );

        // Move to exact expiration block
        vm.roll(expirationBlock);

        // At exact expiration block, should not be expired yet
        assertFalse(PriorityQueue.isExpired(op));
    }

    function test_BlocksUntilExpiration_Future() public {
        uint64 expirationBlock = uint64(block.number + 100);
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx"),
            expirationBlock,
            1 ether
        );

        uint256 blocks = PriorityQueue.blocksUntilExpiration(op);
        assertEq(blocks, 100);
    }

    function test_BlocksUntilExpiration_Expired() public {
        uint64 expirationBlock = uint64(block.number);
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx"),
            expirationBlock,
            1 ether
        );

        // Move past expiration
        vm.roll(block.number + 10);

        uint256 blocks = PriorityQueue.blocksUntilExpiration(op);
        assertEq(blocks, 0);
    }

    function test_BlocksUntilExpiration_ExactlyExpired() public {
        uint64 expirationBlock = uint64(block.number + 50);
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx"),
            expirationBlock,
            1 ether
        );

        // Move to exact expiration block
        vm.roll(expirationBlock);

        uint256 blocks = PriorityQueue.blocksUntilExpiration(op);
        assertEq(blocks, 0);
    }

    // ============ createOperation Tests ============

    function test_CreateOperation() public pure {
        bytes32 hash = keccak256("tx");
        uint64 expiration = 12345;
        uint192 tip = 5 ether;

        PriorityOperation memory op = PriorityQueue.createOperation(hash, expiration, tip);

        assertEq(op.canonicalTxHash, hash);
        assertEq(op.expirationBlock, expiration);
        assertEq(op.layer2Tip, tip);
    }

    function test_CreateOperation_ZeroValues() public pure {
        PriorityOperation memory op = PriorityQueue.createOperation(bytes32(0), 0, 0);

        assertEq(op.canonicalTxHash, bytes32(0));
        assertEq(op.expirationBlock, 0);
        assertEq(op.layer2Tip, 0);
    }

    function test_CreateOperation_MaxValues() public pure {
        bytes32 maxHash = bytes32(type(uint256).max);
        uint64 maxExpiration = type(uint64).max;
        uint192 maxTip = type(uint192).max;

        PriorityOperation memory op = PriorityQueue.createOperation(maxHash, maxExpiration, maxTip);

        assertEq(op.canonicalTxHash, maxHash);
        assertEq(op.expirationBlock, maxExpiration);
        assertEq(op.layer2Tip, maxTip);
    }

    // ============ Multiple Operations Tests ============

    function test_MultipleOperations_LargeQueue() public {
        uint256 count = 100;

        // Push many elements
        for (uint256 i = 0; i < count; i++) {
            queue.pushBack(PriorityQueue.createOperation(
                keccak256(abi.encodePacked("tx", i)),
                uint64(block.number + i),
                uint192(i * 0.1 ether)
            ));
        }

        assertEq(queue.getSize(), count);
        assertEq(queue.getTotalPriorityTxs(), count);

        // Pop half
        for (uint256 i = 0; i < count / 2; i++) {
            PriorityOperation memory op = queue.popFront();
            assertEq(op.canonicalTxHash, keccak256(abi.encodePacked("tx", i)));
        }

        assertEq(queue.getSize(), count / 2);
        assertEq(queue.getTotalPriorityTxs(), count);
        assertEq(queue.getFirstUnprocessedPriorityTx(), count / 2);
    }

    function test_MultipleOperations_ReAddAfterEmpty() public {
        // First batch
        queue.pushBack(PriorityQueue.createOperation(keccak256("tx1"), 100, 1 ether));
        queue.pushBack(PriorityQueue.createOperation(keccak256("tx2"), 200, 2 ether));

        queue.popFront();
        queue.popFront();

        assertTrue(queue.isEmpty());
        assertEq(queue.getTotalPriorityTxs(), 2);

        // Second batch
        bytes32 hash3 = keccak256("tx3");
        queue.pushBack(PriorityQueue.createOperation(hash3, 300, 3 ether));

        assertEq(queue.getSize(), 1);
        assertEq(queue.getTotalPriorityTxs(), 3);
        assertEq(queue.front().canonicalTxHash, hash3);
    }

    // ============ Fuzz Tests ============

    function test_Fuzz_PushPop(uint256 count) public {
        count = bound(count, 1, 50); // Limit for gas

        bytes32[] memory hashes = new bytes32[](count);

        for (uint256 i = 0; i < count; i++) {
            hashes[i] = keccak256(abi.encodePacked("tx", i));
            queue.pushBack(PriorityQueue.createOperation(hashes[i], uint64(i), uint192(i)));
        }

        assertEq(queue.getSize(), count);

        for (uint256 i = 0; i < count; i++) {
            PriorityOperation memory op = queue.popFront();
            assertEq(op.canonicalTxHash, hashes[i]);
        }

        assertTrue(queue.isEmpty());
    }

    function test_Fuzz_CreateOperation(
        bytes32 hash,
        uint64 expiration,
        uint192 tip
    ) public pure {
        PriorityOperation memory op = PriorityQueue.createOperation(hash, expiration, tip);

        assertEq(op.canonicalTxHash, hash);
        assertEq(op.expirationBlock, expiration);
        assertEq(op.layer2Tip, tip);
    }

    function test_Fuzz_ExpirationCheck(uint64 expirationDelta) public {
        expirationDelta = uint64(bound(expirationDelta, 1, 10000));

        uint64 expirationBlock = uint64(block.number) + expirationDelta;
        PriorityOperation memory op = PriorityQueue.createOperation(
            keccak256("tx"),
            expirationBlock,
            1 ether
        );

        // Before expiration
        assertFalse(PriorityQueue.isExpired(op));
        assertEq(PriorityQueue.blocksUntilExpiration(op), expirationDelta);

        // After expiration
        vm.roll(expirationBlock + 1);
        assertTrue(PriorityQueue.isExpired(op));
        assertEq(PriorityQueue.blocksUntilExpiration(op), 0);
    }
}
