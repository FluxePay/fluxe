// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PriorityOperation
 * @notice Represents a pending L1 to L2 transaction in the priority queue
 * @dev Field sizes are optimized for storage packing into a single slot (32 bytes):
 *      - canonicalTxHash: 32 bytes (separate slot)
 *      - expirationBlock + layer2Tip: 8 + 24 = 32 bytes (packed into one slot)
 *
 * @param canonicalTxHash The keccak256 hash of the canonical L2 transaction data
 * @param expirationBlock The L1 block number by which this operation must be processed
 * @param layer2Tip Additional payment (in wei) to incentivize L2 operators to prioritize this transaction
 */
struct PriorityOperation {
    bytes32 canonicalTxHash;
    uint64 expirationBlock;
    uint192 layer2Tip;
}

/**
 * @title PriorityQueue
 * @author FLUXE Team
 * @notice A gas-efficient FIFO queue for managing L1 to L2 priority transactions
 * @dev This library implements a mapping-based queue data structure that provides O(1)
 *      operations for all queue operations. The design uses a head/tail pointer pattern
 *      where:
 *      - `head` points to the first unprocessed element
 *      - `tail` points to the next insertion position
 *      - Elements are stored in a mapping indexed by their position
 *
 *      Storage Layout:
 *      ```
 *      Queue:
 *        data: mapping(uint256 => PriorityOperation)
 *        tail: uint256 (next write position)
 *        head: uint256 (next read position)
 *      ```
 *
 *      The queue is empty when head == tail.
 *      The size is calculated as tail - head.
 *
 *      Gas Optimization Notes:
 *      - Uses mapping instead of array to avoid expensive array operations
 *      - Stores tail/head in stack variables to minimize SLOAD operations
 *      - Deletes processed entries to receive gas refunds
 *
 * @custom:security
 *      - No overflow protection needed for head/tail due to Solidity 0.8+ built-in checks
 *      - Practically impossible to overflow uint256 with block-by-block increments
 */
library PriorityQueue {
    using PriorityQueue for Queue;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when attempting to access or pop from an empty queue
    error PriorityQueueEmpty();

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice The queue container storing priority operations
     * @dev Uses a mapping for O(1) access and gas-efficient storage
     *
     * @param data Mapping from index to PriorityOperation
     * @param tail Index where the next element will be inserted (also equals total ever added)
     * @param head Index of the first unprocessed element (also equals total ever processed)
     */
    struct Queue {
        mapping(uint256 index => PriorityOperation operation) data;
        uint256 tail;
        uint256 head;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns the index of the first unprocessed priority transaction
     * @dev This value represents both the read pointer and the count of processed transactions
     *
     * @param _queue The queue to query
     * @return firstUnprocessedIndex The index of the oldest pending operation (0 if none processed yet)
     *
     * @custom:example
     * If 5 operations were added and 3 were processed:
     * - getFirstUnprocessedPriorityTx() returns 3
     * - This means indices 0, 1, 2 have been processed
     * - Index 3 is the next to be processed
     */
    function getFirstUnprocessedPriorityTx(Queue storage _queue) internal view returns (uint256 firstUnprocessedIndex) {
        return _queue.head;
    }

    /**
     * @notice Returns the total number of priority transactions ever added to the queue
     * @dev This count includes both processed and unprocessed transactions
     *
     * @param _queue The queue to query
     * @return totalCount The cumulative count of all operations ever added
     *
     * @custom:example
     * If 10 operations were added (regardless of how many were processed):
     * - getTotalPriorityTxs() returns 10
     */
    function getTotalPriorityTxs(Queue storage _queue) internal view returns (uint256 totalCount) {
        return _queue.tail;
    }

    /**
     * @notice Returns the number of unprocessed priority operations currently in the queue
     * @dev Calculated as tail - head
     *
     * @param _queue The queue to query
     * @return size The count of pending operations
     *
     * @custom:example
     * If 10 operations were added and 7 were processed:
     * - getSize() returns 3
     */
    function getSize(Queue storage _queue) internal view returns (uint256 size) {
        return _queue.tail - _queue.head;
    }

    /**
     * @notice Checks if the queue contains no pending operations
     * @dev Returns true when head equals tail
     *
     * @param _queue The queue to query
     * @return empty True if no unprocessed operations exist
     */
    function isEmpty(Queue storage _queue) internal view returns (bool empty) {
        return _queue.tail == _queue.head;
    }

    /**
     * @notice Returns the first unprocessed priority operation without removing it
     * @dev Reverts if the queue is empty
     *
     * @param _queue The queue to query
     * @return operation The oldest pending PriorityOperation
     *
     * @custom:throws PriorityQueueEmpty if the queue is empty
     */
    function front(Queue storage _queue) internal view returns (PriorityOperation memory operation) {
        if (_queue.isEmpty()) {
            revert PriorityQueueEmpty();
        }
        return _queue.data[_queue.head];
    }

    /**
     * @notice Returns the priority operation at a specific index
     * @dev Does not check if the index is valid or if the operation exists
     *      Caller must ensure index is within valid range [head, tail)
     *
     * @param _queue The queue to query
     * @param _index The absolute index of the operation
     * @return operation The PriorityOperation at the specified index
     *
     * @custom:security Caller must validate that head <= index < tail
     */
    function getOperationAt(
        Queue storage _queue,
        uint256 _index
    ) internal view returns (PriorityOperation memory operation) {
        return _queue.data[_index];
    }

    /*//////////////////////////////////////////////////////////////
                           MUTATIVE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Adds a new priority operation to the end of the queue
     * @dev Stores the operation at the current tail position and increments tail
     *
     *      Gas optimization: tail is cached in a stack variable to avoid
     *      reading from storage twice.
     *
     * @param _queue The queue to modify
     * @param _operation The PriorityOperation to add
     *
     * @custom:emits No events (caller should emit events if needed)
     *
     * @custom:example
     * ```solidity
     * PriorityOperation memory op = PriorityOperation({
     *     canonicalTxHash: keccak256(txData),
     *     expirationBlock: uint64(block.number + 100),
     *     layer2Tip: 1 ether
     * });
     * queue.pushBack(op);
     * ```
     */
    function pushBack(Queue storage _queue, PriorityOperation memory _operation) internal {
        // Cache tail in stack to avoid double SLOAD
        uint256 tail = _queue.tail;

        _queue.data[tail] = _operation;
        _queue.tail = tail + 1;
    }

    /**
     * @notice Removes and returns the first unprocessed priority operation
     * @dev Deletes the operation from storage (gas refund) and increments head
     *      Reverts if the queue is empty.
     *
     *      Gas optimization: head is cached in a stack variable to avoid
     *      reading from storage multiple times.
     *
     * @param _queue The queue to modify
     * @return operation The removed PriorityOperation
     *
     * @custom:throws PriorityQueueEmpty if the queue is empty
     *
     * @custom:example
     * ```solidity
     * PriorityOperation memory op = queue.popFront();
     * // Process the operation...
     * emit PriorityOperationProcessed(op.canonicalTxHash);
     * ```
     */
    function popFront(Queue storage _queue) internal returns (PriorityOperation memory operation) {
        if (_queue.isEmpty()) {
            revert PriorityQueueEmpty();
        }

        // Cache head in stack to avoid multiple SLOADs
        uint256 head = _queue.head;

        operation = _queue.data[head];
        delete _queue.data[head];
        _queue.head = head + 1;
    }

    /*//////////////////////////////////////////////////////////////
                           UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a new PriorityOperation struct
     * @dev Helper function for constructing operations with proper types
     *
     * @param _canonicalTxHash The hash of the L2 transaction data
     * @param _expirationBlock The L1 block deadline for processing
     * @param _layer2Tip The incentive payment for L2 operators
     * @return operation The constructed PriorityOperation
     */
    function createOperation(
        bytes32 _canonicalTxHash,
        uint64 _expirationBlock,
        uint192 _layer2Tip
    ) internal pure returns (PriorityOperation memory operation) {
        return PriorityOperation({
            canonicalTxHash: _canonicalTxHash,
            expirationBlock: _expirationBlock,
            layer2Tip: _layer2Tip
        });
    }

    /**
     * @notice Checks if a priority operation has expired
     * @dev Compares the operation's expiration block against the current block
     *
     * @param _operation The operation to check
     * @return expired True if the current block is past the expiration block
     */
    function isExpired(PriorityOperation memory _operation) internal view returns (bool expired) {
        return block.number > _operation.expirationBlock;
    }

    /**
     * @notice Returns the number of blocks until an operation expires
     * @dev Returns 0 if the operation has already expired
     *
     * @param _operation The operation to check
     * @return blocksRemaining The number of blocks until expiration (0 if expired)
     */
    function blocksUntilExpiration(PriorityOperation memory _operation) internal view returns (uint256 blocksRemaining) {
        if (block.number >= _operation.expirationBlock) {
            return 0;
        }
        return _operation.expirationBlock - block.number;
    }
}
