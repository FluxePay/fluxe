// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./libraries/PriorityQueue.sol";
import "./libraries/Merkle.sol";

/// @title FluxeMailbox
/// @notice L1 <-> L2 communication contract for FLUXE rollup based on zkSync's Mailbox pattern
/// @dev Handles L1 -> L2 transaction requests and L2 -> L1 message proof verification
contract FluxeMailbox is ReentrancyGuard {
    using PriorityQueue for PriorityQueue.Queue;

    // ============ Constants ============

    /// @notice L2 -> L1 logs Merkle tree height (1024 leaves)
    uint256 public constant L2_TO_L1_LOG_MERKLE_TREE_HEIGHT = 10;

    /// @notice Maximum gas limit for priority transactions
    uint256 public constant PRIORITY_TX_MAX_GAS_LIMIT = 2_097_152;

    /// @notice Priority operation expiration in blocks (~3 days at 13s block time)
    uint256 public constant PRIORITY_EXPIRATION = 16_615;

    /// @notice L2 transaction type identifier for priority operations
    uint256 public constant PRIORITY_OPERATION_L2_TX_TYPE = 255;

    /// @notice The address of the L2 -> L1 messenger system contract
    address public constant L2_TO_L1_MESSENGER = address(0x8008);

    /// @notice Default leaf hash for L2 -> L1 logs Merkle tree
    /// @dev Used to fill incomplete tree, equal to keccak256(new bytes(88))
    bytes32 public constant L2_L1_LOGS_TREE_DEFAULT_LEAF_HASH =
        0x72abee45b59e344af8a6e520241c4744aff26ed411f4c4b00f8af09adada43ba;

    // ============ Structs ============

    /// @notice L2 log structure passed from L2 to L1
    /// @param l2ShardId The shard identifier (0 = rollup, 1 = porter)
    /// @param isService Boolean flag that is part of the log
    /// @param txNumberInBatch The L2 transaction number in a batch
    /// @param sender The L2 address which sent the log
    /// @param key 32 bytes of information sent in the log
    /// @param value 32 bytes of information sent in the log
    struct L2Log {
        uint8 l2ShardId;
        bool isService;
        uint16 txNumberInBatch;
        address sender;
        bytes32 key;
        bytes32 value;
    }

    /// @notice Arbitrary length message passed from L2
    /// @param txNumberInBatch The L2 transaction number in a batch
    /// @param sender The address of the L2 account from which the message was passed
    /// @param data Arbitrary length message data
    struct L2Message {
        uint16 txNumberInBatch;
        address sender;
        bytes data;
    }

    /// @notice Canonical L2 transaction structure
    /// @dev Used for creating the canonical transaction hash
    struct L2CanonicalTransaction {
        uint256 txType;
        uint256 from;
        uint256 to;
        uint256 gasLimit;
        uint256 gasPerPubdataByteLimit;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        uint256 paymaster;
        uint256[6] reserved;
        bytes data;
        bytes signature;
        uint256[] factoryDeps;
        bytes paymasterInput;
        bytes reservedDynamic;
    }

    // ============ State Variables ============

    /// @notice Reference to FluxeRollup contract for batch state
    address public immutable rollup;

    /// @notice Owner address for administrative functions
    address public owner;

    /// @notice Priority operations queue
    PriorityQueue.Queue internal priorityQueue;

    /// @notice Mapping of batch ID to L2 logs root hash
    mapping(uint256 => bytes32) public l2LogsRootHashes;

    /// @notice Total number of executed batches
    uint256 public totalBatchesExecuted;

    // ============ Events ============

    /// @notice Emitted when a new priority request is created
    /// @param txId Serial number of the priority operation
    /// @param txHash keccak256 hash of encoded transaction
    /// @param expirationBlock ETH block number when request expires
    /// @param transaction The L2 transaction structure
    event NewPriorityRequest(
        uint256 indexed txId,
        bytes32 indexed txHash,
        uint64 expirationBlock,
        L2CanonicalTransaction transaction
    );

    /// @notice Emitted when L2 logs root hash is updated
    /// @param batchId The batch ID
    /// @param l2LogsRootHash The L2 logs Merkle root hash
    event L2LogsRootHashUpdated(uint256 indexed batchId, bytes32 l2LogsRootHash);

    /// @notice Emitted when ownership is transferred
    /// @param previousOwner Previous owner address
    /// @param newOwner New owner address
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ============ Errors ============

    error OnlyOwner();
    error OnlyRollup();
    error ZeroAddress();
    error GasLimitExceeded(uint256 provided, uint256 maximum);
    error BatchNotExecuted(uint256 batchId, uint256 totalExecuted);
    error InvalidProofLength(uint256 provided, uint256 expected);
    error InvalidLogHash();

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier onlyRollup() {
        if (msg.sender != rollup) revert OnlyRollup();
        _;
    }

    // ============ Constructor ============

    /// @notice Initialize the Mailbox contract
    /// @param _rollup Address of the FluxeRollup contract
    constructor(address _rollup) {
        if (_rollup == address(0)) revert ZeroAddress();
        rollup = _rollup;
        owner = msg.sender;
    }

    // ============ External Functions - L1 -> L2 ============

    /// @notice Request execution of L2 transaction from L1
    /// @param _contractL2 The L2 receiver address
    /// @param _l2Value msg.value of L2 transaction (taken from L2 balance during execution)
    /// @param _calldata The input of the L2 transaction
    /// @param _gasLimit Maximum gas that transaction can consume on L2
    /// @return canonicalTxHash The hash of the requested L2 transaction
    function requestL2Transaction(
        address _contractL2,
        uint256 _l2Value,
        bytes calldata _calldata,
        uint256 _gasLimit
    ) external payable nonReentrant returns (bytes32 canonicalTxHash) {
        if (_gasLimit > PRIORITY_TX_MAX_GAS_LIMIT) {
            revert GasLimitExceeded(_gasLimit, PRIORITY_TX_MAX_GAS_LIMIT);
        }

        uint64 expirationBlock = uint64(block.number + PRIORITY_EXPIRATION);
        uint256 txId = priorityQueue.getTotalPriorityTxs();

        canonicalTxHash = _writePriorityOp(
            msg.sender,
            txId,
            _l2Value,
            _contractL2,
            _calldata,
            expirationBlock,
            _gasLimit
        );
    }

    // ============ External Functions - L2 -> L1 Message Proofs ============

    /// @notice Prove that a specific L2 message was sent in a specific batch
    /// @param _batchId The executed batch number in which the message appeared
    /// @param _index The position in the L2 logs Merkle tree
    /// @param _message Information about the sent message
    /// @param _proof Merkle proof for inclusion of L2 log
    /// @return Whether the proof is valid
    function proveL2MessageInclusion(
        uint256 _batchId,
        uint256 _index,
        L2Message calldata _message,
        bytes32[] calldata _proof
    ) external view returns (bool) {
        return _proveL2LogInclusion(_batchId, _index, _l2MessageToLog(_message), _proof);
    }

    /// @notice Prove that a specific L2 log was sent in a specific batch
    /// @param _batchId The executed batch number in which the log appeared
    /// @param _index The position of the l2log in the L2 logs Merkle tree
    /// @param _log Information about the sent log
    /// @param _proof Merkle proof for inclusion of the L2 log
    /// @return Whether the proof is valid
    function proveL2LogInclusion(
        uint256 _batchId,
        uint256 _index,
        L2Log memory _log,
        bytes32[] calldata _proof
    ) external view returns (bool) {
        return _proveL2LogInclusion(_batchId, _index, _log, _proof);
    }

    // ============ External Functions - Queue Management ============

    /// @notice Get the first unprocessed priority transaction index
    /// @return Index of the oldest unprocessed priority operation
    function getFirstUnprocessedPriorityTx() external view returns (uint256) {
        return priorityQueue.getFirstUnprocessedPriorityTx();
    }

    /// @notice Get total number of priority transactions
    /// @return Total count including processed ones
    function getTotalPriorityTxs() external view returns (uint256) {
        return priorityQueue.getTotalPriorityTxs();
    }

    /// @notice Get the number of pending priority operations
    /// @return Number of unprocessed priority operations
    function getPriorityQueueSize() external view returns (uint256) {
        return priorityQueue.getSize();
    }

    /// @notice Check if priority queue is empty
    /// @return True if no pending operations
    function isPriorityQueueEmpty() external view returns (bool) {
        return priorityQueue.isEmpty();
    }

    /// @notice Get the front priority operation without removing it
    /// @return The first unprocessed priority operation
    function getPriorityQueueFront() external view returns (PriorityOperation memory) {
        return priorityQueue.front();
    }

    // ============ External Functions - Rollup Integration ============

    /// @notice Update L2 logs root hash for a batch (called by rollup)
    /// @param _batchId The batch ID
    /// @param _l2LogsRootHash The L2 logs Merkle root hash
    function setL2LogsRootHash(uint256 _batchId, bytes32 _l2LogsRootHash) external onlyRollup {
        l2LogsRootHashes[_batchId] = _l2LogsRootHash;
        if (_batchId > totalBatchesExecuted) {
            totalBatchesExecuted = _batchId;
        }
        emit L2LogsRootHashUpdated(_batchId, _l2LogsRootHash);
    }

    /// @notice Process priority operations from the queue (called by rollup during batch execution)
    /// @param _count Number of operations to process
    /// @return operations Array of processed priority operations
    function popPriorityOperations(uint256 _count) external onlyRollup returns (PriorityOperation[] memory operations) {
        operations = new PriorityOperation[](_count);
        for (uint256 i = 0; i < _count; ) {
            operations[i] = priorityQueue.popFront();
            unchecked {
                ++i;
            }
        }
    }

    // ============ Admin Functions ============

    /// @notice Transfer ownership
    /// @param _newOwner Address of new owner
    function transferOwnership(address _newOwner) external onlyOwner {
        if (_newOwner == address(0)) revert ZeroAddress();
        address oldOwner = owner;
        owner = _newOwner;
        emit OwnershipTransferred(oldOwner, _newOwner);
    }

    // ============ Internal Functions ============

    /// @dev Prove that a specific L2 log was sent in a specific batch number
    function _proveL2LogInclusion(
        uint256 _batchId,
        uint256 _index,
        L2Log memory _log,
        bytes32[] calldata _proof
    ) internal view returns (bool) {
        if (_batchId > totalBatchesExecuted) {
            revert BatchNotExecuted(_batchId, totalBatchesExecuted);
        }

        bytes32 hashedLog = keccak256(
            abi.encodePacked(
                _log.l2ShardId,
                _log.isService,
                _log.txNumberInBatch,
                _log.sender,
                _log.key,
                _log.value
            )
        );

        // Check that hashed log is not the default one (indicates out of range)
        if (hashedLog == L2_L1_LOGS_TREE_DEFAULT_LEAF_HASH) {
            revert InvalidLogHash();
        }

        // Check that the proof length matches tree height
        if (_proof.length != L2_TO_L1_LOG_MERKLE_TREE_HEIGHT) {
            revert InvalidProofLength(_proof.length, L2_TO_L1_LOG_MERKLE_TREE_HEIGHT);
        }

        bytes32 calculatedRootHash = Merkle.calculateRoot(_proof, _index, hashedLog);
        bytes32 actualRootHash = l2LogsRootHashes[_batchId];

        return actualRootHash == calculatedRootHash;
    }

    /// @dev Convert arbitrary-length message to the raw L2 log
    function _l2MessageToLog(L2Message calldata _message) internal pure returns (L2Log memory) {
        return L2Log({
            l2ShardId: 0,
            isService: true,
            txNumberInBatch: _message.txNumberInBatch,
            sender: L2_TO_L1_MESSENGER,
            key: bytes32(uint256(uint160(_message.sender))),
            value: keccak256(_message.data)
        });
    }

    /// @dev Stores a transaction record in storage & emits event
    function _writePriorityOp(
        address _sender,
        uint256 _txId,
        uint256 _l2Value,
        address _contractAddressL2,
        bytes calldata _calldata,
        uint64 _expirationBlock,
        uint256 _gasLimit
    ) internal returns (bytes32 canonicalTxHash) {
        L2CanonicalTransaction memory transaction = _serializeL2Transaction(
            _txId,
            _l2Value,
            _sender,
            _contractAddressL2,
            _calldata,
            _gasLimit
        );

        canonicalTxHash = keccak256(abi.encode(transaction));

        priorityQueue.pushBack(
            PriorityOperation({
                canonicalTxHash: canonicalTxHash,
                expirationBlock: _expirationBlock,
                layer2Tip: uint192(0)
            })
        );

        emit NewPriorityRequest(_txId, canonicalTxHash, _expirationBlock, transaction);
    }

    /// @dev Serialize L2 transaction to canonical form
    function _serializeL2Transaction(
        uint256 _txId,
        uint256 _l2Value,
        address _sender,
        address _contractAddressL2,
        bytes calldata _calldata,
        uint256 _gasLimit
    ) internal pure returns (L2CanonicalTransaction memory) {
        return L2CanonicalTransaction({
            txType: PRIORITY_OPERATION_L2_TX_TYPE,
            from: uint256(uint160(_sender)),
            to: uint256(uint160(_contractAddressL2)),
            gasLimit: _gasLimit,
            gasPerPubdataByteLimit: 1,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymaster: 0,
            reserved: [_txId, _l2Value, 0, 0, 0, 0],
            data: _calldata,
            signature: new bytes(0),
            factoryDeps: new uint256[](0),
            paymasterInput: new bytes(0),
            reservedDynamic: new bytes(0)
        });
    }
}
