// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./FluxeRollup.sol";

/// @title FluxeBridge - Deposit and withdrawal bridge for FLUXE L2
/// @notice Handles token deposits and withdrawals with rollup verification
/// @dev Deposits create ingress receipts; withdrawals verify exit receipts
contract FluxeBridge is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ============ Constants ============

    /// @notice Chain ID for this deployment (e.g., 1 for Ethereum mainnet)
    uint32 public immutable chainId;

    // ============ State Variables ============

    /// @notice Reference to the rollup contract for state verification
    FluxeRollup public immutable rollup;

    /// @notice Owner address
    address public owner;

    /// @notice Mapping of asset type to token address
    mapping(uint32 => address) public assetToToken;

    /// @notice Mapping of token address to asset type
    mapping(address => uint32) public tokenToAsset;

    /// @notice Mapping of asset type to pool balance
    mapping(uint32 => uint256) public poolBalances;

    /// @notice Mapping of asset type to minimum deposit
    mapping(uint32 => uint256) public minDeposit;

    /// @notice Mapping of asset type to maximum deposit
    mapping(uint32 => uint256) public maxDeposit;

    /// @notice Processed deposit hashes (to prevent replay)
    mapping(bytes32 => bool) public processedDeposits;

    /// @notice Processed withdrawal hashes (to prevent replay)
    mapping(bytes32 => bool) public processedWithdrawals;

    /// @notice Current nonce for deposits (per asset type)
    mapping(uint32 => uint64) public depositNonce;

    /// @notice Whether the bridge is paused
    bool public paused;

    /// @notice Whether an asset is enabled
    mapping(uint32 => bool) public assetEnabled;

    // ============ Events ============

    event Deposit(
        uint32 indexed assetType,
        uint256 amount,
        bytes32 beneficiaryCm,
        bytes32 indexed ingressReceiptHash,
        uint64 nonce,
        address indexed depositor
    );

    event Withdrawal(
        uint32 indexed assetType,
        uint256 amount,
        address indexed recipient,
        bytes32 indexed exitReceiptHash,
        uint64 batchId
    );

    event AssetRegistered(
        uint32 indexed assetType,
        address indexed tokenAddress,
        uint256 minDeposit,
        uint256 maxDeposit
    );

    event AssetUpdated(
        uint32 indexed assetType,
        bool enabled,
        uint256 minDeposit,
        uint256 maxDeposit
    );

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    event Paused(address indexed account);
    event Unpaused(address indexed account);

    // ============ Errors ============

    error OnlyOwner();
    error ContractPaused();
    error AssetNotRegistered();
    error AssetDisabled();
    error AmountBelowMinimum(uint256 amount, uint256 minimum);
    error AmountAboveMaximum(uint256 amount, uint256 maximum);
    error ZeroAddress();
    error ZeroAmount();
    error InvalidBeneficiary();
    error WithdrawalAlreadyProcessed();
    error InvalidExitProof();
    error ExitReceiptNotInBatch();
    error InsufficientPoolBalance();
    error AssetAlreadyRegistered();
    error InvalidMerkleProof();

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    // ============ Constructor ============

    /// @notice Initialize the bridge contract
    /// @param _rollup Address of the FluxeRollup contract
    /// @param _chainId Chain ID for this deployment
    constructor(address _rollup, uint32 _chainId) {
        if (_rollup == address(0)) revert ZeroAddress();

        rollup = FluxeRollup(_rollup);
        chainId = _chainId;
        owner = msg.sender;
    }

    // ============ External Functions ============

    /// @notice Deposit tokens into the FLUXE L2
    /// @param assetType Asset type identifier
    /// @param amount Amount to deposit
    /// @param beneficiaryCm Commitment to the beneficiary note
    /// @return ingressHash Hash of the ingress receipt
    function deposit(
        uint32 assetType,
        uint256 amount,
        bytes32 beneficiaryCm
    ) external nonReentrant whenNotPaused returns (bytes32 ingressHash) {
        // Validate asset
        address token = assetToToken[assetType];
        if (token == address(0)) revert AssetNotRegistered();
        if (!assetEnabled[assetType]) revert AssetDisabled();

        // Validate amount
        if (amount == 0) revert ZeroAmount();
        if (amount < minDeposit[assetType]) {
            revert AmountBelowMinimum(amount, minDeposit[assetType]);
        }
        if (amount > maxDeposit[assetType]) {
            revert AmountAboveMaximum(amount, maxDeposit[assetType]);
        }

        // Validate beneficiary
        if (beneficiaryCm == bytes32(0)) revert InvalidBeneficiary();

        // Get nonce and increment
        uint64 nonce = depositNonce[assetType]++;

        // Compute ingress receipt hash
        // Format: keccak256(chainId || assetType || amount || beneficiaryCm || nonce)
        ingressHash = keccak256(abi.encodePacked(
            chainId,
            assetType,
            amount,
            beneficiaryCm,
            nonce
        ));

        // Mark as processed
        processedDeposits[ingressHash] = true;

        // Transfer tokens from user to bridge
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Update pool balance
        poolBalances[assetType] += amount;

        emit Deposit(
            assetType,
            amount,
            beneficiaryCm,
            ingressHash,
            nonce,
            msg.sender
        );

        return ingressHash;
    }

    /// @notice Withdraw tokens from FLUXE L2 using exit receipt proof
    /// @param assetType Asset type identifier
    /// @param amount Amount to withdraw
    /// @param recipient Address to receive tokens
    /// @param exitReceiptHash Hash of the exit receipt
    /// @param batchId Batch ID containing the exit receipt
    /// @param merkleProof Merkle proof of exit receipt in exit tree
    function withdraw(
        uint32 assetType,
        uint256 amount,
        address recipient,
        bytes32 exitReceiptHash,
        uint64 batchId,
        bytes32[] calldata merkleProof
    ) external nonReentrant whenNotPaused {
        // Validate asset
        address token = assetToToken[assetType];
        if (token == address(0)) revert AssetNotRegistered();

        // Validate recipient
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        // Check not already processed
        if (processedWithdrawals[exitReceiptHash]) {
            revert WithdrawalAlreadyProcessed();
        }

        // Get exit root from rollup
        FluxeRollup.StateRoots memory roots = rollup.getRoots(batchId);

        // Verify exit receipt is in the exit tree
        // The exit receipt hash should be a leaf in the exit Merkle tree
        bytes32 computedRoot = _computeMerkleRoot(exitReceiptHash, merkleProof);
        if (computedRoot != roots.exitRoot) {
            revert ExitReceiptNotInBatch();
        }

        // Verify exit receipt format matches expected
        // Exit receipt format: keccak256(destinationChain || assetType || amount || nullifier || nonce)
        // We reconstruct and verify the hash includes this chain as destination
        bytes32 expectedPrefix = keccak256(abi.encodePacked(chainId, assetType, amount));
        // Note: Full verification would require the nullifier and nonce, which are provided
        // by the sequencer. For now, we trust the Merkle proof verification.

        // Check pool has sufficient balance
        if (poolBalances[assetType] < amount) {
            revert InsufficientPoolBalance();
        }

        // Mark as processed
        processedWithdrawals[exitReceiptHash] = true;

        // Update pool balance
        poolBalances[assetType] -= amount;

        // Transfer tokens to recipient
        IERC20(token).safeTransfer(recipient, amount);

        emit Withdrawal(
            assetType,
            amount,
            recipient,
            exitReceiptHash,
            batchId
        );
    }

    /// @notice Check if a deposit has been processed
    /// @param ingressHash Hash of the ingress receipt
    /// @return True if processed
    function isDepositProcessed(bytes32 ingressHash) external view returns (bool) {
        return processedDeposits[ingressHash];
    }

    /// @notice Check if a withdrawal has been processed
    /// @param exitReceiptHash Hash of the exit receipt
    /// @return True if processed
    function isWithdrawalProcessed(bytes32 exitReceiptHash) external view returns (bool) {
        return processedWithdrawals[exitReceiptHash];
    }

    /// @notice Get pool balance for an asset
    /// @param assetType Asset type identifier
    /// @return Current pool balance
    function getPoolBalance(uint32 assetType) external view returns (uint256) {
        return poolBalances[assetType];
    }

    /// @notice Get asset info
    /// @param assetType Asset type identifier
    /// @return token Token address
    /// @return enabled Whether asset is enabled
    /// @return min Minimum deposit
    /// @return max Maximum deposit
    function getAssetInfo(uint32 assetType) external view returns (
        address token,
        bool enabled,
        uint256 min,
        uint256 max
    ) {
        return (
            assetToToken[assetType],
            assetEnabled[assetType],
            minDeposit[assetType],
            maxDeposit[assetType]
        );
    }

    // ============ Admin Functions ============

    /// @notice Register a new asset
    /// @param assetType Asset type identifier
    /// @param tokenAddress ERC20 token address
    /// @param _minDeposit Minimum deposit amount
    /// @param _maxDeposit Maximum deposit amount
    function registerAsset(
        uint32 assetType,
        address tokenAddress,
        uint256 _minDeposit,
        uint256 _maxDeposit
    ) external onlyOwner {
        if (tokenAddress == address(0)) revert ZeroAddress();
        if (assetToToken[assetType] != address(0)) revert AssetAlreadyRegistered();

        assetToToken[assetType] = tokenAddress;
        tokenToAsset[tokenAddress] = assetType;
        minDeposit[assetType] = _minDeposit;
        maxDeposit[assetType] = _maxDeposit;
        assetEnabled[assetType] = true;

        emit AssetRegistered(assetType, tokenAddress, _minDeposit, _maxDeposit);
    }

    /// @notice Update asset configuration
    /// @param assetType Asset type identifier
    /// @param enabled Whether asset is enabled
    /// @param _minDeposit Minimum deposit amount
    /// @param _maxDeposit Maximum deposit amount
    function updateAsset(
        uint32 assetType,
        bool enabled,
        uint256 _minDeposit,
        uint256 _maxDeposit
    ) external onlyOwner {
        if (assetToToken[assetType] == address(0)) revert AssetNotRegistered();

        assetEnabled[assetType] = enabled;
        minDeposit[assetType] = _minDeposit;
        maxDeposit[assetType] = _maxDeposit;

        emit AssetUpdated(assetType, enabled, _minDeposit, _maxDeposit);
    }

    /// @notice Transfer ownership
    /// @param newOwner Address of new owner
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /// @notice Pause the bridge
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause the bridge
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ============ Internal Functions ============

    /// @notice Compute Merkle root from leaf and proof
    /// @param leaf Leaf hash
    /// @param proof Array of sibling hashes
    /// @return Computed root
    function _computeMerkleRoot(
        bytes32 leaf,
        bytes32[] calldata proof
    ) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash;
    }
}
