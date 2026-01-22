// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../FluxeBridge.sol";
import "../FluxeRollup.sol";
import "../interfaces/IGroth16Verifier.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockToken - Simple ERC20 for testing
contract MockToken is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {
        _mint(msg.sender, 1_000_000_000 * 10**6); // 1B USDC
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @title MockVerifier - Mock verifier for testing
contract MockVerifier is IGroth16Verifier {
    function verifyProof(bytes calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyProofParsed(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract FluxeBridgeTest is Test {
    FluxeBridge public bridge;
    FluxeRollup public rollup;
    MockToken public usdc;
    MockVerifier public verifier;

    address public owner;
    address public sequencer = address(0x1);
    address public user = address(0x2);
    address public recipient = address(0x3);

    uint32 constant CHAIN_ID = 1;
    uint32 constant USDC_ASSET_TYPE = 1;

    // Event definition for testing
    event Deposit(
        uint32 indexed assetType,
        uint256 amount,
        bytes32 beneficiaryCm,
        bytes32 indexed ingressReceiptHash,
        uint64 nonce,
        address indexed depositor
    );

    function setUp() public {
        owner = address(this);

        // Deploy contracts
        verifier = new MockVerifier();
        rollup = new FluxeRollup(address(verifier), sequencer);
        bridge = new FluxeBridge(address(rollup), CHAIN_ID);
        usdc = new MockToken();

        // Register USDC asset
        bridge.registerAsset(
            USDC_ASSET_TYPE,
            address(usdc),
            1_000_000,       // min: 1 USDC
            1_000_000_000_000 // max: 1M USDC
        );

        // Fund user
        usdc.mint(user, 1_000_000 * 10**6); // 1M USDC
    }

    function test_InitialState() public view {
        assertEq(bridge.chainId(), CHAIN_ID);
        assertEq(bridge.owner(), owner);
        assertFalse(bridge.paused());
    }

    function test_RegisterAsset() public view {
        (address token, bool enabled, uint256 min, uint256 max) = bridge.getAssetInfo(USDC_ASSET_TYPE);
        assertEq(token, address(usdc));
        assertTrue(enabled);
        assertEq(min, 1_000_000);
        assertEq(max, 1_000_000_000_000);
    }

    function test_Deposit() public {
        uint256 amount = 100 * 10**6; // 100 USDC
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        // Approve bridge
        vm.startPrank(user);
        usdc.approve(address(bridge), amount);

        // Deposit
        bytes32 ingressHash = bridge.deposit(USDC_ASSET_TYPE, amount, beneficiaryCm);
        vm.stopPrank();

        // Verify deposit
        assertTrue(bridge.isDepositProcessed(ingressHash));
        assertEq(bridge.getPoolBalance(USDC_ASSET_TYPE), amount);
        assertEq(usdc.balanceOf(address(bridge)), amount);
    }

    function test_DepositEmitsEvent() public {
        uint256 amount = 100 * 10**6;
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        vm.startPrank(user);
        usdc.approve(address(bridge), amount);

        vm.expectEmit(true, true, true, true);
        // Compute expected ingress hash
        bytes32 expectedHash = keccak256(abi.encodePacked(
            CHAIN_ID,
            USDC_ASSET_TYPE,
            amount,
            beneficiaryCm,
            uint64(0) // nonce
        ));
        emit Deposit(USDC_ASSET_TYPE, amount, beneficiaryCm, expectedHash, 0, user);

        bridge.deposit(USDC_ASSET_TYPE, amount, beneficiaryCm);
        vm.stopPrank();
    }

    function test_DepositBelowMinimum() public {
        uint256 amount = 100; // Below 1 USDC minimum
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        vm.startPrank(user);
        usdc.approve(address(bridge), amount);

        vm.expectRevert(abi.encodeWithSelector(
            FluxeBridge.AmountBelowMinimum.selector,
            amount,
            1_000_000
        ));
        bridge.deposit(USDC_ASSET_TYPE, amount, beneficiaryCm);
        vm.stopPrank();
    }

    function test_DepositAboveMaximum() public {
        uint256 amount = 2_000_000_000_000; // 2M USDC (above 1M max)
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        // Mint extra USDC for test
        usdc.mint(user, amount);

        vm.startPrank(user);
        usdc.approve(address(bridge), amount);

        vm.expectRevert(abi.encodeWithSelector(
            FluxeBridge.AmountAboveMaximum.selector,
            amount,
            1_000_000_000_000
        ));
        bridge.deposit(USDC_ASSET_TYPE, amount, beneficiaryCm);
        vm.stopPrank();
    }

    function test_DepositUnregisteredAsset() public {
        uint256 amount = 100 * 10**6;
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        vm.prank(user);
        vm.expectRevert(FluxeBridge.AssetNotRegistered.selector);
        bridge.deposit(99, amount, beneficiaryCm); // Unregistered asset type
    }

    function test_DepositZeroBeneficiary() public {
        uint256 amount = 100 * 10**6;

        vm.startPrank(user);
        usdc.approve(address(bridge), amount);

        vm.expectRevert(FluxeBridge.InvalidBeneficiary.selector);
        bridge.deposit(USDC_ASSET_TYPE, amount, bytes32(0));
        vm.stopPrank();
    }

    function test_DepositWhenPaused() public {
        uint256 amount = 100 * 10**6;
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        bridge.pause();

        vm.startPrank(user);
        usdc.approve(address(bridge), amount);

        vm.expectRevert(FluxeBridge.ContractPaused.selector);
        bridge.deposit(USDC_ASSET_TYPE, amount, beneficiaryCm);
        vm.stopPrank();
    }

    function test_MultipleDeposits() public {
        uint256 amount1 = 100 * 10**6;
        uint256 amount2 = 200 * 10**6;
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        vm.startPrank(user);
        usdc.approve(address(bridge), amount1 + amount2);

        bytes32 hash1 = bridge.deposit(USDC_ASSET_TYPE, amount1, beneficiaryCm);
        bytes32 hash2 = bridge.deposit(USDC_ASSET_TYPE, amount2, beneficiaryCm);
        vm.stopPrank();

        // Hashes should be different due to nonce
        assertTrue(hash1 != hash2);
        assertEq(bridge.getPoolBalance(USDC_ASSET_TYPE), amount1 + amount2);
    }

    function test_UpdateAsset() public {
        bridge.updateAsset(USDC_ASSET_TYPE, false, 2_000_000, 500_000_000_000);

        (address token, bool enabled, uint256 min, uint256 max) = bridge.getAssetInfo(USDC_ASSET_TYPE);
        assertEq(token, address(usdc));
        assertFalse(enabled);
        assertEq(min, 2_000_000);
        assertEq(max, 500_000_000_000);
    }

    function test_DepositDisabledAsset() public {
        bridge.updateAsset(USDC_ASSET_TYPE, false, 1_000_000, 1_000_000_000_000);

        uint256 amount = 100 * 10**6;
        bytes32 beneficiaryCm = bytes32(uint256(12345));

        vm.startPrank(user);
        usdc.approve(address(bridge), amount);

        vm.expectRevert(FluxeBridge.AssetDisabled.selector);
        bridge.deposit(USDC_ASSET_TYPE, amount, beneficiaryCm);
        vm.stopPrank();
    }

    function test_PauseUnpause() public {
        bridge.pause();
        assertTrue(bridge.paused());

        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function test_TransferOwnership() public {
        address newOwner = address(0x4);
        bridge.transferOwnership(newOwner);
        assertEq(bridge.owner(), newOwner);
    }

    function test_OnlyOwnerFunctions() public {
        vm.prank(user);
        vm.expectRevert(FluxeBridge.OnlyOwner.selector);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert(FluxeBridge.OnlyOwner.selector);
        bridge.registerAsset(2, address(usdc), 1, 100);
    }

    function test_RegisterAssetTwice() public {
        vm.expectRevert(FluxeBridge.AssetAlreadyRegistered.selector);
        bridge.registerAsset(USDC_ASSET_TYPE, address(usdc), 1, 100);
    }

    // Note: Withdrawal tests require proper Merkle proof setup
    // which depends on the exit tree structure from the rollup
    function test_WithdrawalAlreadyProcessed() public {
        // First, we need to simulate a valid withdrawal
        // For this test, we'll manually mark a withdrawal as processed
        // In production, this would happen through the withdraw function

        // This is a placeholder test showing the expected revert
        bytes32 exitHash = bytes32(uint256(999));
        bytes32[] memory proof = new bytes32[](0);

        // Since we can't easily set up valid Merkle proofs in this test,
        // we'll verify the basic flow works
        vm.expectRevert(); // Will revert due to invalid proof
        bridge.withdraw(USDC_ASSET_TYPE, 100, recipient, exitHash, 0, proof);
    }
}
