// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../Groth16Verifier.sol";
import "../FluxeRollup.sol";
import "../FluxeBridge.sol";

/// @title FLUXE Deployment Script
/// @notice Deploys the complete FLUXE contract suite to Ethereum
/// @dev Run with: forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract DeployScript is Script {
    // Deployment addresses (set after deployment)
    Groth16Verifier public verifier;
    FluxeRollup public rollup;
    FluxeBridge public bridge;

    // Configuration
    uint32 constant SEPOLIA_CHAIN_ID = 11155111;
    uint32 constant MAINNET_CHAIN_ID = 1;

    function run() external {
        // Get deployer private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Get sequencer address (defaults to deployer if not set)
        address sequencer;
        try vm.envAddress("SEQUENCER_ADDRESS") returns (address addr) {
            sequencer = addr;
        } catch {
            sequencer = deployer;
        }

        // Get chain ID for bridge (defaults to Sepolia)
        uint32 bridgeChainId;
        try vm.envUint("BRIDGE_CHAIN_ID") returns (uint256 chainId) {
            bridgeChainId = uint32(chainId);
        } catch {
            bridgeChainId = SEPOLIA_CHAIN_ID;
        }

        console.log("Deployer:", deployer);
        console.log("Sequencer:", sequencer);
        console.log("Bridge Chain ID:", bridgeChainId);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Groth16Verifier (no constructor args)
        verifier = new Groth16Verifier();
        console.log("Groth16Verifier deployed at:", address(verifier));

        // 2. Deploy FluxeRollup (needs verifier and sequencer)
        rollup = new FluxeRollup(address(verifier), sequencer);
        console.log("FluxeRollup deployed at:", address(rollup));

        // 3. Deploy FluxeBridge (needs rollup and chain ID)
        bridge = new FluxeBridge(address(rollup), bridgeChainId);
        console.log("FluxeBridge deployed at:", address(bridge));

        vm.stopBroadcast();

        // Log deployment summary
        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Groth16Verifier:", address(verifier));
        console.log("FluxeRollup:", address(rollup));
        console.log("FluxeBridge:", address(bridge));
        console.log("");
        console.log("Owner:", deployer);
        console.log("Sequencer:", sequencer);
    }
}

/// @title FLUXE Asset Registration Script
/// @notice Registers test tokens on the deployed bridge
/// @dev Run after Deploy.s.sol to register assets
contract RegisterAssetsScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address bridgeAddress = vm.envAddress("BRIDGE_ADDRESS");

        FluxeBridge bridge = FluxeBridge(bridgeAddress);

        console.log("Registering assets on bridge:", bridgeAddress);

        vm.startBroadcast(deployerPrivateKey);

        // Register test assets
        // Asset type 1: WETH (or test ETH wrapper)
        // Note: Replace with actual testnet token addresses
        address wethAddress = vm.envOr("WETH_ADDRESS", address(0));
        if (wethAddress != address(0)) {
            bridge.registerAsset(
                1,                      // assetType
                wethAddress,            // tokenAddress
                0.001 ether,            // minDeposit (0.001 ETH)
                100 ether               // maxDeposit (100 ETH)
            );
            console.log("Registered WETH (asset 1):", wethAddress);
        }

        // Asset type 2: USDC (or test stablecoin)
        address usdcAddress = vm.envOr("USDC_ADDRESS", address(0));
        if (usdcAddress != address(0)) {
            bridge.registerAsset(
                2,                      // assetType
                usdcAddress,            // tokenAddress
                1e6,                    // minDeposit ($1 USDC, 6 decimals)
                1000000e6               // maxDeposit ($1M USDC)
            );
            console.log("Registered USDC (asset 2):", usdcAddress);
        }

        vm.stopBroadcast();
    }
}

/// @title FLUXE Verification Script
/// @notice Verifies deployment and reads contract state
contract VerifyDeploymentScript is Script {
    function run() external view {
        address verifierAddress = vm.envAddress("VERIFIER_ADDRESS");
        address rollupAddress = vm.envAddress("ROLLUP_ADDRESS");
        address bridgeAddress = vm.envAddress("BRIDGE_ADDRESS");

        Groth16Verifier verifier = Groth16Verifier(verifierAddress);
        FluxeRollup rollup = FluxeRollup(rollupAddress);
        FluxeBridge bridge = FluxeBridge(bridgeAddress);

        console.log("=== Contract Verification ===");
        console.log("");

        // Verify FluxeRollup
        console.log("FluxeRollup:");
        console.log("  verifier:", address(rollup.verifier()));
        console.log("  sequencer:", rollup.sequencer());
        console.log("  owner:", rollup.owner());
        console.log("  lastFinalizedBatchId:", rollup.lastFinalizedBatchId());
        console.log("  paused:", rollup.paused());
        console.log("");

        // Verify FluxeBridge
        console.log("FluxeBridge:");
        console.log("  rollup:", address(bridge.rollup()));
        console.log("  chainId:", bridge.chainId());
        console.log("  owner:", bridge.owner());
        console.log("  paused:", bridge.paused());
        console.log("");

        // Verify linkage
        require(address(rollup.verifier()) == verifierAddress, "Verifier mismatch");
        require(address(bridge.rollup()) == rollupAddress, "Rollup mismatch");

        console.log("All verifications passed!");
    }
}
