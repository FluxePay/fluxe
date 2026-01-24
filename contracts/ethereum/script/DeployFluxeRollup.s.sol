// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../FluxeRollup.sol";

/// @title Deploy FLUXE Rollup Contract
/// @notice Foundry script to deploy FluxeRollup to Ethereum testnets/mainnet
contract DeployFluxeRollup is Script {
    // SP1 Verifier Gateway addresses (from Succinct documentation)
    // https://docs.succinct.xyz/verification/onchain/contract-addresses
    address constant SP1_VERIFIER_GATEWAY_SEPOLIA = 0x3B6041173B80E77f038f3F2C0f9744f04837185e;
    address constant SP1_VERIFIER_GATEWAY_MAINNET = 0x3B6041173B80E77f038f3F2C0f9744f04837185e;

    function run() external {
        // Load configuration from environment
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address sequencer = vm.envAddress("SEQUENCER_ADDRESS");

        // Determine verifier based on chain
        address verifier;
        if (block.chainid == 11155111) {
            // Sepolia
            verifier = SP1_VERIFIER_GATEWAY_SEPOLIA;
            console.log("Deploying to Sepolia testnet");
        } else if (block.chainid == 1) {
            // Mainnet
            verifier = SP1_VERIFIER_GATEWAY_MAINNET;
            console.log("Deploying to Ethereum mainnet");
        } else {
            // Local/custom network - use env variable
            verifier = vm.envAddress("SP1_VERIFIER_ADDRESS");
            console.log("Deploying to chain ID:", block.chainid);
        }

        console.log("SP1 Verifier Gateway:", verifier);
        console.log("Sequencer:", sequencer);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy FluxeRollup
        FluxeRollup rollup = new FluxeRollup(verifier, sequencer);

        vm.stopBroadcast();

        console.log("=== Deployment Complete ===");
        console.log("FluxeRollup deployed to:", address(rollup));
        console.log("FLUXE_BLOCK_VKEY:", vm.toString(rollup.FLUXE_BLOCK_VKEY()));
        console.log("FLUXE_L2_CHAIN_ID:", rollup.FLUXE_L2_CHAIN_ID());
        console.log("Owner:", rollup.owner());
        console.log("Sequencer:", rollup.sequencer());
        console.log("Genesis Finalized:", rollup.genesisFinalized());

        // Write deployment info to JSON
        string memory deploymentJson = string.concat(
            '{\n',
            '  "chainId": ', vm.toString(block.chainid), ',\n',
            '  "rollupAddress": "', vm.toString(address(rollup)), '",\n',
            '  "verifierAddress": "', vm.toString(verifier), '",\n',
            '  "sequencer": "', vm.toString(sequencer), '",\n',
            '  "fluxeBlockVkey": "', vm.toString(rollup.FLUXE_BLOCK_VKEY()), '",\n',
            '  "fluxeL2ChainId": ', vm.toString(rollup.FLUXE_L2_CHAIN_ID()), '\n',
            '}'
        );

        string memory filename = string.concat("deployments/fluxe-rollup-", vm.toString(block.chainid), ".json");
        vm.writeFile(filename, deploymentJson);
        console.log("Deployment info written to:", filename);
    }
}
