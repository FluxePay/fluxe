#!/bin/bash
# Deploy FLUXE Rollup to Ethereum (Sepolia testnet)
#
# Prerequisites:
# - DEPLOYER_PRIVATE_KEY: Private key with ETH for gas
# - SEQUENCER_ADDRESS: Address that will submit batches
# - SEPOLIA_RPC_URL: Alchemy/Infura Sepolia RPC URL
# - ETHERSCAN_API_KEY: For contract verification
#
# Usage:
#   ./deploy-ethereum.sh [network]
#
#   network: sepolia (default), mainnet, or local

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$SCRIPT_DIR/../../contracts/ethereum"

# Default to Sepolia
NETWORK="${1:-sepolia}"

echo "=== FLUXE Ethereum Deployment ==="
echo "Network: $NETWORK"

# Validate environment
if [ -z "$DEPLOYER_PRIVATE_KEY" ]; then
    echo "Error: DEPLOYER_PRIVATE_KEY not set"
    exit 1
fi

if [ -z "$SEQUENCER_ADDRESS" ]; then
    echo "Error: SEQUENCER_ADDRESS not set"
    exit 1
fi

cd "$CONTRACTS_DIR"

# Create deployments directory
mkdir -p deployments

# Run Foundry deployment script
echo ""
echo "Deploying FluxeRollup..."

if [ "$NETWORK" == "sepolia" ]; then
    if [ -z "$SEPOLIA_RPC_URL" ]; then
        echo "Error: SEPOLIA_RPC_URL not set"
        exit 1
    fi
    forge script script/DeployFluxeRollup.s.sol:DeployFluxeRollup \
        --rpc-url "$SEPOLIA_RPC_URL" \
        --broadcast \
        --verify \
        -vvv
elif [ "$NETWORK" == "mainnet" ]; then
    if [ -z "$MAINNET_RPC_URL" ]; then
        echo "Error: MAINNET_RPC_URL not set"
        exit 1
    fi
    echo "WARNING: Deploying to mainnet!"
    echo "Press Ctrl+C to cancel, or wait 10 seconds to continue..."
    sleep 10
    forge script script/DeployFluxeRollup.s.sol:DeployFluxeRollup \
        --rpc-url "$MAINNET_RPC_URL" \
        --broadcast \
        --verify \
        -vvv
elif [ "$NETWORK" == "local" ]; then
    forge script script/DeployFluxeRollup.s.sol:DeployFluxeRollup \
        --rpc-url "http://localhost:8545" \
        --broadcast \
        -vvv
else
    echo "Unknown network: $NETWORK"
    exit 1
fi

echo ""
echo "=== Deployment Complete ==="
echo "Check deployments/ directory for deployment info"
