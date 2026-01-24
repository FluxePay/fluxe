#!/bin/bash
# Deploy FLUXE Bridge to Solana (Devnet or Mainnet)
#
# Prerequisites:
# - Solana CLI installed and configured
# - Anchor CLI installed
# - Keypair with SOL for deployment
#
# Usage:
#   ./deploy-solana.sh [network]
#
#   network: devnet (default), mainnet-beta, or localnet

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$SCRIPT_DIR/../../contracts/solana"

# Default to Devnet
NETWORK="${1:-devnet}"

echo "=== FLUXE Solana Deployment ==="
echo "Network: $NETWORK"

cd "$CONTRACTS_DIR"

# Set Solana cluster
case "$NETWORK" in
    devnet)
        solana config set --url https://api.devnet.solana.com
        ;;
    mainnet-beta)
        solana config set --url https://api.mainnet-beta.solana.com
        echo "WARNING: Deploying to mainnet!"
        echo "Press Ctrl+C to cancel, or wait 10 seconds to continue..."
        sleep 10
        ;;
    localnet)
        solana config set --url http://localhost:8899
        ;;
    *)
        echo "Unknown network: $NETWORK"
        exit 1
        ;;
esac

# Check wallet balance
BALANCE=$(solana balance | awk '{print $1}')
echo "Wallet balance: $BALANCE SOL"

if (( $(echo "$BALANCE < 1" | bc -l) )); then
    echo "Warning: Low balance. You may need more SOL for deployment."
    if [ "$NETWORK" == "devnet" ]; then
        echo "Request airdrop with: solana airdrop 2"
    fi
fi

# Build the program
echo ""
echo "Building Anchor program..."
anchor build

# Get program ID
PROGRAM_ID=$(solana address -k target/deploy/fluxe_bridge-keypair.json 2>/dev/null || echo "")
if [ -z "$PROGRAM_ID" ]; then
    # Generate new keypair if doesn't exist
    solana-keygen new -o target/deploy/fluxe_bridge-keypair.json --no-bip39-passphrase --force
    PROGRAM_ID=$(solana address -k target/deploy/fluxe_bridge-keypair.json)
fi

echo "Program ID: $PROGRAM_ID"

# Update Anchor.toml with program ID
sed -i "s/fluxe_bridge = \".*\"/fluxe_bridge = \"$PROGRAM_ID\"/" Anchor.toml

# Rebuild with correct program ID
anchor build

# Deploy
echo ""
echo "Deploying program..."
anchor deploy --provider.cluster $NETWORK

# Create deployments directory and save info
mkdir -p ../../deploy/deployments

DEPLOYMENT_FILE="../../deploy/deployments/fluxe-bridge-solana-$NETWORK.json"
cat > "$DEPLOYMENT_FILE" << EOF
{
  "network": "$NETWORK",
  "programId": "$PROGRAM_ID",
  "deployedAt": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "cluster": "$(solana config get | grep 'RPC URL' | awk '{print $3}')"
}
EOF

echo ""
echo "=== Deployment Complete ==="
echo "Program ID: $PROGRAM_ID"
echo "Deployment info saved to: $DEPLOYMENT_FILE"
echo ""
echo "Next steps:"
echo "1. Initialize the bridge with: anchor run initialize"
echo "2. Configure asset types"
echo "3. Finalize genesis"
