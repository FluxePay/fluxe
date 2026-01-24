#!/bin/bash
# Verify FLUXE deployment on both Ethereum and Solana
#
# Usage:
#   ./verify-deployment.sh <ethereum-rollup-address> <solana-program-id>

set -e

ETH_ROLLUP_ADDRESS="${1:-}"
SOLANA_PROGRAM_ID="${2:-}"

echo "=== FLUXE Deployment Verification ==="
echo ""

# ============ Ethereum Verification ============
if [ -n "$ETH_ROLLUP_ADDRESS" ]; then
    echo "--- Ethereum (Sepolia) ---"

    if [ -z "$SEPOLIA_RPC_URL" ]; then
        echo "Warning: SEPOLIA_RPC_URL not set, skipping Ethereum verification"
    else
        echo "Rollup Address: $ETH_ROLLUP_ADDRESS"

        # Check if contract exists
        CODE=$(cast code "$ETH_ROLLUP_ADDRESS" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null || echo "")
        if [ -z "$CODE" ] || [ "$CODE" == "0x" ]; then
            echo "ERROR: No contract code at address"
            exit 1
        fi
        echo "Contract deployed: YES"

        # Query contract state
        echo ""
        echo "Contract State:"

        VKEY=$(cast call "$ETH_ROLLUP_ADDRESS" "FLUXE_BLOCK_VKEY()(bytes32)" --rpc-url "$SEPOLIA_RPC_URL")
        echo "  FLUXE_BLOCK_VKEY: $VKEY"

        CHAIN_ID=$(cast call "$ETH_ROLLUP_ADDRESS" "FLUXE_L2_CHAIN_ID()(uint32)" --rpc-url "$SEPOLIA_RPC_URL")
        echo "  FLUXE_L2_CHAIN_ID: $CHAIN_ID"

        SEQUENCER=$(cast call "$ETH_ROLLUP_ADDRESS" "sequencer()(address)" --rpc-url "$SEPOLIA_RPC_URL")
        echo "  Sequencer: $SEQUENCER"

        OWNER=$(cast call "$ETH_ROLLUP_ADDRESS" "owner()(address)" --rpc-url "$SEPOLIA_RPC_URL")
        echo "  Owner: $OWNER"

        GENESIS=$(cast call "$ETH_ROLLUP_ADDRESS" "genesisFinalized()(bool)" --rpc-url "$SEPOLIA_RPC_URL")
        echo "  Genesis Finalized: $GENESIS"

        LAST_BATCH=$(cast call "$ETH_ROLLUP_ADDRESS" "lastFinalizedBatchId()(uint64)" --rpc-url "$SEPOLIA_RPC_URL")
        echo "  Last Finalized Batch: $LAST_BATCH"

        PAUSED=$(cast call "$ETH_ROLLUP_ADDRESS" "paused()(bool)" --rpc-url "$SEPOLIA_RPC_URL")
        echo "  Paused: $PAUSED"

        echo ""
        echo "Ethereum verification: PASSED"
    fi
fi

echo ""

# ============ Solana Verification ============
if [ -n "$SOLANA_PROGRAM_ID" ]; then
    echo "--- Solana (Devnet) ---"
    echo "Program ID: $SOLANA_PROGRAM_ID"

    # Check if program exists
    ACCOUNT_INFO=$(solana program show "$SOLANA_PROGRAM_ID" --url devnet 2>/dev/null || echo "")
    if [ -z "$ACCOUNT_INFO" ]; then
        echo "ERROR: Program not found"
        exit 1
    fi

    echo "Program deployed: YES"
    echo "$ACCOUNT_INFO"

    echo ""
    echo "Solana verification: PASSED"
fi

echo ""
echo "=== Verification Complete ==="

# Summary
echo ""
echo "Deployment Summary:"
if [ -n "$ETH_ROLLUP_ADDRESS" ]; then
    echo "  Ethereum Rollup: $ETH_ROLLUP_ADDRESS"
fi
if [ -n "$SOLANA_PROGRAM_ID" ]; then
    echo "  Solana Program: $SOLANA_PROGRAM_ID"
fi

echo ""
echo "Next Steps:"
echo "  1. Finalize genesis on both chains"
echo "  2. Configure assets (USDC, USDT)"
echo "  3. Start sequencer server"
echo "  4. Run E2E tests"
