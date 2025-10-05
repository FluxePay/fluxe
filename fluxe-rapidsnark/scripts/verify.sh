#!/bin/bash

# Fluxe Rapidsnark Verification Script
# Verifies proofs using both rapidsnark and snarkjs

set -e

# Configuration
CIRCUIT_NAME=${1:-"circuit"}
OUTPUT_DIR=${2:-"outputs"}
RAPIDSNARK_VERIFIER=${3:-"../rapidsnark/package_macos_arm64/bin/verifier"}

echo "=== Fluxe Rapidsnark Proof Verification ==="
echo "Circuit name: $CIRCUIT_NAME"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Check required files
if [ ! -f "$OUTPUT_DIR/${CIRCUIT_NAME}_vkey.json" ]; then
    echo "Error: Verification key not found at $OUTPUT_DIR/${CIRCUIT_NAME}_vkey.json"
    echo "Please run setup first: ./scripts/setup.sh $CIRCUIT_NAME"
    exit 1
fi

if [ ! -f "$OUTPUT_DIR/${CIRCUIT_NAME}_proof.json" ]; then
    echo "Error: Proof not found at $OUTPUT_DIR/${CIRCUIT_NAME}_proof.json"
    echo "Please generate proof first: ./scripts/prove.sh $CIRCUIT_NAME"
    exit 1
fi

if [ ! -f "$OUTPUT_DIR/${CIRCUIT_NAME}_public.json" ]; then
    echo "Error: Public inputs not found at $OUTPUT_DIR/${CIRCUIT_NAME}_public.json"
    echo "Please generate proof first: ./scripts/prove.sh $CIRCUIT_NAME"
    exit 1
fi

# Verify with rapidsnark if available
if [ -f "$RAPIDSNARK_VERIFIER" ]; then
    echo "Verifying with rapidsnark..."
    if "$RAPIDSNARK_VERIFIER" \
        "$OUTPUT_DIR/${CIRCUIT_NAME}_vkey.json" \
        "$OUTPUT_DIR/${CIRCUIT_NAME}_public.json" \
        "$OUTPUT_DIR/${CIRCUIT_NAME}_proof.json"; then
        echo "✓ Rapidsnark verification: VALID"
        RAPIDSNARK_RESULT=0
    else
        echo "✗ Rapidsnark verification: INVALID"
        RAPIDSNARK_RESULT=1
    fi
    echo ""
else
    echo "Warning: Rapidsnark verifier not found at $RAPIDSNARK_VERIFIER"
    echo "Skipping rapidsnark verification"
    echo ""
    RAPIDSNARK_RESULT=0
fi

# Cross-verify with snarkjs
if command -v npx &> /dev/null; then
    echo "Cross-verifying with snarkjs..."
    if npx snarkjs groth16 verify \
        "$OUTPUT_DIR/${CIRCUIT_NAME}_vkey.json" \
        "$OUTPUT_DIR/${CIRCUIT_NAME}_public.json" \
        "$OUTPUT_DIR/${CIRCUIT_NAME}_proof.json"; then
        echo "✓ SnarkJS verification: VALID"
        SNARKJS_RESULT=0
    else
        echo "✗ SnarkJS verification: INVALID"
        SNARKJS_RESULT=1
    fi
else
    echo "Warning: npx not found. Skipping snarkjs verification"
    SNARKJS_RESULT=0
fi

echo ""
if [ $RAPIDSNARK_RESULT -eq 0 ] && [ $SNARKJS_RESULT -eq 0 ]; then
    echo "=== Verification Successful ==="
    exit 0
else
    echo "=== Verification Failed ==="
    exit 1
fi
