#!/bin/bash

# Fluxe Rapidsnark Proving Script
# Generates proofs using rapidsnark prover

set -e

# Configuration
CIRCUIT_NAME=${1:-"circuit"}
OUTPUT_DIR=${2:-"outputs"}
RAPIDSNARK_PROVER=${3:-"../rapidsnark/package_macos_arm64/bin/prover"}

echo "=== Fluxe Rapidsnark Proof Generation ==="
echo "Circuit name: $CIRCUIT_NAME"
echo "Output directory: $OUTPUT_DIR"
echo "Rapidsnark prover: $RAPIDSNARK_PROVER"
echo ""

# Check required files
if [ ! -f "$OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey" ]; then
    echo "Error: Proving key not found at $OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey"
    echo "Please run setup first: ./scripts/setup.sh $CIRCUIT_NAME"
    exit 1
fi

if [ ! -f "$OUTPUT_DIR/${CIRCUIT_NAME}_witness.wtns" ]; then
    echo "Error: Witness file not found at $OUTPUT_DIR/${CIRCUIT_NAME}_witness.wtns"
    echo "Please export witness first: cargo run --example export_$CIRCUIT_NAME"
    exit 1
fi

if [ ! -f "$RAPIDSNARK_PROVER" ]; then
    echo "Error: Rapidsnark prover not found at $RAPIDSNARK_PROVER"
    echo "Please build rapidsnark or adjust the path"
    exit 1
fi

echo "Generating proof with rapidsnark..."
echo "  Proving key: $OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey"
echo "  Witness:     $OUTPUT_DIR/${CIRCUIT_NAME}_witness.wtns"
echo ""

# Generate proof with rapidsnark
"$RAPIDSNARK_PROVER" \
    "$OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey" \
    "$OUTPUT_DIR/${CIRCUIT_NAME}_witness.wtns" \
    "$OUTPUT_DIR/${CIRCUIT_NAME}_proof.json" \
    "$OUTPUT_DIR/${CIRCUIT_NAME}_public.json"

echo ""
echo "=== Proof Generated Successfully ==="
echo "Output files:"
echo "  Proof:        $OUTPUT_DIR/${CIRCUIT_NAME}_proof.json"
echo "  Public inputs: $OUTPUT_DIR/${CIRCUIT_NAME}_public.json"
echo ""
echo "Next steps:"
echo "  Verify proof: ./scripts/verify.sh $CIRCUIT_NAME"
echo ""
