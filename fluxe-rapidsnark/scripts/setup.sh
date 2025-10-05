#!/bin/bash

# Fluxe Rapidsnark Setup Script
# This script performs trusted setup for Fluxe circuits using snarkjs

set -e

# Configuration
CIRCUIT_NAME=${1:-"circuit"}
OUTPUT_DIR=${2:-"outputs"}
PTAU_SIZE=${3:-"16"}  # Powers of Tau ceremony size (2^PTAU_SIZE constraints)

echo "=== Fluxe Rapidsnark Setup ==="
echo "Circuit name: $CIRCUIT_NAME"
echo "Output directory: $OUTPUT_DIR"
echo "Powers of Tau size: $PTAU_SIZE"
echo ""

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Check if R1CS file exists
if [ ! -f "$OUTPUT_DIR/$CIRCUIT_NAME.r1cs" ]; then
    echo "Error: R1CS file not found at $OUTPUT_DIR/$CIRCUIT_NAME.r1cs"
    echo "Please run the circuit export first (cargo run --example export_$CIRCUIT_NAME)"
    exit 1
fi

# Check for snarkjs
if ! command -v npx &> /dev/null; then
    echo "Error: npx not found. Please install Node.js and npm."
    exit 1
fi

echo "Step 1: Checking for Powers of Tau file..."
PTAU_FILE="$OUTPUT_DIR/pot${PTAU_SIZE}_final.ptau"

if [ ! -f "$PTAU_FILE" ]; then
    echo "  Powers of Tau file not found. Generating..."
    echo "  Note: For production, use a file from a trusted ceremony (e.g., Hermez)"

    # Generate Powers of Tau
    npx snarkjs powersoftau new bn128 "$PTAU_SIZE" "$OUTPUT_DIR/pot${PTAU_SIZE}_0000.ptau" -v

    # Contribute to the ceremony
    echo "random_entropy" | npx snarkjs powersoftau contribute "$OUTPUT_DIR/pot${PTAU_SIZE}_0000.ptau" "$OUTPUT_DIR/pot${PTAU_SIZE}_0001.ptau" --name="First contribution" -v

    # Prepare for phase 2
    npx snarkjs powersoftau prepare phase2 "$OUTPUT_DIR/pot${PTAU_SIZE}_0001.ptau" "$PTAU_FILE" -v

    # Clean up intermediate files
    rm -f "$OUTPUT_DIR/pot${PTAU_SIZE}_0000.ptau" "$OUTPUT_DIR/pot${PTAU_SIZE}_0001.ptau"

    echo "  ✓ Powers of Tau generated"
else
    echo "  ✓ Using existing Powers of Tau file"
fi

echo ""
echo "Step 2: Performing Groth16 setup..."
npx snarkjs groth16 setup "$OUTPUT_DIR/$CIRCUIT_NAME.r1cs" "$PTAU_FILE" "$OUTPUT_DIR/${CIRCUIT_NAME}_0000.zkey" -v

echo ""
echo "Step 3: Contributing to zkey..."
echo "random_entropy_zkey" | npx snarkjs zkey contribute "$OUTPUT_DIR/${CIRCUIT_NAME}_0000.zkey" "$OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey" --name="Main contribution" -v

# Clean up intermediate zkey
rm -f "$OUTPUT_DIR/${CIRCUIT_NAME}_0000.zkey"

echo ""
echo "Step 4: Exporting verification key..."
npx snarkjs zkey export verificationkey "$OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey" "$OUTPUT_DIR/${CIRCUIT_NAME}_vkey.json"

echo ""
echo "Step 5: Verifying zkey..."
npx snarkjs zkey verify "$OUTPUT_DIR/$CIRCUIT_NAME.r1cs" "$PTAU_FILE" "$OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey"

echo ""
echo "=== Setup Complete ==="
echo "Generated files:"
echo "  Proving key:      $OUTPUT_DIR/${CIRCUIT_NAME}_final.zkey"
echo "  Verification key: $OUTPUT_DIR/${CIRCUIT_NAME}_vkey.json"
echo ""
echo "Next steps:"
echo "  1. Export witness with your circuit: cargo run --example export_$CIRCUIT_NAME"
echo "  2. Generate proof: ./scripts/prove.sh $CIRCUIT_NAME"
echo ""
