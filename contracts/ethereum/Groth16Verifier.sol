// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IGroth16Verifier.sol";

/// @title Groth16Verifier - BN254 Groth16 proof verifier for FLUXE
/// @notice Verifies Groth16 proofs for FLUXE batch state transitions
/// @dev Uses precompiled contracts for BN254 (alt_bn128) curve operations.
///
/// ## Architecture
///
/// The FLUXE protocol uses a two-layer proof system:
/// 1. Individual Transaction Proofs: Each tx type (Mint, Burn, Transfer, ObjectUpdate)
///    has its own circuit. These proofs are verified inside SP1.
/// 2. Batch Aggregation Proof: SP1 verifies all individual proofs and produces
///    an aggregated proof. This batch proof is verified on-chain.
///
/// ## VK Generation
///
/// IMPORTANT: The VK values below are PLACEHOLDERS from groth16-solana tests.
/// They must be replaced with the actual VK from the FLUXE batch circuit setup.
///
/// To generate the real VK:
/// 1. Run the FLUXE batch circuit setup
/// 2. Export using: `cargo run --bin export_vk -p fluxe-circuits -- batch_vk.bin --sol`
/// 3. Replace the constants below with the exported values
///
/// ## Public Inputs Format
///
/// For FLUXE batch proofs, the public inputs are:
/// [0] - State roots hash (SHA256 of all 8 state tree roots)
/// [1] - Batch ID (uint256)
/// [2] - Transaction count (uint256)
contract Groth16Verifier is IGroth16Verifier {
    // ============ BN254 Curve Constants ============

    /// @notice Prime field modulus for BN254
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @notice Scalar field modulus for BN254 (Fr)
    uint256 constant SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Precompiled contract addresses
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_PAIRING = 0x08;

    // ============ Verification Key ============
    //
    // IMPORTANT: These are PLACEHOLDER values. Replace with actual VK from trusted setup.
    //
    // The verification key consists of:
    // - Alpha (G1): Used in the pairing equation
    // - Beta (G2): Used in the pairing equation
    // - Gamma (G2): Used for public input verification
    // - Delta (G2): Used in the pairing equation
    // - IC (G1[]): Input commitment points, one constant + one per public input

    // Alpha (G1 point)
    uint256 constant VK_ALPHA_X = 0x2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e2;
    uint256 constant VK_ALPHA_Y = 0x14bedd503c37ceb061d8ec60209fe345ce89830a192303010076caff004d1926;

    // Beta (G2 point - note: coordinates are in Fq2, so x = x1 + x2*u, y = y1 + y2*u)
    uint256 constant VK_BETA_X1 = 0x0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c;
    uint256 constant VK_BETA_X2 = 0x0e187847ad4c798374d0d6732bf50184d0d6ff8bc0e071241e0213bc7fc13db7;
    uint256 constant VK_BETA_Y1 = 0x304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a7;
    uint256 constant VK_BETA_Y2 = 0x970c1b1a457a8c73131123d24d2f9192f896b7c63eea05a9d57f0654c7ad0ce8;

    // Gamma (G2 point)
    uint256 constant VK_GAMMA_X1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493353a9e71297e485b7aef312c2;
    uint256 constant VK_GAMMA_X2 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed;
    uint256 constant VK_GAMMA_Y1 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdcd122975b12;
    uint256 constant VK_GAMMA_Y2 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa;

    // Delta (G2 point)
    uint256 constant VK_DELTA_X1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493353a9e71297e485b7aef312c2;
    uint256 constant VK_DELTA_X2 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed;
    uint256 constant VK_DELTA_Y1 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdcd122975b12;
    uint256 constant VK_DELTA_Y2 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa;

    // IC (Input Commitment) points - variable length based on circuit
    // IC[0] is the constant term, IC[1..n] correspond to public inputs
    // Maximum number of public inputs supported
    uint256 constant MAX_PUBLIC_INPUTS = 32;

    // IC points storage (IC[0] + up to MAX_PUBLIC_INPUTS more)
    // These would be initialized from the verification key
    uint256[66] private IC; // 33 points * 2 coordinates

    // Actual number of IC points (set during construction)
    uint256 public immutable icLength;

    // ============ Errors ============

    error InvalidProofLength();
    error InvalidPublicInputCount();
    error PublicInputNotInField();
    error ProofVerificationFailed();
    error PrecompileFailed();

    // ============ Constructor ============

    constructor() {
        // Initialize IC points from verification key
        // PLACEHOLDER: These values must come from trusted setup
        //
        // Format: IC[i] = (IC[i].x, IC[i].y)
        // IC[0] is constant, IC[1..n] are for public inputs

        // IC[0] - constant term (example values from groth16-solana test)
        IC[0] = 0x03b7afbddb49b71c84c85308411688515224b5ba19d8ea199702ebc20ddf2091;
        IC[1] = 0x0f25717a5d3b5b19ec68e3ee3a9a43faba5b5d8d12f4963bcab0b301359f9bc7;

        // IC[1] - first public input coefficient
        IC[2] = 0x2efd5554a6f047af6faef43e5760ebc4d055ba2fa3ed35ccb0be3ec9bdd88447;
        IC[3] = 0x065be4614a0500ff9371a198eeb14e516f0d8edc18851b95426773225fe0ed2c;

        // Set IC length (number of public inputs + 1 for constant)
        // For FLUXE batch proofs: flexible based on number of batches
        icLength = 2; // PLACEHOLDER: Set based on actual circuit

        // Additional IC points would be initialized here...
        // In production, these would be generated from the trusted setup
    }

    // ============ External Functions ============

    /// @inheritdoc IGroth16Verifier
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        // Proof format: [a_x, a_y, b_x2, b_x1, b_y2, b_y1, c_x, c_y]
        // Note: b coordinates are in Fq2 with specific ordering for EVM
        // Total: 8 * 32 = 256 bytes
        if (proof.length != 256) revert InvalidProofLength();

        // Parse proof points
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;

        assembly {
            let proofPtr := proof.offset
            // A (G1)
            mstore(a, calldataload(proofPtr))
            mstore(add(a, 0x20), calldataload(add(proofPtr, 0x20)))
            // B (G2) - x and y components with specific EVM ordering
            mstore(b, calldataload(add(proofPtr, 0x40)))
            mstore(add(b, 0x20), calldataload(add(proofPtr, 0x60)))
            mstore(add(b, 0x40), calldataload(add(proofPtr, 0x80)))
            mstore(add(b, 0x60), calldataload(add(proofPtr, 0xa0)))
            // C (G1)
            mstore(c, calldataload(add(proofPtr, 0xc0)))
            mstore(add(c, 0x20), calldataload(add(proofPtr, 0xe0)))
        }

        return _verifyProofInternal(a, b, c, publicInputs);
    }

    /// @inheritdoc IGroth16Verifier
    function verifyProofParsed(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        return _verifyProofInternal(a, b, c, publicInputs);
    }

    // ============ Internal Functions ============

    /// @notice Internal proof verification
    /// @dev Implements the Groth16 verification equation:
    ///      e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
    function _verifyProofInternal(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        // Validate public inputs count matches IC points
        if (publicInputs.length + 1 != icLength) {
            revert InvalidPublicInputCount();
        }

        // Compute linear combination: vk_x = IC[0] + sum(publicInputs[i] * IC[i+1])
        uint256[2] memory vk_x;
        vk_x[0] = IC[0];
        vk_x[1] = IC[1];

        for (uint256 i = 0; i < publicInputs.length; i++) {
            // Validate public input is in scalar field
            if (publicInputs[i] >= SCALAR_FIELD) {
                revert PublicInputNotInField();
            }

            // Skip if public input is zero (optimization)
            if (publicInputs[i] == 0) continue;

            // Get IC[i+1] coordinates
            uint256 icX = IC[(i + 1) * 2];
            uint256 icY = IC[(i + 1) * 2 + 1];

            // Scalar multiplication: publicInputs[i] * IC[i+1]
            uint256[2] memory mulResult = _scalarMul(icX, icY, publicInputs[i]);

            // Point addition: vk_x = vk_x + mulResult
            vk_x = _pointAdd(vk_x[0], vk_x[1], mulResult[0], mulResult[1]);
        }

        // Verify pairing equation
        return _verifyPairing(a, b, vk_x, c);
    }

    /// @notice Scalar multiplication using bn256ScalarMul precompile
    function _scalarMul(
        uint256 x,
        uint256 y,
        uint256 scalar
    ) internal view returns (uint256[2] memory result) {
        uint256[3] memory input;
        input[0] = x;
        input[1] = y;
        input[2] = scalar;

        bool success;
        assembly {
            success := staticcall(gas(), PRECOMPILE_MUL, input, 0x60, result, 0x40)
        }

        if (!success) revert PrecompileFailed();
        return result;
    }

    /// @notice Point addition using bn256Add precompile
    function _pointAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal view returns (uint256[2] memory result) {
        uint256[4] memory input;
        input[0] = x1;
        input[1] = y1;
        input[2] = x2;
        input[3] = y2;

        bool success;
        assembly {
            success := staticcall(gas(), PRECOMPILE_ADD, input, 0x80, result, 0x40)
        }

        if (!success) revert PrecompileFailed();
        return result;
    }

    /// @notice Negate a G1 point for pairing
    function _negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p; // Point at infinity
        }
        return [p[0], PRIME_Q - (p[1] % PRIME_Q)];
    }

    /// @notice Verify pairing equation using bn256Pairing precompile
    /// @dev Checks: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    function _verifyPairing(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory vk_x,
        uint256[2] memory c
    ) internal view returns (bool) {
        // Negate A for the pairing equation
        uint256[2] memory negA = _negate(a);

        // Build pairing input: 4 pairs of (G1, G2) points
        // Each G1 point: 2 * 32 = 64 bytes
        // Each G2 point: 4 * 32 = 128 bytes
        // Total per pair: 192 bytes, 4 pairs = 768 bytes
        uint256[24] memory input;

        // Pair 1: e(-A, B)
        input[0] = negA[0];
        input[1] = negA[1];
        input[2] = b[0][0];
        input[3] = b[0][1];
        input[4] = b[1][0];
        input[5] = b[1][1];

        // Pair 2: e(alpha, beta)
        input[6] = VK_ALPHA_X;
        input[7] = VK_ALPHA_Y;
        input[8] = VK_BETA_X1;
        input[9] = VK_BETA_X2;
        input[10] = VK_BETA_Y1;
        input[11] = VK_BETA_Y2;

        // Pair 3: e(vk_x, gamma)
        input[12] = vk_x[0];
        input[13] = vk_x[1];
        input[14] = VK_GAMMA_X1;
        input[15] = VK_GAMMA_X2;
        input[16] = VK_GAMMA_Y1;
        input[17] = VK_GAMMA_Y2;

        // Pair 4: e(C, delta)
        input[18] = c[0];
        input[19] = c[1];
        input[20] = VK_DELTA_X1;
        input[21] = VK_DELTA_X2;
        input[22] = VK_DELTA_Y1;
        input[23] = VK_DELTA_Y2;

        uint256[1] memory result;
        bool success;

        assembly {
            // Call bn256Pairing precompile
            // Input: 24 * 32 = 768 bytes
            // Output: 32 bytes (1 if valid, 0 otherwise)
            success := staticcall(gas(), PRECOMPILE_PAIRING, input, 768, result, 0x20)
        }

        if (!success) revert PrecompileFailed();
        return result[0] == 1;
    }
}
