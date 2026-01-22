// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IGroth16Verifier - Interface for Groth16 proof verification
/// @notice Standard interface for verifying Groth16 proofs on BN254 curve
interface IGroth16Verifier {
    /// @notice Verify a Groth16 proof
    /// @param proof Serialized proof (a, b, c points)
    /// @param publicInputs Array of public inputs as field elements
    /// @return True if the proof is valid
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);

    /// @notice Verify a Groth16 proof with pre-parsed points
    /// @param a G1 point (2 uint256)
    /// @param b G2 point (2x2 uint256)
    /// @param c G1 point (2 uint256)
    /// @param publicInputs Array of public inputs
    /// @return True if the proof is valid
    function verifyProofParsed(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}
