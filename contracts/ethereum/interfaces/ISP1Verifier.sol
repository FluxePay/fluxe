// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SP1 Verifier Interface
/// @author Succinct Labs
/// @notice Interface for verifying SP1 proofs on-chain
/// @dev Use with SP1VerifierGateway for automatic proof routing
///
/// Deployed SP1VerifierGateway addresses:
/// - Ethereum Mainnet: 0x3B6041173B80E77f038f3F2C0f9744f04837185e
/// - Ethereum Sepolia: 0x3B6041173B80E77f038f3F2C0f9744f04837185e
/// - Base Mainnet: 0x3B6041173B80E77f038f3F2C0f9744f04837185e
/// - Arbitrum One: 0x3B6041173B80E77f038f3F2C0f9744f04837185e
///
/// See: https://docs.succinct.xyz/docs/sp1/verification/solidity-sdk
interface ISP1Verifier {
    /// @notice Verifies a proof with given public values and vkey.
    /// @dev It is expected that the first 4 bytes of proofBytes must match the first 4 bytes of
    /// target verifier's VERIFIER_HASH. Reverts if verification fails.
    /// @param programVKey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @notice Extended interface that includes verifier hash
interface ISP1VerifierWithHash is ISP1Verifier {
    /// @notice Returns the hash of the verifier.
    function VERIFIER_HASH() external pure returns (bytes32);
}
