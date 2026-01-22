// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Merkle
 * @author FLUXE Team
 * @notice A library for verifying Merkle proofs with support for both index-based and sorted proof verification
 * @dev This library provides gas-efficient Merkle proof verification with fixed height validation
 *      to prevent length extension attacks. It supports two verification modes:
 *      1. Index-based: Uses leaf index to determine sibling ordering
 *      2. Sorted: Uses hash comparison to determine sibling ordering
 *
 *      Security considerations:
 *      - Always validate proof length matches expected tree height
 *      - Use fixed height validation to prevent shorter/longer path attacks
 *      - keccak256 is used for all hash operations
 */
library Merkle {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the proof path length is zero
    error MerkleEmptyProof();

    /// @notice Thrown when the proof path length exceeds maximum allowed (255)
    error MerkleProofTooLong();

    /// @notice Thrown when the leaf index is out of bounds for the given tree height
    error MerkleIndexOutOfBounds();

    /// @notice Thrown when the proof length doesn't match the expected tree height
    error MerkleInvalidProofLength(uint256 expected, uint256 actual);

    /*//////////////////////////////////////////////////////////////
                           INDEX-BASED PROOFS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculates the Merkle root from a proof using index-based sibling ordering
     * @dev The index determines whether the current hash is the left or right sibling:
     *      - If index is even, current hash is on the left
     *      - If index is odd, current hash is on the right
     *
     *      SECURITY WARNING: When using this function, ensure the proof length equals
     *      the expected tree height to prevent shorter/longer path attacks.
     *
     * @param _proof Array of sibling hashes from leaf to root (excluding leaf and root)
     * @param _index Position of the leaf in the tree (0-indexed from left)
     * @param _leafHash Hash of the leaf content to verify
     * @return root The calculated Merkle root
     *
     * @custom:example
     * For a tree with height 3 and leaf at index 5:
     * ```
     *           root
     *          /    \
     *        h01    h23
     *       /  \   /   \
     *      h0  h1 h2   h3
     *     /\ /\ /\  /\
     *    0 1 2 3 4 5 6 7
     *              ^
     *              leaf (index 5)
     * ```
     * The proof would contain [h2, h01] (sibling at each level)
     */
    function calculateRoot(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash
    ) internal pure returns (bytes32 root) {
        uint256 proofLength = _proof.length;

        if (proofLength == 0) {
            revert MerkleEmptyProof();
        }
        if (proofLength >= 256) {
            revert MerkleProofTooLong();
        }
        if (_index >= (1 << proofLength)) {
            revert MerkleIndexOutOfBounds();
        }

        bytes32 currentHash = _leafHash;

        for (uint256 i = 0; i < proofLength;) {
            bytes32 sibling = _proof[i];

            if (_index & 1 == 0) {
                // Current hash is on the left
                currentHash = keccak256(abi.encode(currentHash, sibling));
            } else {
                // Current hash is on the right
                currentHash = keccak256(abi.encode(sibling, currentHash));
            }

            _index >>= 1;

            unchecked {
                ++i;
            }
        }

        return currentHash;
    }

    /**
     * @notice Calculates the Merkle root with fixed height validation
     * @dev This function enforces that the proof length exactly matches the expected tree height,
     *      providing protection against shorter/longer path attacks.
     *
     * @param _proof Array of sibling hashes from leaf to root
     * @param _index Position of the leaf in the tree (0-indexed)
     * @param _leafHash Hash of the leaf content
     * @param _expectedHeight Expected height of the Merkle tree (equals proof length)
     * @return root The calculated Merkle root
     *
     * @custom:security This is the recommended function for production use as it validates tree height
     */
    function calculateRootWithHeight(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash,
        uint256 _expectedHeight
    ) internal pure returns (bytes32 root) {
        if (_proof.length != _expectedHeight) {
            revert MerkleInvalidProofLength(_expectedHeight, _proof.length);
        }

        return calculateRoot(_proof, _index, _leafHash);
    }

    /**
     * @notice Verifies a Merkle proof against an expected root using index-based ordering
     * @dev Convenience function that calculates the root and compares it to the expected value
     *
     * @param _proof Array of sibling hashes from leaf to root
     * @param _index Position of the leaf in the tree
     * @param _leafHash Hash of the leaf content
     * @param _expectedRoot The expected Merkle root
     * @return isValid True if the calculated root matches the expected root
     */
    function verifyProof(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash,
        bytes32 _expectedRoot
    ) internal pure returns (bool isValid) {
        return calculateRoot(_proof, _index, _leafHash) == _expectedRoot;
    }

    /**
     * @notice Verifies a Merkle proof with fixed height validation
     * @dev Combines root verification with height validation for maximum security
     *
     * @param _proof Array of sibling hashes from leaf to root
     * @param _index Position of the leaf in the tree
     * @param _leafHash Hash of the leaf content
     * @param _expectedRoot The expected Merkle root
     * @param _expectedHeight Expected height of the Merkle tree
     * @return isValid True if the proof is valid and height matches
     */
    function verifyProofWithHeight(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash,
        bytes32 _expectedRoot,
        uint256 _expectedHeight
    ) internal pure returns (bool isValid) {
        return calculateRootWithHeight(_proof, _index, _leafHash, _expectedHeight) == _expectedRoot;
    }

    /*//////////////////////////////////////////////////////////////
                            SORTED PROOFS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculates the Merkle root using sorted (hash-ordered) proof verification
     * @dev In sorted proofs, the ordering of siblings is determined by comparing hash values:
     *      - The smaller hash is always placed on the left
     *      - This eliminates the need to track the leaf index
     *      - Compatible with OpenZeppelin's MerkleProof library pattern
     *
     *      SECURITY NOTE: Sorted proofs cannot distinguish between identical subtrees
     *      at different positions. Use index-based proofs when position matters.
     *
     * @param _proof Array of sibling hashes from leaf to root
     * @param _leafHash Hash of the leaf content
     * @return root The calculated Merkle root
     *
     * @custom:example
     * For verifying membership in a set where position doesn't matter (e.g., allowlists)
     */
    function calculateSortedRoot(
        bytes32[] calldata _proof,
        bytes32 _leafHash
    ) internal pure returns (bytes32 root) {
        uint256 proofLength = _proof.length;

        if (proofLength == 0) {
            revert MerkleEmptyProof();
        }
        if (proofLength >= 256) {
            revert MerkleProofTooLong();
        }

        bytes32 currentHash = _leafHash;

        for (uint256 i = 0; i < proofLength;) {
            bytes32 sibling = _proof[i];

            if (currentHash <= sibling) {
                currentHash = keccak256(abi.encode(currentHash, sibling));
            } else {
                currentHash = keccak256(abi.encode(sibling, currentHash));
            }

            unchecked {
                ++i;
            }
        }

        return currentHash;
    }

    /**
     * @notice Calculates sorted Merkle root with fixed height validation
     * @dev Combines sorted proof calculation with height enforcement
     *
     * @param _proof Array of sibling hashes from leaf to root
     * @param _leafHash Hash of the leaf content
     * @param _expectedHeight Expected height of the Merkle tree
     * @return root The calculated Merkle root
     */
    function calculateSortedRootWithHeight(
        bytes32[] calldata _proof,
        bytes32 _leafHash,
        uint256 _expectedHeight
    ) internal pure returns (bytes32 root) {
        if (_proof.length != _expectedHeight) {
            revert MerkleInvalidProofLength(_expectedHeight, _proof.length);
        }

        return calculateSortedRoot(_proof, _leafHash);
    }

    /**
     * @notice Verifies a sorted Merkle proof against an expected root
     * @dev Uses hash comparison for sibling ordering instead of index
     *
     * @param _proof Array of sibling hashes from leaf to root
     * @param _leafHash Hash of the leaf content
     * @param _expectedRoot The expected Merkle root
     * @return isValid True if the calculated root matches the expected root
     */
    function verifySortedProof(
        bytes32[] calldata _proof,
        bytes32 _leafHash,
        bytes32 _expectedRoot
    ) internal pure returns (bool isValid) {
        return calculateSortedRoot(_proof, _leafHash) == _expectedRoot;
    }

    /**
     * @notice Verifies a sorted Merkle proof with fixed height validation
     * @dev Recommended for production use when using sorted proofs
     *
     * @param _proof Array of sibling hashes from leaf to root
     * @param _leafHash Hash of the leaf content
     * @param _expectedRoot The expected Merkle root
     * @param _expectedHeight Expected height of the Merkle tree
     * @return isValid True if the proof is valid and height matches
     */
    function verifySortedProofWithHeight(
        bytes32[] calldata _proof,
        bytes32 _leafHash,
        bytes32 _expectedRoot,
        uint256 _expectedHeight
    ) internal pure returns (bool isValid) {
        return calculateSortedRootWithHeight(_proof, _leafHash, _expectedHeight) == _expectedRoot;
    }

    /*//////////////////////////////////////////////////////////////
                           UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes the hash of a leaf node
     * @dev Applies double hashing to prevent second preimage attacks:
     *      leaf_hash = keccak256(keccak256(data))
     *
     * @param _data The raw leaf data to hash
     * @return leafHash The computed leaf hash
     */
    function hashLeaf(bytes memory _data) internal pure returns (bytes32 leafHash) {
        return keccak256(abi.encodePacked(keccak256(_data)));
    }

    /**
     * @notice Computes the hash of two child nodes to form a parent node
     * @dev Used for building Merkle trees. The order of children matters for index-based proofs.
     *
     * @param _left Hash of the left child
     * @param _right Hash of the right child
     * @return parentHash The computed parent hash
     */
    function hashPair(bytes32 _left, bytes32 _right) internal pure returns (bytes32 parentHash) {
        return keccak256(abi.encode(_left, _right));
    }

    /**
     * @notice Computes the hash of two nodes in sorted order
     * @dev Used for building sorted Merkle trees where the smaller hash is always on the left
     *
     * @param _a First hash
     * @param _b Second hash
     * @return parentHash The computed parent hash with children in sorted order
     */
    function hashSortedPair(bytes32 _a, bytes32 _b) internal pure returns (bytes32 parentHash) {
        if (_a <= _b) {
            return keccak256(abi.encode(_a, _b));
        } else {
            return keccak256(abi.encode(_b, _a));
        }
    }
}
