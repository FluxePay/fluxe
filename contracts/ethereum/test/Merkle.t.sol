// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "contracts/libraries/Merkle.sol";

/// @title MerkleWrapper - Wrapper contract to expose Merkle library functions for testing
/// @notice Converts memory arrays to calldata by making external calls
contract MerkleWrapper {
    function calculateRoot(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash
    ) external pure returns (bytes32) {
        return Merkle.calculateRoot(_proof, _index, _leafHash);
    }

    function calculateRootWithHeight(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash,
        uint256 _expectedHeight
    ) external pure returns (bytes32) {
        return Merkle.calculateRootWithHeight(_proof, _index, _leafHash, _expectedHeight);
    }

    function verifyProof(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash,
        bytes32 _expectedRoot
    ) external pure returns (bool) {
        return Merkle.verifyProof(_proof, _index, _leafHash, _expectedRoot);
    }

    function verifyProofWithHeight(
        bytes32[] calldata _proof,
        uint256 _index,
        bytes32 _leafHash,
        bytes32 _expectedRoot,
        uint256 _expectedHeight
    ) external pure returns (bool) {
        return Merkle.verifyProofWithHeight(_proof, _index, _leafHash, _expectedRoot, _expectedHeight);
    }

    function calculateSortedRoot(
        bytes32[] calldata _proof,
        bytes32 _leafHash
    ) external pure returns (bytes32) {
        return Merkle.calculateSortedRoot(_proof, _leafHash);
    }

    function calculateSortedRootWithHeight(
        bytes32[] calldata _proof,
        bytes32 _leafHash,
        uint256 _expectedHeight
    ) external pure returns (bytes32) {
        return Merkle.calculateSortedRootWithHeight(_proof, _leafHash, _expectedHeight);
    }

    function verifySortedProof(
        bytes32[] calldata _proof,
        bytes32 _leafHash,
        bytes32 _expectedRoot
    ) external pure returns (bool) {
        return Merkle.verifySortedProof(_proof, _leafHash, _expectedRoot);
    }

    function verifySortedProofWithHeight(
        bytes32[] calldata _proof,
        bytes32 _leafHash,
        bytes32 _expectedRoot,
        uint256 _expectedHeight
    ) external pure returns (bool) {
        return Merkle.verifySortedProofWithHeight(_proof, _leafHash, _expectedRoot, _expectedHeight);
    }

    function hashLeaf(bytes memory _data) external pure returns (bytes32) {
        return Merkle.hashLeaf(_data);
    }

    function hashPair(bytes32 _left, bytes32 _right) external pure returns (bytes32) {
        return Merkle.hashPair(_left, _right);
    }

    function hashSortedPair(bytes32 _a, bytes32 _b) external pure returns (bytes32) {
        return Merkle.hashSortedPair(_a, _b);
    }
}

/// @title MerkleTest
/// @notice Comprehensive tests for the Merkle library
contract MerkleTest is Test {
    MerkleWrapper public merkle;

    function setUp() public {
        merkle = new MerkleWrapper();
    }

    // ============ calculateRoot Tests ============

    function test_CalculateRoot_SingleLevel() public view {
        // Tree with 2 leaves: index 0 and 1
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 expectedRoot = keccak256(abi.encode(leaf0, leaf1));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        bytes32 calculatedRoot = merkle.calculateRoot(proof, 0, leaf0);
        assertEq(calculatedRoot, expectedRoot);
    }

    function test_CalculateRoot_TwoLevels() public view {
        // Tree with 4 leaves
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 leaf2 = keccak256("leaf2");
        bytes32 leaf3 = keccak256("leaf3");

        bytes32 hash01 = keccak256(abi.encode(leaf0, leaf1));
        bytes32 hash23 = keccak256(abi.encode(leaf2, leaf3));
        bytes32 expectedRoot = keccak256(abi.encode(hash01, hash23));

        // Proof for leaf0: [leaf1, hash23]
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaf1;
        proof[1] = hash23;

        bytes32 calculatedRoot = merkle.calculateRoot(proof, 0, leaf0);
        assertEq(calculatedRoot, expectedRoot);
    }

    function test_CalculateRoot_RightSideLeaf() public view {
        // Verify proof for leaf at odd index (right side)
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 expectedRoot = keccak256(abi.encode(leaf0, leaf1));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf0;

        // Index 1 means we're on the right side
        bytes32 calculatedRoot = merkle.calculateRoot(proof, 1, leaf1);
        assertEq(calculatedRoot, expectedRoot);
    }

    function test_CalculateRoot_MiddleIndex() public view {
        // Tree with 8 leaves, verify leaf at index 5
        bytes32[] memory leaves = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) {
            leaves[i] = keccak256(abi.encodePacked("leaf", i));
        }

        // Build tree manually
        bytes32 h01 = keccak256(abi.encode(leaves[0], leaves[1]));
        bytes32 h23 = keccak256(abi.encode(leaves[2], leaves[3]));
        bytes32 h45 = keccak256(abi.encode(leaves[4], leaves[5]));
        bytes32 h67 = keccak256(abi.encode(leaves[6], leaves[7]));
        bytes32 h0123 = keccak256(abi.encode(h01, h23));
        bytes32 h4567 = keccak256(abi.encode(h45, h67));
        bytes32 expectedRoot = keccak256(abi.encode(h0123, h4567));

        // Proof for index 5: [leaf4, h67, h0123]
        bytes32[] memory proof = new bytes32[](3);
        proof[0] = leaves[4]; // sibling at level 0
        proof[1] = h67;       // sibling at level 1
        proof[2] = h0123;     // sibling at level 2

        bytes32 calculatedRoot = merkle.calculateRoot(proof, 5, leaves[5]);
        assertEq(calculatedRoot, expectedRoot);
    }

    function test_CalculateRoot_RevertOnEmptyProof() public {
        bytes32[] memory emptyProof = new bytes32[](0);
        bytes32 leaf = keccak256("leaf");

        vm.expectRevert(Merkle.MerkleEmptyProof.selector);
        merkle.calculateRoot(emptyProof, 0, leaf);
    }

    function test_CalculateRoot_RevertOnProofTooLong() public {
        bytes32[] memory longProof = new bytes32[](256);
        bytes32 leaf = keccak256("leaf");

        vm.expectRevert(Merkle.MerkleProofTooLong.selector);
        merkle.calculateRoot(longProof, 0, leaf);
    }

    function test_CalculateRoot_RevertOnIndexOutOfBounds() public {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("sibling0");
        proof[1] = keccak256("sibling1");
        bytes32 leaf = keccak256("leaf");

        // Height 2 means max index is 3 (2^2 - 1)
        vm.expectRevert(Merkle.MerkleIndexOutOfBounds.selector);
        merkle.calculateRoot(proof, 4, leaf);
    }

    function test_CalculateRoot_MaxValidIndex() public view {
        bytes32[] memory proof = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            proof[i] = keccak256(abi.encodePacked("sibling", i));
        }
        bytes32 leaf = keccak256("leaf");

        // Height 3 means max index is 7 (2^3 - 1)
        bytes32 root = merkle.calculateRoot(proof, 7, leaf);
        assertTrue(root != bytes32(0));
    }

    // ============ calculateRootWithHeight Tests ============

    function test_CalculateRootWithHeight_ValidHeight() public view {
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 expectedRoot = keccak256(abi.encode(leaf0, leaf1));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        bytes32 calculatedRoot = merkle.calculateRootWithHeight(proof, 0, leaf0, 1);
        assertEq(calculatedRoot, expectedRoot);
    }

    function test_CalculateRootWithHeight_RevertOnHeightMismatch() public {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("sibling0");
        proof[1] = keccak256("sibling1");
        bytes32 leaf = keccak256("leaf");

        vm.expectRevert(abi.encodeWithSelector(
            Merkle.MerkleInvalidProofLength.selector,
            3,  // expected height
            2   // actual length
        ));
        merkle.calculateRootWithHeight(proof, 0, leaf, 3);
    }

    function test_CalculateRootWithHeight_Height10() public view {
        bytes32[] memory proof = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            proof[i] = keccak256(abi.encodePacked("sibling", i));
        }
        bytes32 leaf = keccak256("leaf");

        bytes32 root = merkle.calculateRootWithHeight(proof, 512, leaf, 10);
        assertTrue(root != bytes32(0));
    }

    // ============ verifyProof Tests ============

    function test_VerifyProof_Valid() public view {
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 expectedRoot = keccak256(abi.encode(leaf0, leaf1));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        bool isValid = merkle.verifyProof(proof, 0, leaf0, expectedRoot);
        assertTrue(isValid);
    }

    function test_VerifyProof_Invalid() public view {
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 wrongRoot = keccak256("wrong");

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        bool isValid = merkle.verifyProof(proof, 0, leaf0, wrongRoot);
        assertFalse(isValid);
    }

    function test_VerifyProof_WrongIndex() public view {
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 correctRoot = keccak256(abi.encode(leaf0, leaf1));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // Using wrong index should produce different root
        bool isValid = merkle.verifyProof(proof, 1, leaf0, correctRoot);
        assertFalse(isValid);
    }

    // ============ verifyProofWithHeight Tests ============

    function test_VerifyProofWithHeight_Valid() public view {
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 expectedRoot = keccak256(abi.encode(leaf0, leaf1));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        bool isValid = merkle.verifyProofWithHeight(proof, 0, leaf0, expectedRoot, 1);
        assertTrue(isValid);
    }

    function test_VerifyProofWithHeight_RevertOnWrongHeight() public {
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 expectedRoot = keccak256(abi.encode(leaf0, leaf1));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        vm.expectRevert(abi.encodeWithSelector(
            Merkle.MerkleInvalidProofLength.selector,
            2,
            1
        ));
        merkle.verifyProofWithHeight(proof, 0, leaf0, expectedRoot, 2);
    }

    // ============ Sorted Proof Tests ============

    function test_CalculateSortedRoot_SmallFirst() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = larger;

        bytes32 root = merkle.calculateSortedRoot(proof, smaller);
        bytes32 expectedRoot = keccak256(abi.encode(smaller, larger));
        assertEq(root, expectedRoot);
    }

    function test_CalculateSortedRoot_LargeFirst() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = smaller;

        // When leaf is larger, it should be placed on the right
        bytes32 root = merkle.calculateSortedRoot(proof, larger);
        bytes32 expectedRoot = keccak256(abi.encode(smaller, larger));
        assertEq(root, expectedRoot);
    }

    function test_CalculateSortedRoot_MultiLevel() public view {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));

        // For sorted proofs, siblings are sorted at each level
        // Level 0: hash(a, b) since a < b
        bytes32 ab = keccak256(abi.encode(a, b));

        // Level 1: We need a sibling for ab
        bytes32 sibling1 = keccak256("sibling1");

        // Compute root based on sorted ordering
        bytes32 expectedRoot;
        if (ab <= sibling1) {
            expectedRoot = keccak256(abi.encode(ab, sibling1));
        } else {
            expectedRoot = keccak256(abi.encode(sibling1, ab));
        }

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = b;
        proof[1] = sibling1;

        bytes32 calculatedRoot = merkle.calculateSortedRoot(proof, a);
        assertEq(calculatedRoot, expectedRoot);
    }

    function test_CalculateSortedRoot_RevertOnEmptyProof() public {
        bytes32[] memory emptyProof = new bytes32[](0);
        bytes32 leaf = keccak256("leaf");

        vm.expectRevert(Merkle.MerkleEmptyProof.selector);
        merkle.calculateSortedRoot(emptyProof, leaf);
    }

    function test_CalculateSortedRoot_RevertOnProofTooLong() public {
        bytes32[] memory longProof = new bytes32[](256);
        bytes32 leaf = keccak256("leaf");

        vm.expectRevert(Merkle.MerkleProofTooLong.selector);
        merkle.calculateSortedRoot(longProof, leaf);
    }

    function test_CalculateSortedRootWithHeight_Valid() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = larger;

        bytes32 root = merkle.calculateSortedRootWithHeight(proof, smaller, 1);
        bytes32 expectedRoot = keccak256(abi.encode(smaller, larger));
        assertEq(root, expectedRoot);
    }

    function test_CalculateSortedRootWithHeight_RevertOnHeightMismatch() public {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = bytes32(uint256(1));
        proof[1] = bytes32(uint256(2));
        bytes32 leaf = bytes32(uint256(3));

        vm.expectRevert(abi.encodeWithSelector(
            Merkle.MerkleInvalidProofLength.selector,
            3,
            2
        ));
        merkle.calculateSortedRootWithHeight(proof, leaf, 3);
    }

    function test_VerifySortedProof_Valid() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));
        bytes32 expectedRoot = keccak256(abi.encode(smaller, larger));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = larger;

        bool isValid = merkle.verifySortedProof(proof, smaller, expectedRoot);
        assertTrue(isValid);
    }

    function test_VerifySortedProof_Invalid() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));
        bytes32 wrongRoot = keccak256("wrong");

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = larger;

        bool isValid = merkle.verifySortedProof(proof, smaller, wrongRoot);
        assertFalse(isValid);
    }

    function test_VerifySortedProofWithHeight_Valid() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));
        bytes32 expectedRoot = keccak256(abi.encode(smaller, larger));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = larger;

        bool isValid = merkle.verifySortedProofWithHeight(proof, smaller, expectedRoot, 1);
        assertTrue(isValid);
    }

    // ============ Utility Function Tests ============

    function test_HashLeaf() public view {
        bytes memory data = "test data";
        bytes32 expectedHash = keccak256(abi.encodePacked(keccak256(data)));
        bytes32 leafHash = merkle.hashLeaf(data);
        assertEq(leafHash, expectedHash);
    }

    function test_HashLeaf_EmptyData() public view {
        bytes memory data = "";
        bytes32 expectedHash = keccak256(abi.encodePacked(keccak256(data)));
        bytes32 leafHash = merkle.hashLeaf(data);
        assertEq(leafHash, expectedHash);
    }

    function test_HashPair() public view {
        bytes32 left = keccak256("left");
        bytes32 right = keccak256("right");
        bytes32 expectedHash = keccak256(abi.encode(left, right));
        bytes32 pairHash = merkle.hashPair(left, right);
        assertEq(pairHash, expectedHash);
    }

    function test_HashPair_OrderMatters() public view {
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");

        bytes32 hash_ab = merkle.hashPair(a, b);
        bytes32 hash_ba = merkle.hashPair(b, a);

        assertTrue(hash_ab != hash_ba);
    }

    function test_HashSortedPair_SmallerFirst() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));
        bytes32 expectedHash = keccak256(abi.encode(smaller, larger));

        bytes32 sortedHash = merkle.hashSortedPair(smaller, larger);
        assertEq(sortedHash, expectedHash);
    }

    function test_HashSortedPair_LargerFirst() public view {
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));
        bytes32 expectedHash = keccak256(abi.encode(smaller, larger));

        // Even when larger is first argument, output should be same
        bytes32 sortedHash = merkle.hashSortedPair(larger, smaller);
        assertEq(sortedHash, expectedHash);
    }

    function test_HashSortedPair_Commutative() public view {
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");

        bytes32 hash_ab = merkle.hashSortedPair(a, b);
        bytes32 hash_ba = merkle.hashSortedPair(b, a);

        assertEq(hash_ab, hash_ba);
    }

    function test_HashSortedPair_EqualValues() public view {
        bytes32 value = keccak256("same");
        bytes32 expectedHash = keccak256(abi.encode(value, value));

        bytes32 sortedHash = merkle.hashSortedPair(value, value);
        assertEq(sortedHash, expectedHash);
    }

    // ============ Edge Case Tests ============

    function test_SingleElement_IndexBased() public view {
        bytes32 leaf = keccak256("single");
        bytes32 sibling = keccak256("sibling");

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        bytes32 root = merkle.calculateRoot(proof, 0, leaf);
        bytes32 expectedRoot = keccak256(abi.encode(leaf, sibling));
        assertEq(root, expectedRoot);
    }

    function test_MaxDepth_255() public view {
        bytes32[] memory proof = new bytes32[](255);
        for (uint256 i = 0; i < 255; i++) {
            proof[i] = keccak256(abi.encodePacked("sibling", i));
        }
        bytes32 leaf = keccak256("leaf");

        // Should not revert for max valid length
        bytes32 root = merkle.calculateRoot(proof, 0, leaf);
        assertTrue(root != bytes32(0));
    }

    function test_Fuzz_CalculateRoot(
        bytes32 leaf,
        bytes32 sibling,
        bool isLeftLeaf
    ) public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        uint256 index = isLeftLeaf ? 0 : 1;
        bytes32 root = merkle.calculateRoot(proof, index, leaf);

        bytes32 expectedRoot;
        if (isLeftLeaf) {
            expectedRoot = keccak256(abi.encode(leaf, sibling));
        } else {
            expectedRoot = keccak256(abi.encode(sibling, leaf));
        }

        assertEq(root, expectedRoot);
    }

    function test_Fuzz_SortedVsIndexBased(bytes32 a, bytes32 b) public view {
        // For sorted proofs, the result should be deterministic regardless of input order
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = b;

        bytes32 sortedRoot = merkle.calculateSortedRoot(proof, a);

        bytes32 expectedRoot;
        if (a <= b) {
            expectedRoot = keccak256(abi.encode(a, b));
        } else {
            expectedRoot = keccak256(abi.encode(b, a));
        }

        assertEq(sortedRoot, expectedRoot);
    }
}
