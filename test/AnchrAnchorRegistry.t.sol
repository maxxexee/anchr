// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AnchrAnchorRegistry} from "../src/AnchrAnchorRegistry.sol";

contract AnchrAnchorRegistryTest is Test {
    AnchrAnchorRegistry registry;

    event RootAnchored(uint256 indexed seq, bytes32 indexed root, address indexed sender, uint256 timestamp);

    function setUp() public {
        registry = new AnchrAnchorRegistry();
    }

    function testAnchorStoresRootWithSequentialIds() public {
        bytes32 first = keccak256("first");
        bytes32 second = keccak256("second");

        uint256 firstSeq = registry.anchor(first);
        uint256 secondSeq = registry.anchor(second);

        assertEq(firstSeq, 1);
        assertEq(secondSeq, 2);
        assertEq(registry.count(), 2);

        (bytes32 root, address sender, uint256 timestamp, uint256 seq) = registry.anchors(first);
        assertEq(root, first);
        assertEq(sender, address(this));
        assertEq(timestamp, block.timestamp);
        assertEq(seq, 1);
    }

    function testAnchorEmitsEvent() public {
        bytes32 root = keccak256("document");
        vm.expectEmit(true, true, true, true);
        emit RootAnchored(1, root, address(this), block.timestamp);
        registry.anchor(root);
    }

    function testAnchorRejectsEmptyRoot() public {
        vm.expectRevert("Empty root");
        registry.anchor(bytes32(0));
    }

    function testAnchorRejectsDuplicateRoot() public {
        bytes32 root = keccak256("duplicate");
        registry.anchor(root);

        vm.expectRevert("Root already anchored");
        registry.anchor(root);
    }

    function testVerifyReportsUnknownRootAsMissing() public view {
        (bool exists, AnchrAnchorRegistry.Anchor memory entry) = registry.verify(keccak256("never anchored"));
        assertFalse(exists);
        assertEq(entry.root, bytes32(0));
        assertEq(entry.timestamp, 0);
    }

    function testVerifyReportsAnchoredRoot() public {
        bytes32 root = keccak256("anchored");
        registry.anchor(root);

        (bool exists, AnchrAnchorRegistry.Anchor memory entry) = registry.verify(root);
        assertTrue(exists);
        assertEq(entry.root, root);
        assertEq(entry.sender, address(this));
    }

    function testAnchoredRootsRecordedInOrder() public {
        bytes32 first = keccak256("a");
        bytes32 second = keccak256("b");
        registry.anchor(first);
        registry.anchor(second);

        assertEq(registry.anchoredRoots(0), first);
        assertEq(registry.anchoredRoots(1), second);
    }
}
