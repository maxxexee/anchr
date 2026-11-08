// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AnchrVault} from "../src/AnchrVault.sol";

contract AnchrVaultTest is Test {
    AnchrVault vault;

    bytes32 constant MERKLE_ROOT = keccak256("merkle root");
    bytes32 constant TOTP_COMMITMENT = keccak256("totp commitment");

    function setUp() public {
        vault = new AnchrVault();
    }

    function sealDocument(address sender) internal returns (bytes32 id) {
        vm.prank(sender);
        id = vault.seal("nda.pdf", "application/pdf", hex"0011223344", MERKLE_ROOT, hex"aabbcc", TOTP_COMMITMENT);
    }

    function testSealStoresDocumentAndCounts() public {
        bytes32 id = sealDocument(address(this));

        assertEq(vault.count(), 1);
        assertEq(vault.getWalletTotpCommitment(address(this)), TOTP_COMMITMENT);

        AnchrVault.Document memory doc = vault.getDocument(id);
        assertEq(doc.name, "nda.pdf");
        assertEq(doc.mimeType, "application/pdf");
        assertEq(doc.merkleRoot, MERKLE_ROOT);
        assertEq(doc.sender, address(this));
        assertEq(doc.size, 5);
        assertFalse(doc.shredded);
        assertEq(doc.seq, 1);

        assertEq(vault.encryptedData(id), hex"0011223344");
        assertEq(vault.wrappedKeys(id), hex"aabbcc");
        assertEq(vault.getTotpCommitment(id), TOTP_COMMITMENT);
    }

    function testSealRejectsEmptyContent() public {
        vm.expectRevert("Empty content");
        vault.seal("empty.pdf", "application/pdf", hex"", MERKLE_ROOT, hex"aabbcc", TOTP_COMMITMENT);
    }

    function testSealRejectsEmptyMerkleRoot() public {
        vm.expectRevert("Empty merkle root");
        vault.seal("nda.pdf", "application/pdf", hex"0011", bytes32(0), hex"aabbcc", TOTP_COMMITMENT);
    }

    function testFetchReturnsEncryptedPayload() public {
        bytes32 id = sealDocument(address(this));

        (string memory name, string memory mimeType, bytes memory content, bytes memory key,) = vault.fetch(id);
        assertEq(name, "nda.pdf");
        assertEq(mimeType, "application/pdf");
        assertEq(content, hex"0011223344");
        assertEq(key, hex"aabbcc");
    }

    function testShredClearsEncryptedData() public {
        bytes32 id = sealDocument(address(this));

        vault.shred(id);

        assertTrue(vault.getDocument(id).shredded);
        assertEq(vault.encryptedData(id).length, 0);
        assertEq(vault.wrappedKeys(id).length, 0);
        assertEq(vault.getTotpCommitment(id), bytes32(0));

        vm.expectRevert("Document was crypto-shredded");
        vault.fetch(id);
    }

    function testShredRejectsSecondCall() public {
        bytes32 id = sealDocument(address(this));
        vault.shred(id);

        vm.expectRevert("Already shredded");
        vault.shred(id);
    }

    function testShredRejectsNonSender() public {
        bytes32 id = sealDocument(address(this));

        vm.prank(address(0xBEEF));
        vm.expectRevert("Only sender can shred");
        vault.shred(id);
    }

    function testDocumentsIndexedBySender() public {
        address owner = address(0xA11CE);
        bytes32 id = sealDocument(owner);

        bytes32[] memory owned = vault.getDocumentsBySender(owner);
        assertEq(owned.length, 1);
        assertEq(owned[0], id);
    }
}
