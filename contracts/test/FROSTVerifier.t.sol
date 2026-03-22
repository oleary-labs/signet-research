// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {FROSTVerifier} from "../contracts/FROSTVerifier.sol";
import {SignetAccount} from "../contracts/SignetAccount.sol";
import {PackedUserOperation} from "../contracts/interfaces/IAccount.sol";

/// @dev Wrapper to expose the library function for testing.
contract FROSTVerifierHarness {
    function verify(bytes32 msgHash, bytes memory signature, address signer) external view returns (bool) {
        return FROSTVerifier.verify(msgHash, signature, signer);
    }
}

contract FROSTVerifierTest is Test {
    FROSTVerifierHarness verifier;

    // Test vector generated from FROST 2-of-3 threshold Schnorr signing (tss package).
    // Produced by cmd/testvector with parties ["alice","bob","carol"], threshold=2,
    // signers=["alice","bob"], msgHash=0x0102...1f20.
    bytes32 constant MSG_HASH = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant SIGNER = 0x61C17C5Be88fa04d59464e49999DbA73f94771f6;
    bytes32 constant SIG_RX = 0x1ad760891f617cd8f0b8185f2ffaf09270bacd83a0bbad19fefcddef901bdfce;
    bytes32 constant SIG_Z = 0xf9c96d5b895e5c3a0502cd70b817240425b843689d8f45ceaf8e7e87a2fafe65;
    uint8 constant SIG_V = 0;

    function setUp() public {
        verifier = new FROSTVerifierHarness();
    }

    function _sig() internal pure returns (bytes memory) {
        return abi.encodePacked(SIG_RX, SIG_Z, SIG_V);
    }

    function testVerifyValid() public view {
        assertTrue(verifier.verify(MSG_HASH, _sig(), SIGNER));
    }

    function testVerifyWrongSigner() public view {
        assertFalse(verifier.verify(MSG_HASH, _sig(), address(0xdead)));
    }

    function testVerifyWrongMessage() public view {
        assertFalse(verifier.verify(bytes32(uint256(1)), _sig(), SIGNER));
    }

    function testVerifyTamperedZ() public view {
        bytes memory sig = abi.encodePacked(SIG_RX, bytes32(uint256(SIG_Z) ^ 1), SIG_V);
        assertFalse(verifier.verify(MSG_HASH, sig, SIGNER));
    }

    function testVerifyTamperedRx() public view {
        bytes memory sig = abi.encodePacked(bytes32(uint256(SIG_RX) ^ 1), SIG_Z, SIG_V);
        assertFalse(verifier.verify(MSG_HASH, sig, SIGNER));
    }

    function testVerifyFlippedV() public view {
        uint8 wrongV = SIG_V == 0 ? 1 : 0;
        bytes memory sig = abi.encodePacked(SIG_RX, SIG_Z, wrongV);
        assertFalse(verifier.verify(MSG_HASH, sig, SIGNER));
    }

    function testVerifyBadLength() public view {
        assertFalse(verifier.verify(MSG_HASH, hex"deadbeef", SIGNER));
        assertFalse(verifier.verify(MSG_HASH, "", SIGNER));
    }

    function testVerifyZeroSigner() public view {
        assertFalse(verifier.verify(MSG_HASH, _sig(), address(0)));
    }

    function testGasCost() public {
        uint256 gasBefore = gasleft();
        verifier.verify(MSG_HASH, _sig(), SIGNER);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("FROST verify gas", gasUsed);
        // modexp precompile dominates; ~12-14k gas total.
        assertLt(gasUsed, 16_000);
    }
}

contract SignetAccountFROSTTest is Test {
    SignetAccount account;
    address entryPoint;

    bytes32 constant MSG_HASH = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant SIGNER = 0x61C17C5Be88fa04d59464e49999DbA73f94771f6;
    bytes32 constant SIG_RX = 0x1ad760891f617cd8f0b8185f2ffaf09270bacd83a0bbad19fefcddef901bdfce;
    bytes32 constant SIG_Z = 0xf9c96d5b895e5c3a0502cd70b817240425b843689d8f45ceaf8e7e87a2fafe65;
    uint8 constant SIG_V = 0;

    function setUp() public {
        entryPoint = makeAddr("entryPoint");
        account = new SignetAccount(entryPoint, SIGNER);
        vm.deal(address(account), 1 ether);
    }

    function testValidateUserOp_valid() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_Z, SIG_V);

        vm.prank(entryPoint);
        uint256 result = account.validateUserOp(userOp, MSG_HASH, 0);
        assertEq(result, 0, "valid signature should return 0");
    }

    function testValidateUserOp_invalid() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_Z, uint8(SIG_V ^ 1));

        vm.prank(entryPoint);
        uint256 result = account.validateUserOp(userOp, MSG_HASH, 0);
        assertEq(result, 1, "invalid signature should return 1");
    }

    function testValidateUserOp_onlyEntryPoint() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        vm.expectRevert(SignetAccount.OnlyEntryPoint.selector);
        account.validateUserOp(userOp, MSG_HASH, 0);
    }

    function testValidateUserOp_paysPrefund() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_Z, SIG_V);
        uint256 prefund = 0.01 ether;

        uint256 epBalBefore = entryPoint.balance;
        vm.prank(entryPoint);
        account.validateUserOp(userOp, MSG_HASH, prefund);
        assertEq(entryPoint.balance - epBalBefore, prefund);
    }

    function testExecute() public {
        address target = makeAddr("target");
        vm.deal(address(account), 1 ether);

        vm.prank(entryPoint);
        account.execute(target, 0.1 ether, "");
        assertEq(target.balance, 0.1 ether);
    }

    function testRotateSigner() public {
        address newSigner = makeAddr("newSigner");

        vm.prank(entryPoint);
        account.execute(
            address(account),
            0,
            abi.encodeCall(SignetAccount.rotateSigner, (newSigner))
        );
        assertEq(account.signer(), newSigner);
    }

    function _dummyUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }
}
