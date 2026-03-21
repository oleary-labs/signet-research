// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {SchnorrVerifier} from "../contracts/SchnorrVerifier.sol";
import {SignetAccount} from "../contracts/SignetAccount.sol";
import {PackedUserOperation} from "../contracts/interfaces/IAccount.sol";

/// @dev Wrapper to expose the library function for testing.
contract SchnorrVerifierHarness {
    function verify(bytes32 msgHash, bytes memory signature, address signer) external view returns (bool) {
        return SchnorrVerifier.verify(msgHash, signature, signer);
    }
}

contract SchnorrVerifierTest is Test {
    SchnorrVerifierHarness verifier;

    // Test vector generated from LSS 2-of-3 threshold Schnorr signing.
    bytes32 constant MSG_HASH = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant SIGNER = 0xf925118a55dE09bbc8Db68fF8e74845a43107d0b;
    bytes32 constant SIG_RX = 0xebe540f9f6f5e555eab37fd87296c60086d2c8e138c09c1722738599011bd72b;
    bytes32 constant SIG_S = 0x7aebbf3b94d0840bf1c2da9c28bb5a55e71dfc52b044d79e7e22fa5d597ee36c;
    uint8 constant SIG_V = 1;

    function setUp() public {
        verifier = new SchnorrVerifierHarness();
    }

    function _sig() internal pure returns (bytes memory) {
        return abi.encodePacked(SIG_RX, SIG_S, SIG_V);
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

    function testVerifyTamperedS() public view {
        bytes memory sig = abi.encodePacked(SIG_RX, bytes32(uint256(SIG_S) ^ 1), SIG_V);
        assertFalse(verifier.verify(MSG_HASH, sig, SIGNER));
    }

    function testVerifyTamperedRx() public view {
        bytes memory sig = abi.encodePacked(bytes32(uint256(SIG_RX) ^ 1), SIG_S, SIG_V);
        assertFalse(verifier.verify(MSG_HASH, sig, SIGNER));
    }

    function testVerifyFlippedV() public view {
        uint8 wrongV = SIG_V == 0 ? 1 : 0;
        bytes memory sig = abi.encodePacked(SIG_RX, SIG_S, wrongV);
        assertFalse(verifier.verify(MSG_HASH, sig, SIGNER));
    }

    function testVerifyBadLength() public view {
        assertFalse(verifier.verify(MSG_HASH, hex"deadbeef", SIGNER));
        assertFalse(verifier.verify(MSG_HASH, "", SIGNER));
    }

    function testVerifyZeroMsgHash() public view {
        assertFalse(verifier.verify(bytes32(0), _sig(), SIGNER));
    }

    function testGasCost() public {
        uint256 gasBefore = gasleft();
        verifier.verify(MSG_HASH, _sig(), SIGNER);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("Schnorr verify gas", gasUsed);
        // modexp precompile dominates; ~12k gas total.
        assertLt(gasUsed, 15_000);
    }
}

contract SignetAccountTest is Test {
    SignetAccount account;
    address entryPoint;

    bytes32 constant MSG_HASH = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant SIGNER = 0xf925118a55dE09bbc8Db68fF8e74845a43107d0b;
    bytes32 constant SIG_RX = 0xebe540f9f6f5e555eab37fd87296c60086d2c8e138c09c1722738599011bd72b;
    bytes32 constant SIG_S = 0x7aebbf3b94d0840bf1c2da9c28bb5a55e71dfc52b044d79e7e22fa5d597ee36c;
    uint8 constant SIG_V = 1;

    function setUp() public {
        entryPoint = makeAddr("entryPoint");
        account = new SignetAccount(entryPoint, SIGNER);
        vm.deal(address(account), 1 ether);
    }

    function testValidateUserOp_valid() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_S, SIG_V);

        vm.prank(entryPoint);
        uint256 result = account.validateUserOp(userOp, MSG_HASH, 0);
        assertEq(result, 0, "valid signature should return 0");
    }

    function testValidateUserOp_invalid() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_S, uint8(SIG_V ^ 1));

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
        userOp.signature = abi.encodePacked(SIG_RX, SIG_S, SIG_V);
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

    function testExecute_onlyEntryPoint() public {
        vm.expectRevert(SignetAccount.OnlyEntryPoint.selector);
        account.execute(address(0), 0, "");
    }

    function testRotateSigner() public {
        address newSigner = makeAddr("newSigner");

        // rotateSigner must be called by the account itself (via execute).
        vm.prank(entryPoint);
        account.execute(
            address(account),
            0,
            abi.encodeCall(SignetAccount.rotateSigner, (newSigner))
        );
        assertEq(account.signer(), newSigner);
    }

    function testRotateSigner_onlySelf() public {
        vm.expectRevert(SignetAccount.OnlySelf.selector);
        account.rotateSigner(address(0));
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
