// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IAccount, PackedUserOperation} from "./interfaces/IAccount.sol";
import {FROSTVerifier} from "./FROSTVerifier.sol";

/// @title SignetAccount
/// @notice ERC-4337 smart account that validates operations using FROST threshold Schnorr
/// signatures. The account's signer is the group public key, represented as an Ethereum address.
///
/// Usage with ERC-4337:
/// 1. Deploy via factory with entryPoint and signer address
/// 2. The FROST signing group produces a Schnorr signature on the userOpHash
/// 3. The signature (65 bytes: R.x || z || v) is placed in userOp.signature
/// 4. EntryPoint calls validateUserOp, which verifies via ecrecover trick
///
/// @dev This is a minimal reference implementation. Production accounts should add:
/// - Execute/batch-execute functions
/// - Signer rotation (via LSS reshare — same public key, new shares)
/// - Fallback/receive handlers
/// - ERC-1271 isValidSignature support
contract SignetAccount is IAccount {
    /// @dev ERC-4337 signature validation failed sentinel.
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @notice The ERC-4337 EntryPoint that may call validateUserOp.
    address public immutable entryPoint;

    /// @notice The signer address: keccak256(uncompressed group public key)[12:].
    /// Updated via signer rotation (not by reshare — reshare preserves the same key).
    address public signer;

    error OnlyEntryPoint();
    error OnlySelf();

    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint) revert OnlyEntryPoint();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    constructor(address _entryPoint, address _signer) {
        entryPoint = _entryPoint;
        signer = _signer;
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /// @notice Execute a call. Only callable by EntryPoint or the account itself.
    function execute(address dest, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool ok, bytes memory result) = dest.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @notice Rotate the signer. Only callable by the account itself (via execute).
    function rotateSigner(address newSigner) external onlySelf {
        signer = newSigner;
    }

    /// @dev Validate the FROST Schnorr signature in the user operation.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        if (FROSTVerifier.verify(userOpHash, userOp.signature, signer)) {
            return 0;
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @dev Pay the EntryPoint the required prefund.
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok); // ignore failure (EntryPoint will catch it)
        }
    }

    receive() external payable {}
}
