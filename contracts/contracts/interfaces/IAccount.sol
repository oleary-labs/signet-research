// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title PackedUserOperation
/// @notice ERC-4337 v0.7 packed user operation struct.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @title IAccount
/// @notice Minimal ERC-4337 account interface (ERC-7562 compatible).
interface IAccount {
    /// @notice Validate a user operation.
    /// @param userOp The packed user operation.
    /// @param userOpHash Hash of the user operation (signed by the account).
    /// @param missingAccountFunds Funds the account must deposit to pay for the operation.
    /// @return validationData 0 for success, 1 for signature failure, or packed
    ///         (sigFailed || validUntil || validAfter) for time-range validation.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}
