// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title SchnorrVerifier
/// @notice Verifies threshold Schnorr signatures on secp256k1 using the ecrecover precompile.
///
/// The LSS threshold signing protocol produces Schnorr signatures of the form:
///   s·G = R + e·P   where e = R.x · msgHash
///
/// Rather than performing EC point arithmetic directly (which secp256k1 lacks precompiles for),
/// we rearrange the equation and use ecrecover to verify:
///   P = (s/e)·G - (1/e)·R
///
/// By choosing ecrecover parameters:
///   r_ec = R.x,  s_ec = -msgHash⁻¹ mod n,  hash_ec = -(s · msgHash⁻¹) mod n
///
/// ecrecover returns address(P) if and only if the Schnorr equation holds.
///
/// Gas cost: ~12,200 (ecrecover: 3000 + modexp precompile: ~8500 + overhead: ~700)
///
/// @dev Designed as a library for use in ERC-4337 account contracts.
/// The signature format is 65 bytes: R.x(32) || s(32) || v(1), matching the
/// wire format produced by lss.Signature.SigEthereum().
library SchnorrVerifier {
    /// @dev secp256k1 curve order.
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Verify a Schnorr signature against an expected signer address.
    /// @param msgHash The 32-byte message hash that was signed.
    /// @param signature 65-byte signature: R.x(32) || s(32) || v(1).
    /// @param signer Expected signer address (keccak of the group public key).
    /// @return True if the signature is valid for the given signer.
    function verify(bytes32 msgHash, bytes memory signature, address signer) internal view returns (bool) {
        if (signature.length != 65) return false;

        uint256 rx;
        uint256 s;
        uint8 v;
        assembly {
            rx := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // Reject degenerate inputs.
        if (rx == 0 || rx >= N) return false;
        if (s == 0 || s >= N) return false;
        if (uint256(msgHash) == 0) return false;

        // Challenge: e = rx * msgHash mod N. Must be nonzero.
        uint256 e = mulmod(rx, uint256(msgHash), N);
        if (e == 0) return false;

        // Compute msgHash⁻¹ mod N via modexp precompile (Fermat's little theorem).
        uint256 mInv = _modInverse(uint256(msgHash));

        // ecrecover parameters derived from Schnorr equation:
        //   s_ec    = -(msgHash⁻¹)     mod N
        //   hash_ec = -(s · msgHash⁻¹)  mod N
        uint256 sEc = N - mInv;
        uint256 hashEc = N - mulmod(s, mInv, N);

        // v for ecrecover: 27 + R.y parity (0 or 1).
        address recovered = ecrecover(bytes32(hashEc), v + 27, bytes32(rx), bytes32(sEc));

        return recovered == signer && recovered != address(0);
    }

    /// @notice Compute a⁻¹ mod N using the modexp precompile (address 0x05).
    /// @dev Uses Fermat's little theorem: a⁻¹ = a^(N-2) mod N.
    function _modInverse(uint256 a) private view returns (uint256 result) {
        // modexp precompile input: base_len(32) || exp_len(32) || mod_len(32) || base || exp || mod
        bytes memory input = abi.encodePacked(
            uint256(32), // base length
            uint256(32), // exponent length
            uint256(32), // modulus length
            a, // base
            N - 2, // exponent (Fermat)
            N // modulus
        );
        (bool ok, bytes memory output) = address(0x05).staticcall(input);
        require(ok && output.length >= 32, "SchnorrVerifier: modexp failed");
        assembly {
            result := mload(add(output, 32))
        }
    }
}
