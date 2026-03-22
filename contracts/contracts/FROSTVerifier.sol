// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title FROSTVerifier
/// @notice Verifies FROST threshold Schnorr signatures on secp256k1 using the ecrecover precompile.
///
/// The FROST signing protocol (RFC 9591) produces signatures of the form:
///   z·G = R + c·Y   where c = keccak256(R_x || v || address(Y) || msgHash) mod N
///
/// Rather than performing EC point arithmetic directly, we rearrange and use ecrecover:
///   ecrecover(hash_ec, v_R+27, rx, s_ec) = address(Y)
///
/// where:
///   s_ec    = -rx · c⁻¹ mod N
///   hash_ec = -rx · z · c⁻¹ mod N
///
/// Derivation: (1/rx)·(s_ec·R - hash_ec·G)
///           = (1/rx)·(-rx·c⁻¹·R + rx·z·c⁻¹·G)
///           = c⁻¹·(z·G - R)
///           = c⁻¹·c·Y = Y  ✓
///
/// Gas cost: ~12,200 (ecrecover: 3000 + modexp: ~8500 + overhead: ~700)
///
/// @dev Designed as a library for use in ERC-4337 account contracts.
/// The signature format is 65 bytes: R.x(32) || z(32) || v(1), matching the
/// wire format produced by tss.Signature.SigEthereum().
library FROSTVerifier {
    /// @dev secp256k1 curve order.
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Verify a FROST threshold Schnorr signature against an expected signer address.
    /// @param msgHash The 32-byte message hash that was signed.
    /// @param signature 65-byte signature: R.x(32) || z(32) || v(1).
    ///        v is the R.y parity: 0 = even, 1 = odd.
    /// @param signer Expected signer address: keccak256(uncompressed group public key Y)[12:].
    /// @return True if the signature is valid for the given signer.
    function verify(bytes32 msgHash, bytes memory signature, address signer) internal view returns (bool) {
        if (signature.length != 65) return false;

        uint256 rx;
        uint256 z;
        uint8 v;
        assembly {
            rx := mload(add(signature, 32))
            z  := mload(add(signature, 64))
            v  := byte(0, mload(add(signature, 96)))
        }

        // Reject degenerate inputs.
        if (rx == 0 || rx >= N) return false;
        if (z == 0 || z >= N) return false;
        if (signer == address(0)) return false;

        // FROST challenge: c = keccak256(R_x || v || address(Y) || msgHash) mod N
        // Matches computeChallenge() in tss/sign.go: R_x(32) || v(1) || signerAddr(20) || msgHash(32)
        uint256 c = uint256(keccak256(abi.encodePacked(rx, v, signer, msgHash))) % N;
        if (c == 0) return false;

        // c_inv = c^(N-2) mod N  (Fermat's little theorem)
        uint256 cInv = _modInverse(c);

        // ecrecover parameters derived from FROST equation z·G = R + c·Y:
        //   s_ec    = -rx · c_inv        mod N
        //   hash_ec = -rx · z · c_inv    mod N
        uint256 sEc    = N - mulmod(rx, cInv, N);
        uint256 hashEc = N - mulmod(mulmod(rx, z, N), cInv, N);

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
            a,           // base
            N - 2,       // exponent (Fermat)
            N            // modulus
        );
        (bool ok, bytes memory output) = address(0x05).staticcall(input);
        require(ok && output.length >= 32, "FROSTVerifier: modexp failed");
        assembly {
            result := mload(add(output, 32))
        }
    }
}
