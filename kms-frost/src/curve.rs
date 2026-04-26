//! Curve identifier shared across KMS modules.

use serde::{Deserialize, Serialize};

/// Supported FROST ciphersuites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Curve {
    Secp256k1,
    Ed25519,
}

impl Curve {
    /// Wire name used in CBOR params.
    pub fn as_str(&self) -> &'static str {
        match self {
            Curve::Secp256k1 => "secp256k1",
            Curve::Ed25519 => "ed25519",
        }
    }

    /// Single-byte prefix for storage keys. Ensures same key_id with
    /// different curves maps to different storage entries.
    pub fn storage_prefix(&self) -> u8 {
        match self {
            Curve::Secp256k1 => 0x01,
            Curve::Ed25519 => 0x02,
        }
    }
}

impl Curve {
    /// Map a frost_core Ciphersuite type to its Curve value.
    /// Used in generic code where C is known at compile time.
    pub fn from_ciphersuite<C: frost_core::Ciphersuite>() -> Self {
        // Compare group key serialization size: 33 = secp256k1, 32 = ed25519.
        // This is a compile-time-resolvable dispatch since the Serialization
        // type is fixed per Ciphersuite.
        let id = C::ID;
        if id.starts_with("FROST-secp256k1") {
            Curve::Secp256k1
        } else if id.starts_with("FROST-Ed25519") || id.starts_with("FROST-ED25519") {
            Curve::Ed25519
        } else {
            panic!("unknown ciphersuite ID: {id}");
        }
    }
}

impl std::fmt::Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
