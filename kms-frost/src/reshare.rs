//! Reshare protocol cryptographic operations.
//!
//! Implements the Lagrange-weighted Feldman VSS redistribution protocol
//! (3-round) for secp256k1. Uses vsss-rs for polynomial operations and
//! Feldman verification, and k256 for group arithmetic.

use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field as FFField, PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Polynomial + Feldman helpers (wrapping vsss-rs)
// ---------------------------------------------------------------------------

/// A polynomial represented by its coefficients [a_0, a_1, ..., a_{d}].
/// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_d*x^d
#[derive(Clone)]
pub struct Polynomial {
    pub coeffs: Vec<Scalar>,
}

impl Polynomial {
    /// Create a random polynomial with the given constant term and degree.
    pub fn random(constant: Scalar, degree: usize, rng: &mut impl RngCore) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(constant);
        for _ in 0..degree {
            coeffs.push(Scalar::random(&mut *rng));
        }
        Polynomial { coeffs }
    }

    /// Evaluate the polynomial at x using Horner's method.
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut result = *self.coeffs.last().unwrap();
        for coeff in self.coeffs[..self.coeffs.len() - 1].iter().rev() {
            result = result * x + coeff;
        }
        result
    }

    /// Compute Feldman commitments: [a_i * G] for each coefficient.
    pub fn commitments(&self) -> Vec<ProjectivePoint> {
        self.coeffs
            .iter()
            .map(|c| ProjectivePoint::GENERATOR * c)
            .collect()
    }
}

/// Compute the Lagrange coefficient for `self_scalar` among `participants`.
/// λ_i = Π_{j≠i} (x_j / (x_j - x_i))
pub fn lagrange_coefficient(self_scalar: &Scalar, participants: &[Scalar]) -> Scalar {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for xj in participants {
        if xj == self_scalar {
            continue;
        }
        numerator = numerator * xj;
        denominator = denominator * (*xj - self_scalar);
    }
    numerator * denominator.invert().unwrap()
}

/// Verify a sub-share against Feldman commitments.
/// Checks: sub_share * G == Σ_{k=0..d} commitment_k * (party_id^k)
pub fn verify_feldman(
    party_scalar: &Scalar,
    sub_share: &Scalar,
    commitments: &[ProjectivePoint],
) -> bool {
    // LHS: sub_share * G
    let lhs = ProjectivePoint::GENERATOR * sub_share;

    // RHS: Σ commitment_k * party_id^k
    let mut rhs = ProjectivePoint::IDENTITY;
    let mut x_power = Scalar::ONE;
    for commitment in commitments {
        rhs = rhs + commitment * &x_power;
        x_power = x_power * party_scalar;
    }

    lhs == rhs
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a ProjectivePoint to 33-byte compressed SEC1 encoding.
pub fn serialize_point(point: &ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

/// Deserialize a 33-byte compressed SEC1 point.
pub fn deserialize_point(bytes: &[u8]) -> Result<ProjectivePoint, String> {
    if bytes.len() != 33 {
        return Err(format!("point must be 33 bytes, got {}", bytes.len()));
    }
    let encoded = k256::EncodedPoint::from_bytes(bytes)
        .map_err(|e| format!("invalid encoded point: {e}"))?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    match Option::<AffinePoint>::from(affine) {
        Some(p) => Ok(ProjectivePoint::from(p)),
        None => Err("invalid curve point".to_string()),
    }
}

/// Serialize a Scalar to 32 bytes (big-endian).
pub fn serialize_scalar(s: &Scalar) -> Vec<u8> {
    s.to_bytes().to_vec()
}

/// Deserialize a 32-byte big-endian scalar.
pub fn deserialize_scalar(bytes: &[u8]) -> Result<Scalar, String> {
    if bytes.len() != 32 {
        return Err(format!("scalar must be 32 bytes, got {}", bytes.len()));
    }
    let field_bytes: &k256::FieldBytes = bytes.into();
    match Option::<Scalar>::from(Scalar::from_repr(*field_bytes)) {
        Some(s) => Ok(s),
        None => Err("invalid scalar".to_string()),
    }
}

/// Convert a frost Identifier to its underlying scalar.
pub fn identifier_to_scalar(id: &frost_secp256k1::Identifier) -> Result<Scalar, String> {
    let bytes = id.serialize();
    deserialize_scalar(&bytes)
}

/// Combine chain keys: SHA256(sorted chain keys concatenated).
/// Input must be sorted by party_id. Returns (combined_chain_key, rid).
pub fn combine_chain_keys(chain_keys: &[(String, Vec<u8>)]) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha256::new();
    for (_, ck) in chain_keys {
        h.update(ck);
    }
    let combined: [u8; 32] = h.finalize().into();
    let rid: [u8; 32] = Sha256::digest(&combined).into();
    (combined, rid)
}

// ---------------------------------------------------------------------------
// Message payloads (CBOR-encoded, matching Go wire format)
// ---------------------------------------------------------------------------

/// Round 1 broadcast from each old party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareR1Payload {
    /// Feldman commitments (serialized group elements).
    #[serde(rename = "c")]
    pub commitments: Vec<Vec<u8>>,
    /// 32-byte random chain key contribution.
    #[serde(rename = "k")]
    pub chain_key: Vec<u8>,
    /// Current generation from old config.
    #[serde(rename = "g")]
    pub generation: u64,
    /// Group verification key (so new-only parties learn it).
    #[serde(rename = "v")]
    pub group_key: Vec<u8>,
}

/// Round 2 unicast from old party to new party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareR2Payload {
    /// Scalar encoding of f_i(j).
    #[serde(rename = "s")]
    pub sub_share: Vec<u8>,
}

/// Round 3 broadcast from each new party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareR3Payload {
    /// Serialized verifying share (public key share) — 33-byte compressed point.
    #[serde(rename = "p")]
    pub verifying_share: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Reshare parameters
// ---------------------------------------------------------------------------

/// Parameters for starting a reshare session.
#[derive(Debug, Clone, Deserialize)]
pub struct ReshareParams {
    pub group_id: String,
    pub key_id: String,
    pub party_id: String,
    pub old_party_ids: Vec<String>,
    pub new_party_ids: Vec<String>,
    pub new_threshold: u16,
}

/// Decode CBOR bytes into reshare params.
pub fn decode_reshare_params(data: &[u8]) -> Result<ReshareParams, String> {
    ciborium::from_reader(data).map_err(|e| format!("decode reshare params: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_polynomial_evaluate() {
        // f(x) = 5 + 3x (degree 1)
        let five = Scalar::from(5u64);
        let three = Scalar::from(3u64);
        let poly = Polynomial {
            coeffs: vec![five, three],
        };
        let two = Scalar::from(2u64);
        let result = poly.evaluate(&two);
        // f(2) = 5 + 3*2 = 11
        assert_eq!(result, Scalar::from(11u64));
    }

    #[test]
    fn test_feldman_commitment_verification() {
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let poly = Polynomial::random(secret, 2, &mut rng);
        let commitments = poly.commitments();

        let party_id = Scalar::from(3u64);
        let sub_share = poly.evaluate(&party_id);

        assert!(verify_feldman(&party_id, &sub_share, &commitments));

        // Tamper with sub_share — should fail.
        let bad_share = sub_share + Scalar::ONE;
        assert!(!verify_feldman(&party_id, &bad_share, &commitments));
    }

    #[test]
    fn test_lagrange_coefficient() {
        // With parties [1, 2, 3], sum of Lagrange coefficients should be 1.
        let ids: Vec<Scalar> = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
        ];
        let l1 = lagrange_coefficient(&ids[0], &ids);
        let l2 = lagrange_coefficient(&ids[1], &ids);
        let l3 = lagrange_coefficient(&ids[2], &ids);

        let sum = l1 + l2 + l3;
        assert_eq!(sum, Scalar::ONE);
    }

    #[test]
    fn test_lagrange_secret_reconstruction() {
        // Create a 2-of-3 sharing and verify reconstruction.
        let mut rng = thread_rng();
        let secret = Scalar::random(&mut rng);
        let poly = Polynomial::random(secret, 1, &mut rng); // degree 1 = threshold 2

        let ids = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let shares: Vec<Scalar> = ids.iter().map(|id| poly.evaluate(id)).collect();

        // Reconstruct from any 2 shares.
        let subset = &ids[0..2];
        let mut reconstructed = Scalar::ZERO;
        for (i, id) in subset.iter().enumerate() {
            let lambda = lagrange_coefficient(id, subset);
            reconstructed = reconstructed + shares[i] * lambda;
        }
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_point_serialization_roundtrip() {
        let scalar = Scalar::from(42u64);
        let point = ProjectivePoint::GENERATOR * &scalar;
        let bytes = serialize_point(&point);
        assert_eq!(bytes.len(), 33);
        let recovered = deserialize_point(&bytes).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_scalar_serialization_roundtrip() {
        let scalar = Scalar::from(123456789u64);
        let bytes = serialize_scalar(&scalar);
        assert_eq!(bytes.len(), 32);
        let recovered = deserialize_scalar(&bytes).unwrap();
        assert_eq!(scalar, recovered);
    }
}
