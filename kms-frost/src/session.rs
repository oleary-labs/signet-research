//! Session state machine for FROST keygen and signing.
//!
//! Each session drives the ZF FROST round loop. The gRPC layer feeds incoming
//! peer messages and collects outgoing messages to forward.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use frost::keys::dkg;
use frost::{Identifier, round1, round2};
use rand::rngs::ThreadRng;

use crate::params::{KeygenParams, SignParams};
use crate::storage::{Storage, StoredKey};

/// A message the KMS wants to send to a peer (or broadcast).
pub struct OutgoingMessage {
    pub session_id: String,
    pub from: String,
    pub to: String, // empty = broadcast
    pub payload: Vec<u8>,
}

/// The result of a completed session.
pub struct SessionResult {
    pub group_key: Option<Vec<u8>>,
    pub verifying_share: Option<Vec<u8>>,
    pub signature_r: Option<Vec<u8>>,
    pub signature_z: Option<Vec<u8>>,
}

/// Output from processing a message or starting a session.
pub struct StepOutput {
    pub messages: Vec<OutgoingMessage>,
    pub result: Option<SessionResult>,
}

/// Maps string PartyIDs to frost Identifiers.
pub(crate) struct PartyMap {
    to_frost: BTreeMap<String, Identifier>,
    from_frost: BTreeMap<Identifier, String>,
}

impl PartyMap {
    fn new(party_ids: &[String]) -> Result<Self, String> {
        let mut to_frost = BTreeMap::new();
        let mut from_frost = BTreeMap::new();
        for pid in party_ids {
            let id = Identifier::derive(pid.as_bytes())
                .map_err(|e| format!("derive identifier for {pid}: {e}"))?;
            to_frost.insert(pid.clone(), id);
            from_frost.insert(id, pid.clone());
        }
        Ok(PartyMap { to_frost, from_frost })
    }

    fn frost_id(&self, party_id: &str) -> Result<Identifier, String> {
        self.to_frost
            .get(party_id)
            .copied()
            .ok_or_else(|| format!("unknown party: {party_id}"))
    }

    fn party_id(&self, frost_id: &Identifier) -> Result<&str, String> {
        self.from_frost
            .get(frost_id)
            .map(|s| s.as_str())
            .ok_or_else(|| "unknown frost id".to_string())
    }

    fn len(&self) -> usize {
        self.to_frost.len()
    }
}

// ---------------------------------------------------------------------------
// Session enum
// ---------------------------------------------------------------------------

pub enum Session {
    /// DKG round 1: collecting part1 packages from all parties.
    KeygenR1 {
        session_id: String,
        params: KeygenParams,
        pmap: PartyMap,
        self_id: Identifier,
        secret: dkg::round1::SecretPackage,
        packages: BTreeMap<Identifier, dkg::round1::Package>,
    },
    /// DKG round 2: collecting part2 packages from all peers.
    KeygenR2 {
        session_id: String,
        params: KeygenParams,
        pmap: PartyMap,
        #[allow(dead_code)]
        self_id: Identifier,
        secret: dkg::round2::SecretPackage,
        r1_packages: BTreeMap<Identifier, dkg::round1::Package>,
        r2_packages: BTreeMap<Identifier, dkg::round2::Package>,
    },
    /// Sign round 1: collecting commitments from all signers.
    SignR1 {
        session_id: String,
        params: SignParams,
        pmap: PartyMap,
        self_id: Identifier,
        key_package: frost::keys::KeyPackage,
        pub_key_package: frost::keys::PublicKeyPackage,
        nonces: round1::SigningNonces,
        commitments: BTreeMap<Identifier, round1::SigningCommitments>,
    },
    /// Sign round 2: collecting signature shares from all signers.
    SignR2 {
        #[allow(dead_code)]
        session_id: String,
        pmap: PartyMap,
        pub_key_package: frost::keys::PublicKeyPackage,
        signing_package: frost::SigningPackage,
        shares: BTreeMap<Identifier, round2::SignatureShare>,
    },
    Completed,
}

impl Session {
    /// Create and start a keygen session. Returns the session and initial outgoing messages.
    pub fn start_keygen(
        session_id: &str,
        params: KeygenParams,
    ) -> Result<(Self, StepOutput), String> {
        let pmap = PartyMap::new(&params.party_ids)?;
        let self_id = pmap.frost_id(&params.party_id)?;
        let max_signers = params.party_ids.len() as u16;
        let min_signers = params.threshold;

        let mut rng: ThreadRng = rand::thread_rng();
        let (secret, package) = dkg::part1(self_id, max_signers, min_signers, &mut rng)
            .map_err(|e| format!("dkg part1: {e}"))?;

        let payload = package.serialize().map_err(|e| format!("serialize dkg package: {e}"))?;

        let out = OutgoingMessage {
            session_id: session_id.to_string(),
            from: params.party_id.clone(),
            to: String::new(),
            payload,
        };

        let mut packages = BTreeMap::new();
        packages.insert(self_id, package);

        Ok((
            Session::KeygenR1 {
                session_id: session_id.to_string(),
                params,
                pmap,
                self_id,
                secret,
                packages,
            },
            StepOutput {
                messages: vec![out],
                result: None,
            },
        ))
    }

    /// Create and start a signing session.
    pub fn start_sign(
        session_id: &str,
        params: SignParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let pmap = PartyMap::new(&params.signer_ids)?;
        let self_id = pmap.frost_id(&params.party_id)?;

        let stored = storage
            .get_key(&params.group_id, &params.key_id)?
            .ok_or_else(|| {
                format!(
                    "key not found: group={} key={}",
                    params.group_id, params.key_id
                )
            })?;

        let key_package = frost::keys::KeyPackage::deserialize(&stored.key_package)
            .map_err(|e| format!("deserialize key package: {e}"))?;
        let pub_key_package =
            frost::keys::PublicKeyPackage::deserialize(&stored.public_key_package)
                .map_err(|e| format!("deserialize public key package: {e}"))?;

        let mut rng: ThreadRng = rand::thread_rng();
        let (nonces, my_commitments) = round1::commit(key_package.signing_share(), &mut rng);

        let payload = my_commitments
            .serialize()
            .map_err(|e| format!("serialize commitments: {e}"))?;

        let out = OutgoingMessage {
            session_id: session_id.to_string(),
            from: params.party_id.clone(),
            to: String::new(),
            payload,
        };

        let mut commitments = BTreeMap::new();
        commitments.insert(self_id, my_commitments);

        Ok((
            Session::SignR1 {
                session_id: session_id.to_string(),
                params,
                pmap,
                self_id,
                key_package,
                pub_key_package,
                nonces,
                commitments,
            },
            StepOutput {
                messages: vec![out],
                result: None,
            },
        ))
    }

    /// Feed an incoming peer message. Returns outgoing messages and possibly a result.
    /// When a result is returned, the session transitions to Completed.
    pub fn process_message(
        &mut self,
        from: &str,
        _to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        // Take ownership of current state, replacing with Completed temporarily.
        let state = std::mem::replace(self, Session::Completed);

        let (new_state, output) = match state {
            Session::KeygenR1 {
                session_id,
                params,
                pmap,
                self_id,
                secret,
                mut packages,
            } => {
                let from_id = pmap.frost_id(from)?;
                let pkg = dkg::round1::Package::deserialize(payload)
                    .map_err(|e| format!("deserialize r1 package from {from}: {e}"))?;
                packages.insert(from_id, pkg);

                if packages.len() < pmap.len() {
                    (
                        Session::KeygenR1 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret,
                            packages,
                        },
                        StepOutput {
                            messages: vec![],
                            result: None,
                        },
                    )
                } else {
                    // All round1 packages received. Run part2.
                    let (r2_secret, r2_packages) = dkg::part2(secret, &packages)
                        .map_err(|e| format!("dkg part2: {e}"))?;

                    let mut messages = Vec::new();
                    for (target_id, pkg) in &r2_packages {
                        if *target_id == self_id {
                            continue;
                        }
                        let to_party = pmap.party_id(target_id)?;
                        let payload = pkg
                            .serialize()
                            .map_err(|e| format!("serialize r2 package: {e}"))?;
                        messages.push(OutgoingMessage {
                            session_id: session_id.clone(),
                            from: params.party_id.clone(),
                            to: to_party.to_string(),
                            payload,
                        });
                    }

                    (
                        Session::KeygenR2 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret: r2_secret,
                            r1_packages: packages,
                            r2_packages: BTreeMap::new(),
                        },
                        StepOutput {
                            messages,
                            result: None,
                        },
                    )
                }
            }

            Session::KeygenR2 {
                session_id,
                params,
                pmap,
                self_id,
                secret,
                r1_packages,
                mut r2_packages,
            } => {
                let from_id = pmap.frost_id(from)?;
                let pkg = dkg::round2::Package::deserialize(payload)
                    .map_err(|e| format!("deserialize r2 package from {from}: {e}"))?;
                r2_packages.insert(from_id, pkg);

                // Need N-1 round2 packages (from all peers, not self).
                if r2_packages.len() < pmap.len() - 1 {
                    (
                        Session::KeygenR2 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret,
                            r1_packages,
                            r2_packages,
                        },
                        StepOutput {
                            messages: vec![],
                            result: None,
                        },
                    )
                } else {
                    // Finalize DKG.
                    let (key_package, pub_key_package) =
                        dkg::part3(&secret, &r1_packages, &r2_packages)
                            .map_err(|e| format!("dkg part3: {e}"))?;

                    let group_key = pub_key_package
                        .verifying_key()
                        .serialize()
                        .map_err(|e| format!("serialize group key: {e}"))?;
                    let verifying_share = key_package
                        .verifying_share()
                        .serialize()
                        .map_err(|e| format!("serialize verifying share: {e}"))?;

                    // Persist to sled.
                    let stored = StoredKey {
                        key_package: key_package
                            .serialize()
                            .map_err(|e| format!("serialize key package: {e}"))?,
                        public_key_package: pub_key_package
                            .serialize()
                            .map_err(|e| format!("serialize pub key package: {e}"))?,
                        group_key: group_key.clone(),
                        verifying_share: verifying_share.clone(),
                        generation: 0,
                    };
                    storage.put_key(&params.group_id, &params.key_id, &stored)?;

                    (
                        Session::Completed,
                        StepOutput {
                            messages: vec![],
                            result: Some(SessionResult {
                                group_key: Some(group_key),
                                verifying_share: Some(verifying_share),
                                signature_r: None,
                                signature_z: None,
                            }),
                        },
                    )
                }
            }

            Session::SignR1 {
                session_id,
                params,
                pmap,
                self_id,
                key_package,
                pub_key_package,
                nonces,
                mut commitments,
            } => {
                let from_id = pmap.frost_id(from)?;
                let c = round1::SigningCommitments::deserialize(payload)
                    .map_err(|e| format!("deserialize commitments from {from}: {e}"))?;
                commitments.insert(from_id, c);

                if commitments.len() < pmap.len() {
                    (
                        Session::SignR1 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            key_package,
                            pub_key_package,
                            nonces,
                            commitments,
                        },
                        StepOutput {
                            messages: vec![],
                            result: None,
                        },
                    )
                } else {
                    // All commitments received. Build signing package and sign.
                    let signing_package =
                        frost::SigningPackage::new(commitments, &params.message);

                    let sig_share =
                        round2::sign(&signing_package, &nonces, &key_package)
                            .map_err(|e| format!("round2 sign: {e}"))?;

                    // SignatureShare::serialize() returns Vec<u8> directly.
                    let payload = sig_share.serialize();

                    let out = OutgoingMessage {
                        session_id: session_id.clone(),
                        from: params.party_id.clone(),
                        to: String::new(),
                        payload,
                    };

                    let mut shares = BTreeMap::new();
                    shares.insert(self_id, sig_share);

                    (
                        Session::SignR2 {
                            session_id,
                            pmap,
                            pub_key_package,
                            signing_package,
                            shares,
                        },
                        StepOutput {
                            messages: vec![out],
                            result: None,
                        },
                    )
                }
            }

            Session::SignR2 {
                session_id,
                pmap,
                pub_key_package,
                signing_package,
                mut shares,
            } => {
                let from_id = pmap.frost_id(from)?;
                let share = round2::SignatureShare::deserialize(payload)
                    .map_err(|e| format!("deserialize sig share from {from}: {e}"))?;
                shares.insert(from_id, share);

                if shares.len() < pmap.len() {
                    (
                        Session::SignR2 {
                            session_id,
                            pmap,
                            pub_key_package,
                            signing_package,
                            shares,
                        },
                        StepOutput {
                            messages: vec![],
                            result: None,
                        },
                    )
                } else {
                    // Aggregate signatures.
                    let sig = frost::aggregate(
                        &signing_package,
                        &shares,
                        &pub_key_package,
                    )
                    .map_err(|e| format!("aggregate: {e}"))?;

                    let sig_bytes = sig
                        .serialize()
                        .map_err(|e| format!("serialize signature: {e}"))?;

                    // frost-secp256k1 Signature serialization: R (33 bytes) || z (32 bytes)
                    if sig_bytes.len() != 65 {
                        return Err(format!(
                            "unexpected signature length: {} (expected 65)",
                            sig_bytes.len()
                        ));
                    }

                    (
                        Session::Completed,
                        StepOutput {
                            messages: vec![],
                            result: Some(SessionResult {
                                group_key: None,
                                verifying_share: None,
                                signature_r: Some(sig_bytes[..33].to_vec()),
                                signature_z: Some(sig_bytes[33..].to_vec()),
                            }),
                        },
                    )
                }
            }

            Session::Completed => {
                return Err("session already completed".into());
            }
        };

        *self = new_state;
        Ok(output)
    }
}
