//! Session state machine for FROST keygen and signing.
//!
//! Each session drives the ZF FROST round loop. The gRPC layer feeds incoming
//! peer messages and collects outgoing messages to forward.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use frost::keys::dkg;
use frost::{Identifier, round1, round2};
use rand::rngs::ThreadRng;
use rand::RngCore;
use tracing::debug;

use crate::params::{KeygenParams, SignParams};
use crate::reshare::{
    self, decode_reshare_params, Polynomial, ReshareParams, ReshareR1Payload, ReshareR2Payload,
    ReshareR3Payload,
};
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

/// Distinguishes errors that may resolve on retry (wrong round) from errors
/// that will never succeed (unknown sender, completed session, corrupted data
/// from a permanently invalid source).
enum ProcessError {
    /// Message arrived in the wrong round — buffer and retry after the next
    /// state transition.
    WrongRound(String),
    /// Permanently invalid — drop the message.
    Invalid(String),
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

/// CBOR-encode a serializable value.
fn cbor_encode<T: serde::Serialize>(val: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).map_err(|e| format!("cbor encode: {e}"))?;
    Ok(buf)
}

/// CBOR-decode a deserializable value.
fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, String> {
    ciborium::from_reader(data).map_err(|e| format!("cbor decode: {e}"))
}

// ---------------------------------------------------------------------------
// Session — wraps the inner state with a pending message buffer
// ---------------------------------------------------------------------------

/// A buffered (from, to, payload) triple for messages that arrived before
/// the session was ready to process them (e.g. a round-2 unicast arriving
/// while still in round 1). They are replayed after each state transition.
type PendingMsg = (String, String, Vec<u8>);

/// Session wraps the inner round state and handles out-of-order messages by
/// buffering them and replaying after transitions, mirroring the Go tss.Run
/// pending-message pattern.
pub struct Session {
    inner: SessionInner,
    pending: Vec<PendingMsg>,
}

impl Session {
    fn new(inner: SessionInner) -> Self {
        Session { inner, pending: vec![] }
    }

    /// Current round/state name (e.g. "KeygenR1", "Completed").
    pub fn state_name(&self) -> &'static str {
        self.inner.state_name()
    }

    /// Number of messages buffered for later replay.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Create and start a keygen session.
    pub fn start_keygen(
        session_id: &str,
        params: KeygenParams,
    ) -> Result<(Self, StepOutput), String> {
        let (inner, output) = SessionInner::start_keygen(session_id, params)?;
        debug!(state = inner.state_name(), "keygen session started");
        Ok((Session::new(inner), output))
    }

    /// Create and start a signing session.
    pub fn start_sign(
        session_id: &str,
        params: SignParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let (inner, output) = SessionInner::start_sign(session_id, params, storage)?;
        debug!(state = inner.state_name(), "sign session started");
        Ok((Session::new(inner), output))
    }

    /// Create and start a reshare session.
    pub fn start_reshare(
        session_id: &str,
        params: ReshareParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let (inner, output) = SessionInner::start_reshare(session_id, params, storage)?;
        debug!(state = inner.state_name(), "reshare session started");
        Ok((Session::new(inner), output))
    }

    /// Feed an incoming peer message. Out-of-order messages are buffered and
    /// replayed automatically after each state transition.
    pub fn process_message(
        &mut self,
        from: &str,
        to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        let prev_state = self.inner.state_name();

        // Take inner state, process (consuming), put it back.
        let state = std::mem::replace(&mut self.inner, SessionInner::Completed);
        let (new_state, output) = state.process_message(from, to, payload, storage);
        self.inner = new_state;

        match output {
            Ok(step) => {
                debug!(
                    from,
                    prev_state,
                    new_state = self.inner.state_name(),
                    outgoing = step.messages.len(),
                    has_result = step.result.is_some(),
                    "message processed"
                );

                // Successful transition — try to drain pending messages.
                let mut combined = step;
                if !self.pending.is_empty() {
                    let pending = std::mem::take(&mut self.pending);
                    debug!(count = pending.len(), "draining pending messages");
                    for (f, t, p) in pending {
                        let state = std::mem::replace(&mut self.inner, SessionInner::Completed);
                        let (new_state, result) = state.process_message(&f, &t, &p, storage);
                        self.inner = new_state;
                        match result {
                            Ok(more) => {
                                debug!(
                                    from = f.as_str(),
                                    new_state = self.inner.state_name(),
                                    outgoing = more.messages.len(),
                                    has_result = more.result.is_some(),
                                    "pending message processed"
                                );
                                combined.messages.extend(more.messages);
                                if let Some(r) = more.result {
                                    combined.result = Some(r);
                                }
                            }
                            Err(ProcessError::WrongRound(e)) => {
                                debug!(from = f.as_str(), error = e.as_str(), "pending message re-buffered");
                                self.pending.push((f, t, p));
                            }
                            Err(ProcessError::Invalid(e)) => {
                                debug!(from = f.as_str(), error = e.as_str(), "pending message dropped (invalid)");
                            }
                        }
                    }
                }
                Ok(combined)
            }
            Err(ProcessError::WrongRound(e)) => {
                debug!(
                    from,
                    state = prev_state,
                    error = e.as_str(),
                    pending = self.pending.len() + 1,
                    "message buffered (wrong round)"
                );
                self.pending.push((from.to_string(), to.to_string(), payload.to_vec()));
                Ok(StepOutput { messages: vec![], result: None })
            }
            Err(ProcessError::Invalid(e)) => {
                debug!(
                    from,
                    state = prev_state,
                    error = e.as_str(),
                    "message dropped (invalid)"
                );
                Ok(StepOutput { messages: vec![], result: None })
            }
        }
    }
}

enum SessionInner {
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
    /// Reshare round 1: old parties broadcast commitments; all collect.
    ReshareR1 {
        session_id: String,
        params: ReshareParams,
        is_old: bool,
        is_new: bool,
        /// Old party's polynomial (None for new-only parties).
        polynomial: Option<Polynomial>,
        chain_key: Option<Vec<u8>>,
        /// Old party scalar IDs (for Lagrange).
        old_scalars: Vec<k256::Scalar>,
        /// New party scalar IDs.
        new_scalars: Vec<k256::Scalar>,
        /// This party's scalar in the old set.
        self_old_scalar: Option<k256::Scalar>,
        /// This party's scalar in the new set.
        self_new_scalar: Option<k256::Scalar>,
        /// Existing key share secret (old parties only).
        old_secret: Option<k256::Scalar>,
        /// Group key from stored config.
        group_key: Vec<u8>,
        generation: u64,
        /// Collected R1 broadcasts from old parties.
        r1_received: BTreeMap<String, ReshareR1Payload>,
        broadcast_sent: bool,
    },
    /// Reshare round 2: new parties collect sub-shares from old parties.
    ReshareR2 {
        session_id: String,
        params: ReshareParams,
        is_old: bool,
        is_new: bool,
        polynomial: Option<Polynomial>,
        old_scalars: Vec<k256::Scalar>,
        new_scalars: Vec<k256::Scalar>,
        self_new_scalar: Option<k256::Scalar>,
        group_key: Vec<u8>,
        generation: u64,
        /// Decoded commitments from all old parties.
        all_commitments: BTreeMap<String, Vec<k256::ProjectivePoint>>,
        /// Chain keys from old parties (sorted by party_id for hashing).
        chain_keys: Vec<(String, Vec<u8>)>,
        /// Sub-shares received from old parties (new parties accumulate these).
        sub_shares: BTreeMap<String, k256::Scalar>,
    },
    /// Reshare round 3: new parties exchange public key shares.
    ReshareR3 {
        session_id: String,
        params: ReshareParams,
        new_scalars: Vec<k256::Scalar>,
        self_new_scalar: k256::Scalar,
        group_key: Vec<u8>,
        generation: u64,
        /// This party's new secret share.
        new_secret: k256::Scalar,
        chain_keys: Vec<(String, Vec<u8>)>,
        /// Collected verifying shares from new parties.
        pub_shares: BTreeMap<String, Vec<u8>>,
    },
    Completed,
}

impl SessionInner {
    fn state_name(&self) -> &'static str {
        match self {
            SessionInner::KeygenR1 { .. } => "KeygenR1",
            SessionInner::KeygenR2 { .. } => "KeygenR2",
            SessionInner::SignR1 { .. } => "SignR1",
            SessionInner::SignR2 { .. } => "SignR2",
            SessionInner::ReshareR1 { .. } => "ReshareR1",
            SessionInner::ReshareR2 { .. } => "ReshareR2",
            SessionInner::ReshareR3 { .. } => "ReshareR3",
            SessionInner::Completed => "Completed",
        }
    }

    /// Create and start a keygen session. Returns the inner state and initial outgoing messages.
    fn start_keygen(
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
            SessionInner::KeygenR1 {
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
    fn start_sign(
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
            SessionInner::SignR1 {
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

    /// Create and start a reshare session.
    fn start_reshare(
        session_id: &str,
        params: ReshareParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let is_old = params.old_party_ids.contains(&params.party_id);
        let is_new = params.new_party_ids.contains(&params.party_id);
        if !is_old && !is_new {
            return Err(format!("party {} not in old or new sets", params.party_id));
        }

        // Derive scalar IDs for old and new parties using frost's Identifier::derive.
        let old_scalars: Vec<k256::Scalar> = params
            .old_party_ids
            .iter()
            .map(|pid| reshare::identifier_to_scalar(
                &frost::Identifier::derive(pid.as_bytes()).unwrap()
            ).unwrap())
            .collect();
        let new_scalars: Vec<k256::Scalar> = params
            .new_party_ids
            .iter()
            .map(|pid| reshare::identifier_to_scalar(
                &frost::Identifier::derive(pid.as_bytes()).unwrap()
            ).unwrap())
            .collect();

        let self_old_scalar = if is_old {
            let id = frost::Identifier::derive(params.party_id.as_bytes())
                .map_err(|e| format!("derive self old id: {e}"))?;
            Some(reshare::identifier_to_scalar(&id)?)
        } else {
            None
        };
        let self_new_scalar = if is_new {
            let id = frost::Identifier::derive(params.party_id.as_bytes())
                .map_err(|e| format!("derive self new id: {e}"))?;
            Some(reshare::identifier_to_scalar(&id)?)
        } else {
            None
        };

        // Load existing key (old parties must have one).
        let stored = storage.get_key(&params.group_id, &params.key_id)?;
        let (old_secret, group_key, generation) = if is_old {
            let s = stored.ok_or_else(|| {
                format!("reshare: old party has no key for {}/{}", params.group_id, params.key_id)
            })?;
            // Extract the secret scalar from the frost KeyPackage.
            let kp = frost::keys::KeyPackage::deserialize(&s.key_package)
                .map_err(|e| format!("deserialize key package: {e}"))?;
            let secret_bytes = kp.signing_share().serialize();
            let secret = reshare::deserialize_scalar(&secret_bytes)
                .map_err(|e| format!("decode secret scalar: {e}"))?;
            (Some(secret), s.group_key, s.generation)
        } else {
            // New-only party: no secret. group_key and generation will be learned from R1.
            (None, vec![], 0)
        };

        // If old, generate polynomial and broadcast commitments immediately.
        let mut messages = Vec::new();
        let mut polynomial = None;
        let mut chain_key = None;
        let mut r1_received = BTreeMap::new();

        if is_old {
            let secret = old_secret.unwrap();
            let lambda = reshare::lagrange_coefficient(
                self_old_scalar.as_ref().unwrap(),
                &old_scalars,
            );
            let weighted_secret = secret * &lambda;

            let mut rng = rand::thread_rng();
            let poly = Polynomial::random(
                weighted_secret,
                (params.new_threshold - 1) as usize,
                &mut rng,
            );

            let commitments = poly.commitments();
            let encoded_commitments: Vec<Vec<u8>> = commitments
                .iter()
                .map(|c| reshare::serialize_point(c))
                .collect();

            let mut ck = [0u8; 32];
            rng.fill_bytes(&mut ck);

            let payload = ReshareR1Payload {
                commitments: encoded_commitments,
                chain_key: ck.to_vec(),
                generation,
                group_key: group_key.clone(),
            };

            // Store own R1 payload.
            r1_received.insert(params.party_id.clone(), payload.clone());

            // Broadcast R1.
            let data = cbor_encode(&payload)?;
            messages.push(OutgoingMessage {
                session_id: session_id.to_string(),
                from: params.party_id.clone(),
                to: String::new(),
                payload: data,
            });

            polynomial = Some(poly);
            chain_key = Some(ck.to_vec());
        }

        Ok((
            SessionInner::ReshareR1 {
                session_id: session_id.to_string(),
                params,
                is_old,
                is_new,
                polynomial,
                chain_key,
                old_scalars,
                new_scalars,
                self_old_scalar,
                self_new_scalar,
                old_secret,
                group_key,
                generation,
                r1_received,
                broadcast_sent: is_old, // old parties broadcast on start
            },
            StepOutput {
                messages,
                result: None,
            },
        ))
    }

    /// Feed an incoming peer message. Returns outgoing messages and possibly a result.
    /// When a result is returned, the session transitions to Completed.
    ///
    /// This is a consuming method that always returns the (possibly updated) state
    /// alongside the result. This prevents state loss: if processing fails, the
    /// caller gets back the original state instead of an accidental `Completed`.
    fn process_message(
        self,
        from: &str,
        _to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> (Self, Result<StepOutput, ProcessError>) {
        // Helper macros: if a fallible expression fails, return (restored_state, Err).
        // try_wrong_round: deserialize failures from known senders — likely wrong round.
        // try_invalid: protocol/serialization errors after state transition — permanent.
        macro_rules! try_wrong_round {
            ($expr:expr, $state:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => return ($state, Err(ProcessError::WrongRound(e.to_string()))),
                }
            };
        }
        macro_rules! try_invalid {
            ($expr:expr, $state:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => return ($state, Err(ProcessError::Invalid(e.to_string()))),
                }
            };
        }

        match self {
            SessionInner::KeygenR1 {
                session_id,
                params,
                pmap,
                self_id,
                secret,
                mut packages,
            } => {
                let restore = || SessionInner::KeygenR1 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    self_id,
                    secret: secret.clone(),
                    packages: packages.clone(),
                };

                let from_id = try_invalid!(pmap.frost_id(from), restore());
                let pkg = try_wrong_round!(
                    dkg::round1::Package::deserialize(payload)
                        .map_err(|e| format!("deserialize r1 package from {from}: {e}")),
                    restore()
                );
                packages.insert(from_id, pkg);

                if packages.len() < pmap.len() {
                    (
                        SessionInner::KeygenR1 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret,
                            packages,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // All round1 packages received. Run part2.
                    let others: BTreeMap<_, _> = packages
                        .iter()
                        .filter(|(id, _)| **id != self_id)
                        .map(|(id, pkg)| (*id, pkg.clone()))
                        .collect();
                    let (r2_secret, r2_packages) = try_invalid!(
                        dkg::part2(secret, &others)
                            .map_err(|e| format!("dkg part2: {e}")),
                        SessionInner::Completed
                    );

                    let mut messages = Vec::new();
                    for (target_id, pkg) in &r2_packages {
                        if *target_id == self_id {
                            continue;
                        }
                        let to_party = try_invalid!(
                            pmap.party_id(target_id),
                            SessionInner::Completed
                        );
                        let payload = try_invalid!(
                            pkg.serialize()
                                .map_err(|e| format!("serialize r2 package: {e}")),
                            SessionInner::Completed
                        );
                        messages.push(OutgoingMessage {
                            session_id: session_id.clone(),
                            from: params.party_id.clone(),
                            to: to_party.to_string(),
                            payload,
                        });
                    }

                    (
                        SessionInner::KeygenR2 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret: r2_secret,
                            r1_packages: others,
                            r2_packages: BTreeMap::new(),
                        },
                        Ok(StepOutput {
                            messages,
                            result: None,
                        }),
                    )
                }
            }

            SessionInner::KeygenR2 {
                session_id,
                params,
                pmap,
                self_id,
                secret,
                r1_packages,
                mut r2_packages,
            } => {
                let restore = || SessionInner::KeygenR2 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    self_id,
                    secret: secret.clone(),
                    r1_packages: r1_packages.clone(),
                    r2_packages: r2_packages.clone(),
                };

                let from_id = try_invalid!(pmap.frost_id(from), restore());
                let pkg = try_wrong_round!(
                    dkg::round2::Package::deserialize(payload)
                        .map_err(|e| format!("deserialize r2 package from {from}: {e}")),
                    restore()
                );
                r2_packages.insert(from_id, pkg);

                // Need N-1 round2 packages (from all peers, not self).
                if r2_packages.len() < pmap.len() - 1 {
                    (
                        SessionInner::KeygenR2 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret,
                            r1_packages,
                            r2_packages,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // Finalize DKG.
                    let (key_package, pub_key_package) = try_invalid!(
                        dkg::part3(&secret, &r1_packages, &r2_packages)
                            .map_err(|e| format!("dkg part3: {e}")),
                        SessionInner::Completed
                    );

                    let group_key = try_invalid!(
                        pub_key_package.verifying_key().serialize()
                            .map_err(|e| format!("serialize group key: {e}")),
                        SessionInner::Completed
                    );
                    let verifying_share = try_invalid!(
                        key_package.verifying_share().serialize()
                            .map_err(|e| format!("serialize verifying share: {e}")),
                        SessionInner::Completed
                    );

                    let kp_bytes = try_invalid!(
                        key_package.serialize()
                            .map_err(|e| format!("serialize key package: {e}")),
                        SessionInner::Completed
                    );
                    let pkp_bytes = try_invalid!(
                        pub_key_package.serialize()
                            .map_err(|e| format!("serialize pub key package: {e}")),
                        SessionInner::Completed
                    );

                    let stored = StoredKey {
                        key_package: kp_bytes,
                        public_key_package: pkp_bytes,
                        group_key: group_key.clone(),
                        verifying_share: verifying_share.clone(),
                        generation: 0,
                    };
                    try_invalid!(
                        storage.put_key(&params.group_id, &params.key_id, &stored),
                        SessionInner::Completed
                    );

                    (
                        SessionInner::Completed,
                        Ok(StepOutput {
                            messages: vec![],
                            result: Some(SessionResult {
                                group_key: Some(group_key),
                                verifying_share: Some(verifying_share),
                                signature_r: None,
                                signature_z: None,
                            }),
                        }),
                    )
                }
            }

            SessionInner::SignR1 {
                session_id,
                params,
                pmap,
                self_id,
                key_package,
                pub_key_package,
                nonces,
                mut commitments,
            } => {
                let restore = || SessionInner::SignR1 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    self_id,
                    key_package: key_package.clone(),
                    pub_key_package: pub_key_package.clone(),
                    nonces: nonces.clone(),
                    commitments: commitments.clone(),
                };

                let from_id = try_invalid!(pmap.frost_id(from), restore());
                let c = try_wrong_round!(
                    round1::SigningCommitments::deserialize(payload)
                        .map_err(|e| format!("deserialize commitments from {from}: {e}")),
                    restore()
                );
                commitments.insert(from_id, c);

                if commitments.len() < pmap.len() {
                    (
                        SessionInner::SignR1 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            key_package,
                            pub_key_package,
                            nonces,
                            commitments,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // All commitments received. Build signing package and sign.
                    let signing_package =
                        frost::SigningPackage::new(commitments, &params.message);

                    let sig_share = try_invalid!(
                        round2::sign(&signing_package, &nonces, &key_package)
                            .map_err(|e| format!("round2 sign: {e}")),
                        SessionInner::Completed
                    );

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
                        SessionInner::SignR2 {
                            session_id,
                            pmap,
                            pub_key_package,
                            signing_package,
                            shares,
                        },
                        Ok(StepOutput {
                            messages: vec![out],
                            result: None,
                        }),
                    )
                }
            }

            SessionInner::SignR2 {
                session_id,
                pmap,
                pub_key_package,
                signing_package,
                mut shares,
            } => {
                let restore = || SessionInner::SignR2 {
                    session_id: session_id.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    pub_key_package: pub_key_package.clone(),
                    signing_package: signing_package.clone(),
                    shares: shares.clone(),
                };

                let from_id = try_invalid!(pmap.frost_id(from), restore());
                let share = try_wrong_round!(
                    round2::SignatureShare::deserialize(payload)
                        .map_err(|e| format!("deserialize sig share from {from}: {e}")),
                    restore()
                );
                shares.insert(from_id, share);

                if shares.len() < pmap.len() {
                    (
                        SessionInner::SignR2 {
                            session_id,
                            pmap,
                            pub_key_package,
                            signing_package,
                            shares,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // Aggregate signatures.
                    let sig = try_invalid!(
                        frost::aggregate(&signing_package, &shares, &pub_key_package)
                            .map_err(|e| format!("aggregate: {e}")),
                        SessionInner::Completed
                    );

                    let sig_bytes = try_invalid!(
                        sig.serialize()
                            .map_err(|e| format!("serialize signature: {e}")),
                        SessionInner::Completed
                    );

                    if sig_bytes.len() != 65 {
                        return (
                            SessionInner::Completed,
                            Err(ProcessError::Invalid(format!(
                                "unexpected signature length: {} (expected 65)",
                                sig_bytes.len()
                            ))),
                        );
                    }

                    (
                        SessionInner::Completed,
                        Ok(StepOutput {
                            messages: vec![],
                            result: Some(SessionResult {
                                group_key: None,
                                verifying_share: None,
                                signature_r: Some(sig_bytes[..33].to_vec()),
                                signature_z: Some(sig_bytes[33..].to_vec()),
                            }),
                        }),
                    )
                }
            }

            // -----------------------------------------------------------------
            // Reshare Round 1: collect R1 broadcasts from all old parties
            // -----------------------------------------------------------------
            SessionInner::ReshareR1 {
                session_id,
                params,
                is_old,
                is_new,
                polynomial,
                chain_key,
                old_scalars,
                new_scalars,
                self_old_scalar,
                self_new_scalar,
                old_secret,
                group_key,
                generation,
                mut r1_received,
                broadcast_sent,
            } => {
                // Only accept R1 from old parties.
                if !params.old_party_ids.contains(&from.to_string()) {
                    return (
                        SessionInner::ReshareR1 {
                            session_id, params, is_old, is_new, polynomial, chain_key,
                            old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                            old_secret, group_key, generation, r1_received, broadcast_sent,
                        },
                        Err(ProcessError::Invalid(format!("R1 from non-old party: {from}"))),
                    );
                }
                if r1_received.contains_key(from) {
                    return (
                        SessionInner::ReshareR1 {
                            session_id, params, is_old, is_new, polynomial, chain_key,
                            old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                            old_secret, group_key, generation, r1_received, broadcast_sent,
                        },
                        Err(ProcessError::Invalid(format!("duplicate R1 from {from}"))),
                    );
                }

                let r1: ReshareR1Payload = match cbor_decode(payload) {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            SessionInner::ReshareR1 {
                                session_id, params, is_old, is_new, polynomial, chain_key,
                                old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                                old_secret, group_key, generation, r1_received, broadcast_sent,
                            },
                            Err(ProcessError::WrongRound(e)),
                        );
                    }
                };
                r1_received.insert(from.to_string(), r1);

                // Not all R1 collected yet.
                if r1_received.len() < params.old_party_ids.len() {
                    return (
                        SessionInner::ReshareR1 {
                            session_id, params, is_old, is_new, polynomial, chain_key,
                            old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                            old_secret, group_key, generation, r1_received, broadcast_sent,
                        },
                        Ok(StepOutput { messages: vec![], result: None }),
                    );
                }

                // All R1 received. Verify group key consistency and decode commitments.
                let resolved_group_key = if group_key.is_empty() {
                    // New-only party: learn group key from first R1.
                    r1_received.values().next().unwrap().group_key.clone()
                } else {
                    group_key
                };
                let resolved_generation = if generation == 0 && !is_old {
                    r1_received.values().next().unwrap().generation
                } else {
                    generation
                };

                // Verify all old parties agree on group key.
                for (pid, r1) in &r1_received {
                    if r1.group_key != resolved_group_key {
                        return (
                            SessionInner::Completed,
                            Err(ProcessError::Invalid(format!("group key mismatch from {pid}"))),
                        );
                    }
                }

                // Decode commitments.
                let mut all_commitments: BTreeMap<String, Vec<k256::ProjectivePoint>> = BTreeMap::new();
                for (pid, r1) in &r1_received {
                    let mut points = Vec::new();
                    for raw in &r1.commitments {
                        match reshare::deserialize_point(raw) {
                            Ok(p) => points.push(p),
                            Err(e) => return (
                                SessionInner::Completed,
                                Err(ProcessError::Invalid(format!("bad commitment from {pid}: {e}"))),
                            ),
                        }
                    }
                    all_commitments.insert(pid.clone(), points);
                }

                // Verify group key preservation: sum of constant terms == group key.
                let group_key_point = match reshare::deserialize_point(&resolved_group_key) {
                    Ok(p) => p,
                    Err(e) => return (
                        SessionInner::Completed,
                        Err(ProcessError::Invalid(format!("bad group key: {e}"))),
                    ),
                };
                let mut commit_sum = k256::ProjectivePoint::IDENTITY;
                for (_, commits) in &all_commitments {
                    commit_sum = commit_sum + commits[0];
                }
                if commit_sum != group_key_point {
                    return (
                        SessionInner::Completed,
                        Err(ProcessError::Invalid("commitment constants don't sum to group key".into())),
                    );
                }

                // Collect chain keys sorted by party_id.
                let mut sorted_chain_keys: Vec<(String, Vec<u8>)> = r1_received
                    .iter()
                    .map(|(pid, r1)| (pid.clone(), r1.chain_key.clone()))
                    .collect();
                sorted_chain_keys.sort_by(|a, b| a.0.cmp(&b.0));

                // Old parties: send sub-shares to new parties.
                let mut messages = Vec::new();
                if is_old {
                    let poly = polynomial.as_ref().unwrap();
                    for (i, new_pid) in params.new_party_ids.iter().enumerate() {
                        if *new_pid == params.party_id {
                            continue; // compute own locally in R2
                        }
                        let sub_share = poly.evaluate(&new_scalars[i]);
                        let payload = ReshareR2Payload {
                            sub_share: reshare::serialize_scalar(&sub_share),
                        };
                        let data = match cbor_encode(&payload) {
                            Ok(d) => d,
                            Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(e))),
                        };
                        messages.push(OutgoingMessage {
                            session_id: session_id.clone(),
                            from: params.party_id.clone(),
                            to: new_pid.clone(),
                            payload: data,
                        });
                    }
                }

                (
                    SessionInner::ReshareR2 {
                        session_id,
                        params,
                        is_old,
                        is_new,
                        polynomial,
                        old_scalars,
                        new_scalars,
                        self_new_scalar,
                        group_key: resolved_group_key,
                        generation: resolved_generation,
                        all_commitments,
                        chain_keys: sorted_chain_keys,
                        sub_shares: BTreeMap::new(),
                    },
                    Ok(StepOutput { messages, result: None }),
                )
            }

            // -----------------------------------------------------------------
            // Reshare Round 2: new parties collect sub-shares from old parties
            // -----------------------------------------------------------------
            SessionInner::ReshareR2 {
                session_id,
                params,
                is_old,
                is_new,
                polynomial,
                old_scalars,
                new_scalars,
                self_new_scalar,
                group_key,
                generation,
                all_commitments,
                chain_keys,
                mut sub_shares,
            } => {
                if !params.old_party_ids.contains(&from.to_string()) {
                    return (
                        SessionInner::ReshareR2 {
                            session_id, params, is_old, is_new, polynomial,
                            old_scalars, new_scalars, self_new_scalar,
                            group_key, generation, all_commitments, chain_keys, sub_shares,
                        },
                        Err(ProcessError::Invalid(format!("R2 from non-old party: {from}"))),
                    );
                }
                if sub_shares.contains_key(from) {
                    return (
                        SessionInner::ReshareR2 {
                            session_id, params, is_old, is_new, polynomial,
                            old_scalars, new_scalars, self_new_scalar,
                            group_key, generation, all_commitments, chain_keys, sub_shares,
                        },
                        Err(ProcessError::Invalid(format!("duplicate R2 from {from}"))),
                    );
                }

                let r2: ReshareR2Payload = match cbor_decode(payload) {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            SessionInner::ReshareR2 {
                                session_id, params, is_old, is_new, polynomial,
                                old_scalars, new_scalars, self_new_scalar,
                                group_key, generation, all_commitments, chain_keys, sub_shares,
                            },
                            Err(ProcessError::WrongRound(e)),
                        );
                    }
                };

                let sub_share = match reshare::deserialize_scalar(&r2.sub_share) {
                    Ok(s) => s,
                    Err(e) => return (
                        SessionInner::Completed,
                        Err(ProcessError::Invalid(format!("bad sub-share from {from}: {e}"))),
                    ),
                };

                // Feldman verification.
                let self_scalar = self_new_scalar.unwrap();
                let commitments = &all_commitments[from];
                if !reshare::verify_feldman(&self_scalar, &sub_share, commitments) {
                    return (
                        SessionInner::Completed,
                        Err(ProcessError::Invalid(format!("Feldman verification failed for {from}"))),
                    );
                }

                sub_shares.insert(from.to_string(), sub_share);

                // If old+new, compute own sub-share locally.
                if is_old && !sub_shares.contains_key(&params.party_id) {
                    let poly = polynomial.as_ref().unwrap();
                    let own_share = poly.evaluate(&self_scalar);
                    sub_shares.insert(params.party_id.clone(), own_share);
                }

                // Need sub-shares from all old parties.
                if sub_shares.len() < params.old_party_ids.len() {
                    return (
                        SessionInner::ReshareR2 {
                            session_id, params, is_old, is_new, polynomial,
                            old_scalars, new_scalars, self_new_scalar,
                            group_key, generation, all_commitments, chain_keys, sub_shares,
                        },
                        Ok(StepOutput { messages: vec![], result: None }),
                    );
                }

                if is_new {
                    // Combine sub-shares: s'_j = Σ f_i(j)
                    let mut new_secret = k256::Scalar::ZERO;
                    for (_, share) in &sub_shares {
                        new_secret = new_secret + share;
                    }

                    // Compute verifying share (public key share).
                    let verifying_share = k256::ProjectivePoint::GENERATOR * &new_secret;
                    let vs_bytes = reshare::serialize_point(&verifying_share);

                    // Broadcast R3.
                    let r3_payload = ReshareR3Payload {
                        verifying_share: vs_bytes.clone(),
                    };
                    let data = match cbor_encode(&r3_payload) {
                        Ok(d) => d,
                        Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(e))),
                    };
                    let messages = vec![OutgoingMessage {
                        session_id: session_id.clone(),
                        from: params.party_id.clone(),
                        to: String::new(),
                        payload: data,
                    }];

                    let mut pub_shares = BTreeMap::new();
                    pub_shares.insert(params.party_id.clone(), vs_bytes);

                    (
                        SessionInner::ReshareR3 {
                            session_id,
                            params,
                            new_scalars,
                            self_new_scalar: self_scalar,
                            group_key,
                            generation,
                            new_secret,
                            chain_keys,
                            pub_shares,
                        },
                        Ok(StepOutput { messages, result: None }),
                    )
                } else {
                    // Old-only party: done. Return result with incremented generation.
                    (
                        SessionInner::Completed,
                        Ok(StepOutput {
                            messages: vec![],
                            result: Some(SessionResult {
                                group_key: Some(group_key),
                                verifying_share: None,
                                signature_r: None,
                                signature_z: None,
                            }),
                        }),
                    )
                }
            }

            // -----------------------------------------------------------------
            // Reshare Round 3: new parties exchange verifying shares and finalize
            // -----------------------------------------------------------------
            SessionInner::ReshareR3 {
                session_id,
                params,
                new_scalars,
                self_new_scalar,
                group_key,
                generation,
                new_secret,
                chain_keys,
                mut pub_shares,
            } => {
                if !params.new_party_ids.contains(&from.to_string()) {
                    return (
                        SessionInner::ReshareR3 {
                            session_id, params, new_scalars, self_new_scalar,
                            group_key, generation, new_secret, chain_keys, pub_shares,
                        },
                        Err(ProcessError::Invalid(format!("R3 from non-new party: {from}"))),
                    );
                }
                if pub_shares.contains_key(from) {
                    return (
                        SessionInner::ReshareR3 {
                            session_id, params, new_scalars, self_new_scalar,
                            group_key, generation, new_secret, chain_keys, pub_shares,
                        },
                        Err(ProcessError::Invalid(format!("duplicate R3 from {from}"))),
                    );
                }

                let r3: ReshareR3Payload = match cbor_decode(payload) {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            SessionInner::ReshareR3 {
                                session_id, params, new_scalars, self_new_scalar,
                                group_key, generation, new_secret, chain_keys, pub_shares,
                            },
                            Err(ProcessError::WrongRound(e)),
                        );
                    }
                };
                pub_shares.insert(from.to_string(), r3.verifying_share);

                if pub_shares.len() < params.new_party_ids.len() {
                    return (
                        SessionInner::ReshareR3 {
                            session_id, params, new_scalars, self_new_scalar,
                            group_key, generation, new_secret, chain_keys, pub_shares,
                        },
                        Ok(StepOutput { messages: vec![], result: None }),
                    );
                }

                // All pub shares collected. Build the new key and persist.
                let (combined_chain_key, _rid) = reshare::combine_chain_keys(&chain_keys);

                // Compute own verifying share.
                let self_verifying_share = k256::ProjectivePoint::GENERATOR * &new_secret;
                let vs_bytes = reshare::serialize_point(&self_verifying_share);

                // Build a new KeyPackage and PublicKeyPackage from the reshare output.
                // We need to construct these in the format frost-secp256k1 expects.
                let self_frost_id = frost::Identifier::derive(params.party_id.as_bytes())
                    .map_err(|e| format!("derive frost id: {e}"));
                let self_frost_id = match self_frost_id {
                    Ok(id) => id,
                    Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(e))),
                };

                // Build verifying_shares map for PublicKeyPackage.
                let mut frost_verifying_shares = BTreeMap::new();
                for (pid, share_bytes) in &pub_shares {
                    let fid = match frost::Identifier::derive(pid.as_bytes()) {
                        Ok(id) => id,
                        Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(format!("derive id for {pid}: {e}")))),
                    };
                    let vs_array: [u8; 33] = match share_bytes.clone().try_into() {
                        Ok(a) => a,
                        Err(_) => return (SessionInner::Completed, Err(ProcessError::Invalid(format!("verifying share for {pid} must be 33 bytes")))),
                    };
                    let vs = match frost::keys::VerifyingShare::deserialize(&vs_array) {
                        Ok(v) => v,
                        Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(format!("deserialize verifying share for {pid}: {e}")))),
                    };
                    frost_verifying_shares.insert(fid, vs);
                }

                let gk_array: [u8; 33] = match group_key.clone().try_into() {
                    Ok(a) => a,
                    Err(_) => return (SessionInner::Completed, Err(ProcessError::Invalid("group key must be 33 bytes".into()))),
                };
                let group_verifying_key = match frost::VerifyingKey::deserialize(&gk_array) {
                    Ok(v) => v,
                    Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(format!("deserialize group key: {e}")))),
                };

                let ss_bytes: [u8; 32] = reshare::serialize_scalar(&new_secret).try_into().unwrap();
                let signing_share = match frost::keys::SigningShare::deserialize(&ss_bytes) {
                    Ok(s) => s,
                    Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(format!("build signing share: {e}")))),
                };

                let key_package = frost::keys::KeyPackage::new(
                    self_frost_id,
                    signing_share,
                    *frost_verifying_shares.get(&self_frost_id).unwrap(),
                    group_verifying_key,
                    params.new_threshold,
                );
                let pub_key_package = frost::keys::PublicKeyPackage::new(
                    frost_verifying_shares,
                    group_verifying_key,
                );

                let kp_bytes = match key_package.serialize() {
                    Ok(b) => b,
                    Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(format!("serialize key package: {e}")))),
                };
                let pkp_bytes = match pub_key_package.serialize() {
                    Ok(b) => b,
                    Err(e) => return (SessionInner::Completed, Err(ProcessError::Invalid(format!("serialize pub key package: {e}")))),
                };

                // Store as pending (the Go layer will call CommitReshare to promote).
                let stored = StoredKey {
                    key_package: kp_bytes,
                    public_key_package: pkp_bytes,
                    group_key: group_key.clone(),
                    verifying_share: vs_bytes.clone(),
                    generation: generation + 1,
                };
                if let Err(e) = storage.put_pending(&params.group_id, &params.key_id, &stored) {
                    return (SessionInner::Completed, Err(ProcessError::Invalid(format!("persist pending reshare: {e}"))));
                }

                (
                    SessionInner::Completed,
                    Ok(StepOutput {
                        messages: vec![],
                        result: Some(SessionResult {
                            group_key: Some(group_key),
                            verifying_share: Some(vs_bytes),
                            signature_r: None,
                            signature_z: None,
                        }),
                    }),
                )
            }

            SessionInner::Completed => {
                (SessionInner::Completed, Err(ProcessError::Invalid("session already completed".into())))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1 as frost;
    use std::collections::HashMap;
    use std::sync::Once;

    const GROUP_ID: &str = "test-group";
    const KEY_ID: &str = "test-key";
    const PARTIES: [&str; 3] = ["peer-A", "peer-B", "peer-C"];

    static TRACING_INIT: Once = Once::new();

    /// Install a tracing subscriber that prints debug output when
    /// RUST_LOG is set. Silent by default; run with
    /// `RUST_LOG=debug cargo test -- --nocapture` to see traces.
    fn init_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();
        });
    }

    /// Create a temp Storage for each party.
    fn make_storages(parties: &[&str]) -> HashMap<String, (Storage, tempfile::TempDir)> {
        parties
            .iter()
            .map(|pid| {
                let dir = tempfile::tempdir().unwrap();
                let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();
                (pid.to_string(), (storage, dir))
            })
            .collect()
    }

    /// Route messages between sessions using a breadth-first queue.
    /// Broadcasts (to == "") go to every session except the sender;
    /// unicasts go to the named recipient.
    ///
    /// Returns all results produced by the receiving sessions.
    fn route(
        initial_msgs: Vec<OutgoingMessage>,
        sessions: &mut HashMap<String, (Session, Storage)>,
    ) -> Vec<SessionResult> {
        let mut results = Vec::new();
        let mut queue: std::collections::VecDeque<OutgoingMessage> = initial_msgs.into();

        while let Some(msg) = queue.pop_front() {
            let recipients: Vec<String> = if msg.to.is_empty() {
                sessions
                    .keys()
                    .filter(|k| **k != msg.from)
                    .cloned()
                    .collect()
            } else {
                vec![msg.to.clone()]
            };

            for recipient in recipients {
                if let Some((session, storage)) = sessions.get_mut(&recipient) {
                    let out = session
                        .process_message(&msg.from, &recipient, &msg.payload, storage)
                        .expect("process_message failed");
                    if let Some(r) = out.result {
                        results.push(r);
                    }
                    for m in out.messages {
                        queue.push_back(m);
                    }
                }
            }
        }
        results
    }

    /// Deliver messages one-at-a-time without recursion. Returns messages
    /// produced by each delivery so the caller controls ordering.
    fn deliver_one(
        msg: &OutgoingMessage,
        recipient: &str,
        sessions: &mut HashMap<String, (Session, Storage)>,
    ) -> StepOutput {
        let (session, storage) = sessions.get_mut(recipient).expect("unknown recipient");
        session
            .process_message(&msg.from, recipient, &msg.payload, storage)
            .expect("process_message failed")
    }

    /// Run a full 2-of-3 keygen. Returns the group public key.
    /// Storages are borrowed from `owned` (which keeps TempDirs alive).
    fn run_keygen(
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> Vec<u8> {
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            initial_messages.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), 3, "expected 3 keygen results, got {}", results.len());

        let group_keys: Vec<Vec<u8>> = results
            .iter()
            .map(|r| r.group_key.clone().expect("group_key missing"))
            .collect();
        assert!(
            group_keys.windows(2).all(|w| w[0] == w[1]),
            "group keys disagree"
        );

        // Move storages back (re-wrap with dummy TempDirs — originals still live in caller).
        for (pid, (session, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            // Re-open storage at same path is fine for sled; but we just reuse the instance.
            owned.insert(pid, (storage, dir));
            drop(session);
        }

        group_keys.into_iter().next().unwrap()
    }

    /// Sign `message` with the given signer subset and verify the result.
    /// Returns (R, z) byte vecs.
    fn run_sign(
        signers: &[&str],
        message: &[u8],
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> (Vec<u8>, Vec<u8>) {
        let signer_ids: Vec<String> = signers.iter().map(|s| s.to_string()).collect();
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();

        for pid in signers {
            let params = SignParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.to_string(),
                signer_ids: signer_ids.clone(),
                message: message.to_vec(),
            };
            let (storage, _) = owned.remove(*pid).unwrap();
            let (session, output) =
                Session::start_sign(&format!("sign-{pid}"), params, &storage)
                    .expect("start_sign");
            initial_messages.extend(output.messages);
            sessions.insert(pid.to_string(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), signers.len(), "expected {} sign results", signers.len());

        // All signers must agree.
        let r0 = results[0].signature_r.as_ref().unwrap();
        let z0 = results[0].signature_z.as_ref().unwrap();
        for r in &results[1..] {
            assert_eq!(r.signature_r.as_ref().unwrap(), r0, "R mismatch");
            assert_eq!(r.signature_z.as_ref().unwrap(), z0, "z mismatch");
        }

        // Move storages back.
        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        (r0.clone(), z0.clone())
    }

    fn verify_signature(group_key: &[u8], message: &[u8], sig_r: &[u8], sig_z: &[u8]) {
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(sig_r);
        sig_bytes.extend_from_slice(sig_z);
        let sig = frost::Signature::deserialize(&sig_bytes).expect("deserialize signature");
        let vk = frost::VerifyingKey::deserialize(group_key).expect("deserialize verifying key");
        vk.verify(message, &sig).expect("signature verification failed");
    }

    // =======================================================================
    // Happy-path tests
    // =======================================================================

    #[test]
    fn test_keygen_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        assert_eq!(group_key.len(), 33);
        for pid in PARTIES {
            let (storage, _) = owned.get(pid).unwrap();
            let stored = storage
                .get_key(GROUP_ID, KEY_ID)
                .unwrap()
                .expect("missing stored key");
            assert_eq!(stored.group_key, group_key);
        }
    }

    #[test]
    fn test_sign_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        let message = b"deadbeef01234567deadbeef01234567";
        let (sig_r, sig_z) = run_sign(&["peer-A", "peer-B"], message, &mut owned);
        verify_signature(&group_key, message, &sig_r, &sig_z);
    }

    // =======================================================================
    // Signer subset tests — verify all 2-of-3 combinations produce valid sigs
    // =======================================================================

    #[test]
    fn test_all_signer_subsets() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);
        let message = b"test all subsets message payload!";

        let subsets: &[&[&str]] = &[
            &["peer-A", "peer-B"],
            &["peer-A", "peer-C"],
            &["peer-B", "peer-C"],
        ];
        for subset in subsets {
            let (sig_r, sig_z) = run_sign(subset, message, &mut owned);
            verify_signature(&group_key, message, &sig_r, &sig_z);
        }
    }

    // =======================================================================
    // Multiple independent signs with the same key
    // =======================================================================

    #[test]
    fn test_sign_different_messages() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        let msg1 = b"first message to sign here!!!!!" ;
        let msg2 = b"second message, totally different";

        let (r1, z1) = run_sign(&["peer-A", "peer-B"], msg1, &mut owned);
        let (r2, z2) = run_sign(&["peer-A", "peer-C"], msg2, &mut owned);

        verify_signature(&group_key, msg1, &r1, &z1);
        verify_signature(&group_key, msg2, &r2, &z2);

        // Different messages must produce different signatures.
        assert_ne!(r1, r2, "different messages produced same R");
    }

    // =======================================================================
    // Out-of-order message delivery
    // =======================================================================

    #[test]
    fn test_keygen_out_of_order_delivery() {
        init_tracing();
        // Manually drive a 2-of-3 keygen delivering round-2 messages
        // before all round-1 messages have arrived.
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut r1_broadcasts: Vec<OutgoingMessage> = Vec::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            r1_broadcasts.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        // Deliver A's broadcast to B and C (everyone has 2/3 R1 packages).
        let a_broadcast = &r1_broadcasts[0];
        deliver_one(a_broadcast, "peer-B", &mut sessions);
        deliver_one(a_broadcast, "peer-C", &mut sessions);
        assert_eq!(sessions["peer-B"].0.state_name(), "KeygenR1");
        assert_eq!(sessions["peer-C"].0.state_name(), "KeygenR1");

        // Deliver B's broadcast to C — C now has all 3 R1 packages, transitions to R2.
        let b_broadcast = &r1_broadcasts[1];
        let step = deliver_one(b_broadcast, "peer-C", &mut sessions);
        assert_eq!(sessions["peer-C"].0.state_name(), "KeygenR2");
        let c_r2_messages = step.messages;
        assert_eq!(c_r2_messages.len(), 2, "C should send 2 unicast R2 packages");

        // Deliver C's R2 unicasts BEFORE finishing R1 delivery.
        // A and B are still in KeygenR1 — these must be buffered.
        for msg in &c_r2_messages {
            let recipient = &msg.to;
            deliver_one(msg, recipient, &mut sessions);
        }
        assert_eq!(sessions["peer-A"].0.state_name(), "KeygenR1");
        assert_eq!(sessions["peer-A"].0.pending_count(), 1, "A should buffer C's R2 msg");
        assert_eq!(sessions["peer-B"].0.state_name(), "KeygenR1");
        assert_eq!(sessions["peer-B"].0.pending_count(), 1, "B should buffer C's R2 msg");

        // Now deliver remaining R1 broadcasts so everyone can finish.
        // B's broadcast to A:
        deliver_one(b_broadcast, "peer-A", &mut sessions);
        assert_eq!(sessions["peer-A"].0.state_name(), "KeygenR1", "A still needs C's R1");

        // C's broadcast to A and B:
        let c_broadcast = &r1_broadcasts[2];
        let step_a = deliver_one(c_broadcast, "peer-A", &mut sessions);
        // A should transition to R2, drain pending C R2 msg, and possibly complete.
        assert!(
            sessions["peer-A"].0.state_name() == "KeygenR2"
                || sessions["peer-A"].0.state_name() == "Completed",
            "A should be in KeygenR2 or Completed after getting all R1 + buffered R2, got {}",
            sessions["peer-A"].0.state_name()
        );
        let a_r2_messages = step_a.messages;

        let step_b = deliver_one(c_broadcast, "peer-B", &mut sessions);
        let b_r2_messages = step_b.messages;

        // Route remaining R2 messages to completion.
        let mut all_remaining = Vec::new();
        all_remaining.extend(a_r2_messages);
        all_remaining.extend(b_r2_messages);
        route(all_remaining, &mut sessions);

        // Collect all results (some may have come from pending drain).
        let completed: Vec<_> = sessions
            .values()
            .filter(|(s, _)| s.state_name() == "Completed")
            .collect();
        assert_eq!(completed.len(), 3, "all 3 parties should complete");
    }

    // =======================================================================
    // Duplicate message handling
    // =======================================================================

    #[test]
    fn test_duplicate_r1_message_ignored() {
        init_tracing();
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut r1_broadcasts: Vec<OutgoingMessage> = Vec::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            r1_broadcasts.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        // Deliver A's broadcast to B twice — the duplicate should overwrite
        // (BTreeMap insert) and not cause a double-count.
        let a_broadcast = &r1_broadcasts[0];
        deliver_one(a_broadcast, "peer-B", &mut sessions);
        deliver_one(a_broadcast, "peer-B", &mut sessions);
        assert_eq!(
            sessions["peer-B"].0.state_name(),
            "KeygenR1",
            "duplicate R1 should not advance state"
        );

        // Now deliver remaining broadcasts normally — keygen should complete.
        let results = route(r1_broadcasts, &mut sessions);
        assert_eq!(results.len(), 3, "keygen should still complete after duplicate");
    }

    // =======================================================================
    // Unknown sender
    // =======================================================================

    #[test]
    fn test_unknown_sender_dropped() {
        init_tracing();
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, _output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            sessions.insert(pid.clone(), (session, storage));
        }

        // Send a message from an unknown party — permanently invalid, should be dropped.
        let (session, storage) = sessions.get_mut("peer-A").unwrap();
        let result = session.process_message("peer-UNKNOWN", "peer-A", b"garbage", storage);
        assert!(result.is_ok(), "unknown sender should not cause panic");
        assert_eq!(session.pending_count(), 0, "invalid message should be dropped, not buffered");
        assert_eq!(session.state_name(), "KeygenR1", "state should be unchanged");
    }

    // =======================================================================
    // Corrupted payload
    // =======================================================================

    #[test]
    fn test_bad_payload_from_known_sender_buffered() {
        init_tracing();
        // A deserialization failure from a known sender is treated as a
        // wrong-round message (we can't distinguish garbage from valid data
        // for a different round). These get buffered and retried.
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, _output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            sessions.insert(pid.clone(), (session, storage));
        }

        let (session, storage) = sessions.get_mut("peer-A").unwrap();
        let result = session.process_message("peer-B", "peer-A", b"not-a-frost-package", storage);
        assert!(result.is_ok(), "bad payload should not cause panic");
        assert_eq!(session.pending_count(), 1, "wrong-round message should be buffered");
        assert_eq!(session.state_name(), "KeygenR1", "state should be preserved");
    }

    // =======================================================================
    // Message after completion
    // =======================================================================

    #[test]
    fn test_message_after_completion_dropped() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        run_keygen(&mut owned);

        // Sign to get a completed session.
        let signer_ids: Vec<String> = vec!["peer-A".to_string(), "peer-B".to_string()];
        let message = b"deadbeef01234567deadbeef01234567";

        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();
        for pid in ["peer-A", "peer-B"] {
            let params = SignParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.to_string(),
                signer_ids: signer_ids.clone(),
                message: message.to_vec(),
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_sign(&format!("sign-{pid}"), params, &storage).expect("start_sign");
            initial_messages.extend(output.messages);
            sessions.insert(pid.to_string(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), 2);
        assert_eq!(sessions["peer-A"].0.state_name(), "Completed");

        // Send another message to the completed session — should be dropped.
        let (session, storage) = sessions.get_mut("peer-A").unwrap();
        let result = session.process_message("peer-B", "peer-A", b"late-message", storage);
        assert!(result.is_ok(), "message to completed session should not panic");
        assert_eq!(session.pending_count(), 0, "message to completed session should be dropped");
    }

    // =======================================================================
    // Storage round-trip: sign using key loaded from cold storage
    // =======================================================================

    #[test]
    fn test_sign_from_cold_storage() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        // Sign using storages that only have persisted keys — no in-memory
        // session state carried over. This is the real-world path: KMS restarts
        // between keygen and sign.
        let message = b"cold storage signing test!!!!!!!" ;
        let (sig_r, sig_z) = run_sign(&["peer-B", "peer-C"], message, &mut owned);
        verify_signature(&group_key, message, &sig_r, &sig_z);
    }

    // =======================================================================
    // Reshare: same committee, key refresh
    // =======================================================================

    /// Run a same-committee reshare (key refresh). Promotes the pending key
    /// to active by renaming in storage. Returns the group key (should be preserved).
    fn run_reshare(
        old_parties: &[&str],
        new_parties: &[&str],
        new_threshold: u16,
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> Vec<u8> {
        let old_ids: Vec<String> = old_parties.iter().map(|s| s.to_string()).collect();
        let new_ids: Vec<String> = new_parties.iter().map(|s| s.to_string()).collect();

        // All parties involved in the reshare (union of old and new).
        let mut all_parties: Vec<String> = old_ids.clone();
        for p in &new_ids {
            if !all_parties.contains(p) {
                all_parties.push(p.clone());
            }
        }

        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();

        for pid in &all_parties {
            let params = ReshareParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                old_party_ids: old_ids.clone(),
                new_party_ids: new_ids.clone(),
                new_threshold,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_reshare(&format!("reshare-{pid}"), params, &storage)
                    .expect("start_reshare");
            initial_messages.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        // All parties should produce a result.
        assert_eq!(
            results.len(),
            all_parties.len(),
            "expected {} reshare results, got {}",
            all_parties.len(),
            results.len()
        );

        // All results should agree on group key.
        let group_keys: Vec<Vec<u8>> = results
            .iter()
            .map(|r| r.group_key.clone().expect("group_key missing"))
            .collect();
        assert!(
            group_keys.windows(2).all(|w| w[0] == w[1]),
            "group keys disagree after reshare"
        );

        // Promote pending keys to active for new parties via commit_reshare.
        for pid in &new_ids {
            let (_, storage) = sessions.get(pid).unwrap();
            let pending = storage
                .get_pending(GROUP_ID, KEY_ID)
                .unwrap()
                .expect("pending key should exist after reshare");
            assert_eq!(pending.generation, 1, "generation should be incremented");
            let new_gen = storage.commit_reshare(GROUP_ID, KEY_ID).unwrap();
            assert_eq!(new_gen, 1);
        }

        // Move storages back.
        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        group_keys.into_iter().next().unwrap()
    }

    #[test]
    fn test_reshare_same_committee() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        // Sign before reshare to confirm key works.
        let msg1 = b"before reshare, signing works!!!";
        let (r1, z1) = run_sign(&["peer-A", "peer-B"], msg1, &mut owned);
        verify_signature(&group_key, msg1, &r1, &z1);

        // Reshare: same committee, same threshold (key refresh).
        let reshare_group_key = run_reshare(
            &["peer-A", "peer-B", "peer-C"],
            &["peer-A", "peer-B", "peer-C"],
            2,
            &mut owned,
        );

        // Group key must be preserved.
        assert_eq!(group_key, reshare_group_key, "reshare must preserve group key");

        // Sign after reshare with new shares.
        let msg2 = b"after reshare, still works!!!!!!";
        let (r2, z2) = run_sign(&["peer-A", "peer-C"], msg2, &mut owned);
        verify_signature(&group_key, msg2, &r2, &z2);
    }

    // =======================================================================
    // Reshare: 5-party same committee (matches testnet configuration)
    // =======================================================================

    const PARTIES5: &[&str] = &["peer-A", "peer-B", "peer-C", "peer-D", "peer-E"];

    #[test]
    fn test_reshare_5_of_5_same_committee() {
        init_tracing();
        let mut owned = make_storages(PARTIES5);

        // Keygen: 2-of-5.
        let party_ids: Vec<String> = PARTIES5.iter().map(|s| s.to_string()).collect();
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();
        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            initial_messages.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }
        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), 5);
        let group_key = results[0].group_key.clone().unwrap();
        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        // Sign before reshare.
        let msg1 = b"5-party sign before reshare!!!!!";
        let (r1, z1) = run_sign(&["peer-A", "peer-B"], msg1, &mut owned);
        verify_signature(&group_key, msg1, &r1, &z1);

        // Reshare: same committee, same threshold.
        let reshare_group_key = run_reshare(PARTIES5, PARTIES5, 2, &mut owned);
        assert_eq!(group_key, reshare_group_key, "reshare must preserve group key");

        // Sign after reshare with all 2-of-5 subsets.
        let subsets: &[&[&str]] = &[
            &["peer-A", "peer-B"],
            &["peer-A", "peer-E"],
            &["peer-C", "peer-D"],
            &["peer-B", "peer-E"],
        ];
        for subset in subsets {
            let msg = b"5-party sign after reshare!!!!!!";
            let (r, z) = run_sign(subset, msg, &mut owned);
            verify_signature(&group_key, msg, &r, &z);
        }
    }
}
