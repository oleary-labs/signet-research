//! Reshare session state machine (secp256k1 only).
//!
//! Extracted from session.rs. Reshare uses k256 types directly for polynomial
//! arithmetic and Feldman verification, so it is not (yet) generic over
//! Ciphersuite. Ed25519 reshare support can be added later by abstracting the
//! curve operations behind frost_core::Group.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use sha2::Digest;
use tracing::debug;

use crate::reshare::{
    self, Polynomial, ReshareParams, ReshareR1Payload, ReshareR2Payload,
    ReshareR3Payload,
};
use crate::storage::{Storage, StoredKey};

use crate::types::{cbor_decode, cbor_encode, OutgoingMessage, ProcessError, SessionResult, StepOutput};

// ---------------------------------------------------------------------------
// Reshare state
// ---------------------------------------------------------------------------

pub(crate) enum ReshareState {
    R1 {
        session_id: String,
        params: ReshareParams,
        is_old: bool,
        is_new: bool,
        polynomial: Option<Polynomial>,
        chain_key: Option<Vec<u8>>,
        old_scalars: Vec<k256::Scalar>,
        new_scalars: Vec<k256::Scalar>,
        self_old_scalar: Option<k256::Scalar>,
        self_new_scalar: Option<k256::Scalar>,
        old_secret: Option<k256::Scalar>,
        group_key: Vec<u8>,
        generation: u64,
        r1_received: BTreeMap<String, ReshareR1Payload>,
        broadcast_sent: bool,
    },
    R2 {
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
        all_commitments: BTreeMap<String, Vec<k256::ProjectivePoint>>,
        chain_keys: Vec<(String, Vec<u8>)>,
        sub_shares: BTreeMap<String, k256::Scalar>,
    },
    R3 {
        session_id: String,
        params: ReshareParams,
        new_scalars: Vec<k256::Scalar>,
        self_new_scalar: k256::Scalar,
        group_key: Vec<u8>,
        generation: u64,
        new_secret: k256::Scalar,
        chain_keys: Vec<(String, Vec<u8>)>,
        pub_shares: BTreeMap<String, Vec<u8>>,
    },
    Completed,
}

// ---------------------------------------------------------------------------
// Reshare session (wraps state + pending buffer)
// ---------------------------------------------------------------------------

pub(crate) struct ReshareSession {
    state: ReshareState,
    pending: Vec<(String, String, Vec<u8>)>,
}

impl ReshareSession {
    pub fn state_name(&self) -> &'static str {
        match &self.state {
            ReshareState::R1 { .. } => "ReshareR1",
            ReshareState::R2 { .. } => "ReshareR2",
            ReshareState::R3 { .. } => "ReshareR3",
            ReshareState::Completed => "Completed",
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn start(
        session_id: &str,
        params: ReshareParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let (state, output) = start_reshare(session_id, params, storage)?;
        debug!(state = state_name(&state), "reshare session started");
        Ok((ReshareSession { state, pending: vec![] }, output))
    }

    pub fn process_message(
        &mut self,
        from: &str,
        to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        let prev_state = state_name(&self.state);
        let state = std::mem::replace(&mut self.state, ReshareState::Completed);
        let (new_state, output) = process_reshare(state, from, to, payload, storage);
        self.state = new_state;

        match output {
            Ok(step) => {
                debug!(
                    from,
                    prev_state,
                    new_state = state_name(&self.state),
                    outgoing = step.messages.len(),
                    has_result = step.result.is_some(),
                    "reshare message processed"
                );
                let mut combined = step;
                if !self.pending.is_empty() {
                    let pending = std::mem::take(&mut self.pending);
                    for (f, t, p) in pending {
                        let s = std::mem::replace(&mut self.state, ReshareState::Completed);
                        let (ns, result) = process_reshare(s, &f, &t, &p, storage);
                        self.state = ns;
                        match result {
                            Ok(more) => {
                                combined.messages.extend(more.messages);
                                if let Some(r) = more.result {
                                    combined.result = Some(r);
                                }
                            }
                            Err(ProcessError::WrongRound(_)) => {
                                self.pending.push((f, t, p));
                            }
                            Err(ProcessError::Invalid(e)) => {
                                debug!(error = e.as_str(), "pending reshare message dropped");
                            }
                        }
                    }
                }
                Ok(combined)
            }
            Err(ProcessError::WrongRound(_)) => {
                self.pending.push((from.to_string(), to.to_string(), payload.to_vec()));
                Ok(StepOutput { messages: vec![], result: None })
            }
            Err(ProcessError::Invalid(e)) => {
                debug!(from, error = e.as_str(), "reshare message dropped (invalid)");
                Ok(StepOutput { messages: vec![], result: None })
            }
        }
    }
}

fn state_name(state: &ReshareState) -> &'static str {
    match state {
        ReshareState::R1 { .. } => "ReshareR1",
        ReshareState::R2 { .. } => "ReshareR2",
        ReshareState::R3 { .. } => "ReshareR3",
        ReshareState::Completed => "Completed",
    }
}

// ---------------------------------------------------------------------------
// start_reshare
// ---------------------------------------------------------------------------

fn start_reshare(
    session_id: &str,
    params: ReshareParams,
    storage: &Storage,
) -> Result<(ReshareState, StepOutput), String> {
    let is_old = params.old_party_ids.contains(&params.party_id);
    let is_new = params.new_party_ids.contains(&params.party_id);
    if !is_old && !is_new {
        return Err(format!("party {} not in old or new sets", params.party_id));
    }

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

    let stored = storage.get_key(&params.group_id, &params.key_id)?;
    let (old_secret, group_key, generation) = if is_old {
        let s = stored.ok_or_else(|| {
            format!("reshare: old party has no key for {}/{}", params.group_id, params.key_id)
        })?;
        let kp = frost::keys::KeyPackage::deserialize(&s.key_package)
            .map_err(|e| format!("deserialize key package: {e}"))?;
        let secret_bytes = kp.signing_share().serialize();
        let secret = reshare::deserialize_scalar(&secret_bytes)
            .map_err(|e| format!("decode secret scalar: {e}"))?;
        (Some(secret), s.group_key, s.generation)
    } else {
        (None, vec![], 0)
    };

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
        rand::RngCore::fill_bytes(&mut rng, &mut ck);

        let payload = ReshareR1Payload {
            commitments: encoded_commitments,
            chain_key: ck.to_vec(),
            generation,
            group_key: group_key.clone(),
        };

        r1_received.insert(params.party_id.clone(), payload.clone());

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
        ReshareState::R1 {
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
            broadcast_sent: is_old,
        },
        StepOutput { messages, result: None },
    ))
}

// ---------------------------------------------------------------------------
// process_reshare (consuming state machine)
// ---------------------------------------------------------------------------

fn process_reshare(
    state: ReshareState,
    from: &str,
    _to: &str,
    payload: &[u8],
    storage: &Storage,
) -> (ReshareState, Result<StepOutput, ProcessError>) {
    match state {
        // ---- Round 1 ----
        ReshareState::R1 {
            session_id, params, is_old, is_new, polynomial, chain_key,
            old_scalars, new_scalars, self_old_scalar, self_new_scalar,
            old_secret, group_key, generation, mut r1_received, broadcast_sent,
        } => {
            let r1: ReshareR1Payload = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        ReshareState::R1 {
                            session_id, params, is_old, is_new, polynomial, chain_key,
                            old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                            old_secret, group_key, generation, r1_received, broadcast_sent,
                        },
                        Err(ProcessError::WrongRound(e)),
                    );
                }
            };

            if !params.old_party_ids.contains(&from.to_string()) {
                return (
                    ReshareState::R1 {
                        session_id, params, is_old, is_new, polynomial, chain_key,
                        old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                        old_secret, group_key, generation, r1_received, broadcast_sent,
                    },
                    Err(ProcessError::Invalid(format!("R1 from non-old party: {from}"))),
                );
            }
            if r1_received.contains_key(from) {
                return (
                    ReshareState::R1 {
                        session_id, params, is_old, is_new, polynomial, chain_key,
                        old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                        old_secret, group_key, generation, r1_received, broadcast_sent,
                    },
                    Err(ProcessError::Invalid(format!("duplicate R1 from {from}"))),
                );
            }
            r1_received.insert(from.to_string(), r1);

            if r1_received.len() < params.old_party_ids.len() {
                return (
                    ReshareState::R1 {
                        session_id, params, is_old, is_new, polynomial, chain_key,
                        old_scalars, new_scalars, self_old_scalar, self_new_scalar,
                        old_secret, group_key, generation, r1_received, broadcast_sent,
                    },
                    Ok(StepOutput { messages: vec![], result: None }),
                );
            }

            let resolved_group_key = if group_key.is_empty() {
                r1_received.values().next().unwrap().group_key.clone()
            } else {
                group_key
            };
            let resolved_generation = if generation == 0 && !is_old {
                r1_received.values().next().unwrap().generation
            } else {
                generation
            };

            for (pid, r1) in &r1_received {
                if r1.group_key != resolved_group_key {
                    return (
                        ReshareState::Completed,
                        Err(ProcessError::Invalid(format!("group key mismatch from {pid}"))),
                    );
                }
            }

            let mut all_commitments: BTreeMap<String, Vec<k256::ProjectivePoint>> = BTreeMap::new();
            for (pid, r1) in &r1_received {
                let mut points = Vec::new();
                for raw in &r1.commitments {
                    match reshare::deserialize_point(raw) {
                        Ok(p) => points.push(p),
                        Err(e) => return (
                            ReshareState::Completed,
                            Err(ProcessError::Invalid(format!("bad commitment from {pid}: {e}"))),
                        ),
                    }
                }
                all_commitments.insert(pid.clone(), points);
            }

            let group_key_point = match reshare::deserialize_point(&resolved_group_key) {
                Ok(p) => p,
                Err(e) => return (
                    ReshareState::Completed,
                    Err(ProcessError::Invalid(format!("bad group key: {e}"))),
                ),
            };
            let mut commit_sum = k256::ProjectivePoint::IDENTITY;
            for (_, commits) in &all_commitments {
                commit_sum = commit_sum + commits[0];
            }
            if commit_sum != group_key_point {
                return (
                    ReshareState::Completed,
                    Err(ProcessError::Invalid("commitment constants don't sum to group key".into())),
                );
            }

            let mut sorted_chain_keys: Vec<(String, Vec<u8>)> = r1_received
                .iter()
                .map(|(pid, r1)| (pid.clone(), r1.chain_key.clone()))
                .collect();
            sorted_chain_keys.sort_by(|a, b| a.0.cmp(&b.0));

            let mut messages = Vec::new();
            if is_old {
                let poly = polynomial.as_ref().unwrap();
                for (i, new_pid) in params.new_party_ids.iter().enumerate() {
                    if *new_pid == params.party_id {
                        continue;
                    }
                    let sub_share = poly.evaluate(&new_scalars[i]);
                    let r2_payload = ReshareR2Payload {
                        sub_share: reshare::serialize_scalar(&sub_share),
                    };
                    let data = match cbor_encode(&r2_payload) {
                        Ok(d) => d,
                        Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(e))),
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
                ReshareState::R2 {
                    session_id, params, is_old, is_new, polynomial,
                    old_scalars, new_scalars, self_new_scalar,
                    group_key: resolved_group_key,
                    generation: resolved_generation,
                    all_commitments,
                    chain_keys: sorted_chain_keys,
                    sub_shares: BTreeMap::new(),
                },
                Ok(StepOutput { messages, result: None }),
            )
        }

        // ---- Round 2 ----
        ReshareState::R2 {
            session_id, params, is_old, is_new, polynomial,
            old_scalars, new_scalars, self_new_scalar,
            group_key, generation, all_commitments, chain_keys, mut sub_shares,
        } => {
            let r2: ReshareR2Payload = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        ReshareState::R2 {
                            session_id, params, is_old, is_new, polynomial,
                            old_scalars, new_scalars, self_new_scalar,
                            group_key, generation, all_commitments, chain_keys, sub_shares,
                        },
                        Err(ProcessError::WrongRound(e)),
                    );
                }
            };

            if !params.old_party_ids.contains(&from.to_string()) {
                return (
                    ReshareState::R2 {
                        session_id, params, is_old, is_new, polynomial,
                        old_scalars, new_scalars, self_new_scalar,
                        group_key, generation, all_commitments, chain_keys, sub_shares,
                    },
                    Err(ProcessError::Invalid(format!("R2 from non-old party: {from}"))),
                );
            }
            if sub_shares.contains_key(from) {
                return (
                    ReshareState::R2 {
                        session_id, params, is_old, is_new, polynomial,
                        old_scalars, new_scalars, self_new_scalar,
                        group_key, generation, all_commitments, chain_keys, sub_shares,
                    },
                    Err(ProcessError::Invalid(format!("duplicate R2 from {from}"))),
                );
            }

            let sub_share = match reshare::deserialize_scalar(&r2.sub_share) {
                Ok(s) => s,
                Err(e) => return (
                    ReshareState::Completed,
                    Err(ProcessError::Invalid(format!("bad sub-share from {from}: {e}"))),
                ),
            };

            let self_scalar = self_new_scalar.unwrap();
            let commitments = &all_commitments[from];
            if !reshare::verify_feldman(&self_scalar, &sub_share, commitments) {
                return (
                    ReshareState::Completed,
                    Err(ProcessError::Invalid(format!("Feldman verification failed for {from}"))),
                );
            }

            sub_shares.insert(from.to_string(), sub_share);

            if is_old && !sub_shares.contains_key(&params.party_id) {
                let poly = polynomial.as_ref().unwrap();
                let own_share = poly.evaluate(&self_scalar);
                sub_shares.insert(params.party_id.clone(), own_share);
            }

            if sub_shares.len() < params.old_party_ids.len() {
                return (
                    ReshareState::R2 {
                        session_id, params, is_old, is_new, polynomial,
                        old_scalars, new_scalars, self_new_scalar,
                        group_key, generation, all_commitments, chain_keys, sub_shares,
                    },
                    Ok(StepOutput { messages: vec![], result: None }),
                );
            }

            if is_new {
                let mut new_secret = k256::Scalar::ZERO;
                for (_, share) in &sub_shares {
                    new_secret = new_secret + share;
                }

                let verifying_share = k256::ProjectivePoint::GENERATOR * &new_secret;
                let vs_bytes = reshare::serialize_point(&verifying_share);

                let r3_payload = ReshareR3Payload {
                    verifying_share: vs_bytes.clone(),
                };
                let data = match cbor_encode(&r3_payload) {
                    Ok(d) => d,
                    Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(e))),
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
                    ReshareState::R3 {
                        session_id, params, new_scalars,
                        self_new_scalar: self_scalar,
                        group_key, generation, new_secret, chain_keys, pub_shares,
                    },
                    Ok(StepOutput { messages, result: None }),
                )
            } else {
                (
                    ReshareState::Completed,
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

        // ---- Round 3 ----
        ReshareState::R3 {
            session_id, params, new_scalars, self_new_scalar,
            group_key, generation, new_secret, chain_keys, mut pub_shares,
        } => {
            let r3: ReshareR3Payload = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        ReshareState::R3 {
                            session_id, params, new_scalars, self_new_scalar,
                            group_key, generation, new_secret, chain_keys, pub_shares,
                        },
                        Err(ProcessError::WrongRound(e)),
                    );
                }
            };

            if !params.new_party_ids.contains(&from.to_string()) {
                return (
                    ReshareState::R3 {
                        session_id, params, new_scalars, self_new_scalar,
                        group_key, generation, new_secret, chain_keys, pub_shares,
                    },
                    Err(ProcessError::Invalid(format!("R3 from non-new party: {from}"))),
                );
            }
            if pub_shares.contains_key(from) {
                return (
                    ReshareState::R3 {
                        session_id, params, new_scalars, self_new_scalar,
                        group_key, generation, new_secret, chain_keys, pub_shares,
                    },
                    Err(ProcessError::Invalid(format!("duplicate R3 from {from}"))),
                );
            }
            pub_shares.insert(from.to_string(), r3.verifying_share);

            if pub_shares.len() < params.new_party_ids.len() {
                return (
                    ReshareState::R3 {
                        session_id, params, new_scalars, self_new_scalar,
                        group_key, generation, new_secret, chain_keys, pub_shares,
                    },
                    Ok(StepOutput { messages: vec![], result: None }),
                );
            }

            let (_combined_chain_key, _rid) = reshare::combine_chain_keys(&chain_keys);

            let self_verifying_share = k256::ProjectivePoint::GENERATOR * &new_secret;
            let vs_bytes = reshare::serialize_point(&self_verifying_share);

            let self_frost_id = frost::Identifier::derive(params.party_id.as_bytes())
                .map_err(|e| format!("derive frost id: {e}"));
            let self_frost_id = match self_frost_id {
                Ok(id) => id,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(e))),
            };

            let mut frost_verifying_shares = BTreeMap::new();
            for (pid, share_bytes) in &pub_shares {
                let fid = match frost::Identifier::derive(pid.as_bytes()) {
                    Ok(id) => id,
                    Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("derive id for {pid}: {e}")))),
                };
                let vs_array: [u8; 33] = match share_bytes.clone().try_into() {
                    Ok(a) => a,
                    Err(_) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("verifying share for {pid} must be 33 bytes")))),
                };
                let vs = match frost::keys::VerifyingShare::deserialize(&vs_array) {
                    Ok(v) => v,
                    Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("deserialize verifying share for {pid}: {e}")))),
                };
                frost_verifying_shares.insert(fid, vs);
            }

            let gk_array: [u8; 33] = match group_key.clone().try_into() {
                Ok(a) => a,
                Err(_) => return (ReshareState::Completed, Err(ProcessError::Invalid("group key must be 33 bytes".into()))),
            };
            let group_verifying_key = match frost::VerifyingKey::deserialize(&gk_array) {
                Ok(v) => v,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("deserialize group key: {e}")))),
            };

            let ss_bytes: [u8; 32] = reshare::serialize_scalar(&new_secret).try_into().unwrap();
            let signing_share = match frost::keys::SigningShare::deserialize(&ss_bytes) {
                Ok(s) => s,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("build signing share: {e}")))),
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
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("serialize key package: {e}")))),
            };
            let pkp_bytes = match pub_key_package.serialize() {
                Ok(b) => b,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("serialize pub key package: {e}")))),
            };

            let stored = StoredKey {
                key_package: kp_bytes.clone(),
                public_key_package: pkp_bytes.clone(),
                group_key: group_key.clone(),
                verifying_share: vs_bytes.clone(),
                generation: generation + 1,
            };
            debug!(
                key_id = params.key_id.as_str(),
                kp_len = kp_bytes.len(),
                pkp_len = pkp_bytes.len(),
                kp_hash = %hex::encode(&sha2::Sha256::digest(&kp_bytes)[..8]),
                pkp_hash = %hex::encode(&sha2::Sha256::digest(&pkp_bytes)[..8]),
                "reshare: storing pending key"
            );
            if let Err(e) = storage.put_pending(&params.group_id, &params.key_id, &stored) {
                return (ReshareState::Completed, Err(ProcessError::Invalid(format!("persist pending reshare: {e}"))));
            }

            (
                ReshareState::Completed,
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

        ReshareState::Completed => {
            (ReshareState::Completed, Err(ProcessError::Invalid("session already completed".into())))
        }
    }
}
