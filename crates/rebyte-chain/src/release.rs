// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fresh, signed witness sessions for threshold content-key release.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::{
    Deserializable as _, OpModeR, OpModeS, Serializable as _, single_shot_open, single_shot_seal,
};
use rebyte_contract::{PrincipalId, ReleasePolicy};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{
    decode_array, domain_hash, encode_base64, put_bytes_u32, put_u16, put_u32, put_u64,
};
use crate::envelope::{
    CapsuleEnvelope, ChainLimits, OpenedContent, decrypt_payload_with_cek, opened_content,
    unwrap_quorum_share,
};
use crate::identity::{ChainKem, HpkePublicKey};
use crate::secret_sharing::{SHARE_BYTES, combine_shares};
use crate::{ChainError, IdentityId, IdentityPublicDocument, UnlockedIdentity};

const DOCUMENT_VERSION: u16 = 1;
const REQUEST_KIND: &str = "rebyte-chain-release-request";
const GRANT_KIND: &str = "rebyte-chain-release-grant";
const REQUEST_SIGNATURE_DOMAIN: &[u8] = b"rebyte chain release request signature v1\0";
const GRANT_SIGNATURE_DOMAIN: &[u8] = b"rebyte chain release grant signature v1\0";
const GRANT_HPKE_INFO_DOMAIN: &[u8] = b"rebyte chain release grant hpke v1\0";
const REQUEST_ID_CONTEXT: &str = "Rebyte Chain release request id v1 2026-07-18";
const GRANT_ID_CONTEXT: &str = "Rebyte Chain release grant id v1 2026-07-18";
const GRANT_CORE_CONTEXT: &str = "Rebyte Chain release grant core v1 2026-07-18";
const HPKE_ENCAPPED_KEY_BYTES: usize = 32;
const HPKE_WRAPPED_SHARE_BYTES: usize = SHARE_BYTES + 16;
type ReleaseScope = ([u8; 32], [u8; 32]);
type ReleaseRequests = BTreeMap<ReleaseScope, Vec<[u8; 32]>>;

/// Fresh recipient-authenticated request for one quorum release session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseRequest {
    schema_version: u16,
    kind: String,
    envelope_id: String,
    proposal_id: String,
    contract_id: String,
    recipient: IdentityPublicDocument,
    request_nonce: String,
    request_id: String,
    signature: String,
}

impl ReleaseRequest {
    /// Parses and verifies canonical request JSON and its recipient signature.
    ///
    /// Envelope and contract bindings are checked when the request is granted
    /// or opened.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, non-canonical or invalidly signed
    /// data.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        request.validate_shape()?;
        if request.to_json()?.as_slice() != bytes {
            return Err(ChainError::InvalidDocument);
        }
        Ok(request)
    }

    /// Serializes canonical pretty JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the in-memory request is inconsistent.
    pub fn to_json(&self) -> Result<Vec<u8>, ChainError> {
        self.validate_shape()?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| ChainError::InvalidDocument)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns the stable identifier of this fresh request.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed canonical encoding.
    pub fn request_id(&self) -> Result<[u8; 32], ChainError> {
        self.validate_shape()?;
        decode_array(&self.request_id)
    }

    /// Returns the requesting public identity.
    #[must_use]
    pub const fn recipient(&self) -> &IdentityPublicDocument {
        &self.recipient
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != REQUEST_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        self.recipient.validate()?;
        let _envelope_id: [u8; 32] = decode_array(&self.envelope_id)?;
        let _proposal_id: [u8; 32] = decode_array(&self.proposal_id)?;
        let _contract_id: [u8; 32] = decode_array(&self.contract_id)?;
        let _nonce: [u8; 32] = decode_array(&self.request_nonce)?;
        let request_id: [u8; 32] = decode_array(&self.request_id)?;
        let signature: [u8; 64] = decode_array(&self.signature)?;
        let message = request_message(self)?;
        let verifying_key = VerifyingKey::from_bytes(&self.recipient.signing_public_key()?)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        verifying_key
            .verify(&message, &Signature::from_bytes(&signature))
            .map_err(|_| ChainError::InvalidSignature)?;
        if calculate_request_id(&message, &signature) != request_id {
            return Err(ChainError::InvalidRelease);
        }
        Ok(())
    }
}

/// One witness's signed and recipient-encrypted threshold share.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseGrant {
    schema_version: u16,
    kind: String,
    request_id: String,
    envelope_id: String,
    witness: IdentityPublicDocument,
    observed_unix_ms: u64,
    release_ordinal: u32,
    encapped_key: String,
    wrapped_share: String,
    grant_id: String,
    signature: String,
}

impl ReleaseGrant {
    /// Parses and verifies canonical grant JSON and its witness signature.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, non-canonical or invalidly signed
    /// data.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let grant: Self = serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        grant.validate_shape()?;
        if grant.to_json()?.as_slice() != bytes {
            return Err(ChainError::InvalidDocument);
        }
        Ok(grant)
    }

    /// Serializes canonical pretty JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the in-memory grant is inconsistent.
    pub fn to_json(&self) -> Result<Vec<u8>, ChainError> {
        self.validate_shape()?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| ChainError::InvalidDocument)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns the granting witness.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed identity encoding.
    pub fn witness_id(&self) -> Result<IdentityId, ChainError> {
        self.validate_shape()?;
        self.witness.identity_id()
    }

    /// Returns the witness-observed release time.
    #[must_use]
    pub const fn observed_unix_ms(&self) -> u64 {
        self.observed_unix_ms
    }

    /// Returns this request's ledger ordinal.
    #[must_use]
    pub const fn release_ordinal(&self) -> u32 {
        self.release_ordinal
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION
            || self.kind != GRANT_KIND
            || self.release_ordinal == 0
        {
            return Err(ChainError::UnsupportedDocument);
        }
        self.witness.validate()?;
        let _request_id: [u8; 32] = decode_array(&self.request_id)?;
        let _envelope_id: [u8; 32] = decode_array(&self.envelope_id)?;
        let encapped_key: [u8; HPKE_ENCAPPED_KEY_BYTES] = decode_array(&self.encapped_key)?;
        let wrapped_share: [u8; HPKE_WRAPPED_SHARE_BYTES] = decode_array(&self.wrapped_share)?;
        let grant_id: [u8; 32] = decode_array(&self.grant_id)?;
        let signature: [u8; 64] = decode_array(&self.signature)?;
        let core = grant_core(self)?;
        if calculate_grant_id(&core, &encapped_key, &wrapped_share) != grant_id {
            return Err(ChainError::InvalidRelease);
        }
        let witness_id = self.witness.identity_id()?;
        let verifying_key = VerifyingKey::from_bytes(&self.witness.signing_public_key()?)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        verifying_key
            .verify(
                &grant_signature_message(&grant_id, &witness_id),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| ChainError::InvalidSignature)
    }
}

/// Trusted time source used by a witness release authority.
///
/// Production implementations must resist rollback relative to the threat
/// model. A recipient's ordinary wall clock is not sufficient.
pub trait TrustedClock {
    /// Returns current Unix Epoch milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ReleaseAuthorityUnavailable`] when no trustworthy
    /// time decision can be made.
    fn now_unix_ms(&self) -> Result<u64, ChainError>;
}

/// Atomic durable state required for bounded release sessions.
pub trait ReleaseLedger {
    /// Authorizes or idempotently replays one exact request.
    ///
    /// Implementations must atomically persist a new request before returning.
    /// The returned ordinal starts at one. A repeated request ID must return
    /// its original ordinal without consuming another allowance.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ReleaseLimitReached`] when no new session remains,
    /// or [`ChainError::ReleaseAuthorityUnavailable`] if durable state cannot
    /// be read or committed.
    fn authorize(&mut self, authorization: &ReleaseAuthorization) -> Result<u32, ChainError>;
}

/// Exact ledger scope and allowance for one release decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseAuthorization {
    contract_id: [u8; 32],
    proposal_id: [u8; 32],
    request_id: [u8; 32],
    maximum_successful_releases: Option<u32>,
}

impl ReleaseAuthorization {
    /// Creates an exact ledger decision from verified protocol identifiers.
    ///
    /// Most callers receive this value through [`ReleaseLedger::authorize`];
    /// this constructor supports durable-ledger restoration and testing.
    #[must_use]
    pub const fn from_parts(
        contract_id: [u8; 32],
        proposal_id: [u8; 32],
        request_id: [u8; 32],
        maximum_successful_releases: Option<u32>,
    ) -> Self {
        Self {
            contract_id,
            proposal_id,
            request_id,
            maximum_successful_releases,
        }
    }

    /// Returns the contract ledger scope.
    #[must_use]
    pub const fn contract_id(&self) -> &[u8; 32] {
        &self.contract_id
    }

    /// Returns the proposal ledger scope.
    #[must_use]
    pub const fn proposal_id(&self) -> &[u8; 32] {
        &self.proposal_id
    }

    /// Returns the fresh request being authorized.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 32] {
        &self.request_id
    }

    /// Returns the contract's maximum distinct sessions.
    #[must_use]
    pub const fn maximum_successful_releases(&self) -> Option<u32> {
        self.maximum_successful_releases
    }
}

/// Volatile ledger useful for tests and single-process cooperative tools.
///
/// It is not rollback-resistant and therefore is not a production authority
/// for usage-limited contracts.
#[derive(Debug, Default)]
pub struct MemoryReleaseLedger {
    requests: ReleaseRequests,
}

impl ReleaseLedger for MemoryReleaseLedger {
    fn authorize(&mut self, authorization: &ReleaseAuthorization) -> Result<u32, ChainError> {
        let requests = self
            .requests
            .entry((authorization.contract_id, authorization.proposal_id))
            .or_default();
        if let Some(index) = requests
            .iter()
            .position(|request| request == &authorization.request_id)
        {
            return u32::try_from(index.saturating_add(1))
                .map_err(|_| ChainError::ReleaseAuthorityUnavailable);
        }
        let current =
            u32::try_from(requests.len()).map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        if authorization
            .maximum_successful_releases
            .is_some_and(|maximum| current >= maximum)
        {
            return Err(ChainError::ReleaseLimitReached);
        }
        requests.push(authorization.request_id);
        u32::try_from(requests.len()).map_err(|_| ChainError::ReleaseAuthorityUnavailable)
    }
}

/// Creates a fresh signed opening request for an authorized recipient.
///
/// # Errors
///
/// Returns [`ChainError`] unless the envelope uses quorum release and the
/// identity is a listed recipient.
pub fn create_release_request(
    envelope: &CapsuleEnvelope,
    recipient: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<ReleaseRequest, ChainError> {
    envelope.validate(limits)?;
    let ReleasePolicy::Quorum(_) = envelope.proposal().contract().release() else {
        return Err(ChainError::UnsupportedReleasePolicy);
    };
    let recipient_id = recipient.identity_id();
    if !envelope
        .proposal()
        .contract()
        .recipients()
        .contains(&principal_id(recipient_id))
    {
        return Err(ChainError::NotRecipient);
    }
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ChainError::EntropyUnavailable)?;
    let mut request = ReleaseRequest {
        schema_version: DOCUMENT_VERSION,
        kind: REQUEST_KIND.to_string(),
        envelope_id: encode_base64(envelope.envelope_id()),
        proposal_id: encode_base64(envelope.proposal().proposal_id()),
        contract_id: envelope.proposal().contract().contract_id().to_base64(),
        recipient: recipient.public_identity().clone(),
        request_nonce: encode_base64(&nonce),
        request_id: encode_base64(&[0; 32]),
        signature: encode_base64(&[0; 64]),
    };
    let message = request_message(&request)?;
    let signature = recipient.sign(&message);
    request.request_id = encode_base64(&calculate_request_id(&message, &signature));
    request.signature = encode_base64(&signature);
    request.validate_shape()?;
    Ok(request)
}

/// Releases one witness share into a fresh recipient-authenticated session.
///
/// The witness first validates the envelope and request, checks trusted time,
/// unwraps only its own share and atomically records the release decision.
///
/// # Errors
///
/// Returns [`ChainError`] for an invalid request/witness, unmet time, exhausted
/// allowance, unavailable authority state or cryptographic failure.
pub fn grant_release(
    envelope: &CapsuleEnvelope,
    request: &ReleaseRequest,
    witness: &UnlockedIdentity,
    clock: &impl TrustedClock,
    ledger: &mut impl ReleaseLedger,
    limits: &ChainLimits,
) -> Result<ReleaseGrant, ChainError> {
    verify_request_binding(envelope, request, limits)?;
    let ReleasePolicy::Quorum(policy) = envelope.proposal().contract().release() else {
        return Err(ChainError::UnsupportedReleasePolicy);
    };
    let witness_id = witness.identity_id();
    if !policy.witnesses().contains(&principal_id(witness_id)) {
        return Err(ChainError::NotWitness);
    }
    let observed_unix_ms = clock.now_unix_ms()?;
    if policy
        .not_before_unix_ms()
        .is_some_and(|not_before| observed_unix_ms < not_before)
    {
        return Err(ChainError::ReleaseNotYetAvailable);
    }
    let share = unwrap_quorum_share(envelope, witness, limits)?;
    let request_id = request.request_id()?;
    let authorization = ReleaseAuthorization {
        contract_id: *envelope.proposal().contract().contract_id().as_bytes(),
        proposal_id: *envelope.proposal().proposal_id(),
        request_id,
        maximum_successful_releases: policy.maximum_successful_releases(),
    };
    let release_ordinal = ledger.authorize(&authorization)?;
    let mut grant = ReleaseGrant {
        schema_version: DOCUMENT_VERSION,
        kind: GRANT_KIND.to_string(),
        request_id: encode_base64(&request_id),
        envelope_id: encode_base64(envelope.envelope_id()),
        witness: witness.public_identity().clone(),
        observed_unix_ms,
        release_ordinal,
        encapped_key: encode_base64(&[0; HPKE_ENCAPPED_KEY_BYTES]),
        wrapped_share: encode_base64(&[0; HPKE_WRAPPED_SHARE_BYTES]),
        grant_id: encode_base64(&[0; 32]),
        signature: encode_base64(&[0; 64]),
    };
    let core = grant_core(&grant)?;
    let core_digest = domain_hash(GRANT_CORE_CONTEXT, &[&core]);
    let recipient_public = HpkePublicKey::from_bytes(&request.recipient.encryption_public_key()?)
        .map_err(|_| ChainError::InvalidPublicKey)?;
    let (encapped_key, wrapped_share) =
        single_shot_seal::<HpkeChaCha20Poly1305, HkdfSha256, ChainKem>(
            &OpModeS::Base,
            &recipient_public,
            &grant_hpke_info(&core),
            share.as_ref(),
            &core_digest,
        )
        .map_err(|_| ChainError::CryptographicFailure)?;
    let encapped_key: [u8; HPKE_ENCAPPED_KEY_BYTES] = encapped_key
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::CryptographicFailure)?;
    let wrapped_share: [u8; HPKE_WRAPPED_SHARE_BYTES] = wrapped_share
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::CryptographicFailure)?;
    let grant_id = calculate_grant_id(&core, &encapped_key, &wrapped_share);
    grant.encapped_key = encode_base64(&encapped_key);
    grant.wrapped_share = encode_base64(&wrapped_share);
    grant.grant_id = encode_base64(&grant_id);
    grant.signature =
        encode_base64(&witness.sign(&grant_signature_message(&grant_id, &witness_id)));
    grant.validate_shape()?;
    Ok(grant)
}

/// Verifies a fresh quorum and opens its canonical protected content.
///
/// Exactly the configured threshold of unique grants must be supplied. An
/// invalid share can deny availability but cannot produce unauthenticated
/// plaintext because payload AEAD and content commitments are rechecked.
///
/// # Errors
///
/// Returns [`ChainError`] for an invalid request/grant/quorum, wrong recipient,
/// key reconstruction failure or protected-content verification failure.
pub fn open_quorum_content(
    envelope: &CapsuleEnvelope,
    request: &ReleaseRequest,
    grants: &[ReleaseGrant],
    recipient: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<OpenedContent, ChainError> {
    verify_request_binding(envelope, request, limits)?;
    if request.recipient.identity_id()? != recipient.identity_id() {
        return Err(ChainError::NotRecipient);
    }
    let ReleasePolicy::Quorum(policy) = envelope.proposal().contract().release() else {
        return Err(ChainError::UnsupportedReleasePolicy);
    };
    if grants.len() != usize::from(policy.threshold()) {
        return Err(ChainError::InsufficientApprovals);
    }
    let mut shares = Vec::with_capacity(grants.len());
    let mut witness_ids = Vec::with_capacity(grants.len());
    for grant in grants {
        let witness_id = verify_grant_binding(envelope, request, grant)?;
        if witness_ids.contains(&witness_id) {
            return Err(ChainError::DuplicateIdentity);
        }
        witness_ids.push(witness_id);
        let core = grant_core(grant)?;
        let core_digest = domain_hash(GRANT_CORE_CONTEXT, &[&core]);
        let encapped_key =
            <ChainKem as hpke::Kem>::EncappedKey::from_bytes(&decode_array::<
                HPKE_ENCAPPED_KEY_BYTES,
            >(&grant.encapped_key)?)
            .map_err(|_| ChainError::CryptographicFailure)?;
        let wrapped_share: [u8; HPKE_WRAPPED_SHARE_BYTES] = decode_array(&grant.wrapped_share)?;
        let share = Zeroizing::new(
            single_shot_open::<HpkeChaCha20Poly1305, HkdfSha256, ChainKem>(
                &OpModeR::Base,
                &recipient.hpke_private_key(),
                &encapped_key,
                &grant_hpke_info(&core),
                &wrapped_share,
                &core_digest,
            )
            .map_err(|_| ChainError::CryptographicFailure)?,
        );
        let share: [u8; SHARE_BYTES] = share
            .as_slice()
            .try_into()
            .map_err(|_| ChainError::InvalidShare)?;
        let expected_x = policy
            .witnesses()
            .iter()
            .position(|candidate| candidate == &principal_id(witness_id))
            .and_then(|index| u8::try_from(index.saturating_add(1)).ok())
            .ok_or(ChainError::InvalidShare)?;
        if share[0] != expected_x {
            return Err(ChainError::InvalidShare);
        }
        shares.push(share);
    }
    shares.sort_unstable_by_key(|share| share[0]);
    let threshold = u8::try_from(policy.threshold()).map_err(|_| ChainError::InvalidThreshold)?;
    let cek = combine_shares(&shares, threshold)?;
    let decrypted =
        decrypt_payload_with_cek(envelope, recipient.identity_id(), cek.as_ref(), limits)?;
    opened_content(decrypted)
}

fn verify_request_binding(
    envelope: &CapsuleEnvelope,
    request: &ReleaseRequest,
    limits: &ChainLimits,
) -> Result<(), ChainError> {
    envelope.validate(limits)?;
    request.validate_shape()?;
    let recipient_id = request.recipient.identity_id()?;
    if decode_array::<32>(&request.envelope_id)? != *envelope.envelope_id()
        || decode_array::<32>(&request.proposal_id)? != *envelope.proposal().proposal_id()
        || decode_array::<32>(&request.contract_id)?
            != *envelope.proposal().contract().contract_id().as_bytes()
        || !envelope
            .proposal()
            .contract()
            .recipients()
            .contains(&principal_id(recipient_id))
    {
        return Err(ChainError::InvalidRelease);
    }
    Ok(())
}

fn verify_grant_binding(
    envelope: &CapsuleEnvelope,
    request: &ReleaseRequest,
    grant: &ReleaseGrant,
) -> Result<IdentityId, ChainError> {
    grant.validate_shape()?;
    let witness_id = grant.witness.identity_id()?;
    let ReleasePolicy::Quorum(policy) = envelope.proposal().contract().release() else {
        return Err(ChainError::UnsupportedReleasePolicy);
    };
    if decode_array::<32>(&grant.request_id)? != request.request_id()?
        || decode_array::<32>(&grant.envelope_id)? != *envelope.envelope_id()
        || !policy.witnesses().contains(&principal_id(witness_id))
        || policy
            .not_before_unix_ms()
            .is_some_and(|not_before| grant.observed_unix_ms < not_before)
        || policy
            .maximum_successful_releases()
            .is_some_and(|maximum| grant.release_ordinal > maximum)
    {
        return Err(ChainError::InvalidRelease);
    }
    Ok(witness_id)
}

fn request_message(request: &ReleaseRequest) -> Result<Vec<u8>, ChainError> {
    let mut message = Vec::new();
    message.extend_from_slice(REQUEST_SIGNATURE_DOMAIN);
    put_u16(&mut message, DOCUMENT_VERSION);
    message.extend_from_slice(&decode_array::<32>(&request.envelope_id)?);
    message.extend_from_slice(&decode_array::<32>(&request.proposal_id)?);
    message.extend_from_slice(&decode_array::<32>(&request.contract_id)?);
    message.extend_from_slice(&decode_array::<32>(&request.request_nonce)?);
    put_bytes_u32(&mut message, &request.recipient.to_json()?)?;
    Ok(message)
}

fn calculate_request_id(message: &[u8], signature: &[u8; 64]) -> [u8; 32] {
    domain_hash(REQUEST_ID_CONTEXT, &[message, signature])
}

fn grant_core(grant: &ReleaseGrant) -> Result<Vec<u8>, ChainError> {
    let mut core = Vec::new();
    core.extend_from_slice(GRANT_SIGNATURE_DOMAIN);
    put_u16(&mut core, DOCUMENT_VERSION);
    core.extend_from_slice(&decode_array::<32>(&grant.request_id)?);
    core.extend_from_slice(&decode_array::<32>(&grant.envelope_id)?);
    core.extend_from_slice(grant.witness.identity_id()?.as_bytes());
    put_u64(&mut core, grant.observed_unix_ms);
    put_u32(&mut core, grant.release_ordinal);
    Ok(core)
}

fn calculate_grant_id(
    core: &[u8],
    encapped_key: &[u8; HPKE_ENCAPPED_KEY_BYTES],
    wrapped_share: &[u8; HPKE_WRAPPED_SHARE_BYTES],
) -> [u8; 32] {
    domain_hash(GRANT_ID_CONTEXT, &[core, encapped_key, wrapped_share])
}

fn grant_signature_message(grant_id: &[u8; 32], witness_id: &IdentityId) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        GRANT_SIGNATURE_DOMAIN
            .len()
            .saturating_add(grant_id.len())
            .saturating_add(witness_id.as_bytes().len()),
    );
    message.extend_from_slice(GRANT_SIGNATURE_DOMAIN);
    message.extend_from_slice(grant_id);
    message.extend_from_slice(witness_id.as_bytes());
    message
}

fn grant_hpke_info(core: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(GRANT_HPKE_INFO_DOMAIN.len().saturating_add(core.len()));
    info.extend_from_slice(GRANT_HPKE_INFO_DOMAIN);
    info.extend_from_slice(core);
    info
}

const fn principal_id(identity_id: IdentityId) -> PrincipalId {
    PrincipalId::from_bytes(*identity_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use rebyte_artifact_token::{Artifact, ArtifactOptions, encode_artifact};

    use super::{
        MemoryReleaseLedger, ReleaseAuthorization, ReleaseGrant, ReleaseLedger, TrustedClock,
        create_release_request, grant_release, open_quorum_content,
    };
    use crate::group::deterministic_group;
    use crate::identity::deterministic_identity;
    use crate::{
        CapsuleEnvelope, ChainError, ChainLimits, OpenedContent, QuorumProposalOptions,
        accept_group, approve_capsule, create_quorum_capsule_proposal, finalize_capsule,
        finalize_group,
    };

    struct FixedClock(u64);

    impl TrustedClock for FixedClock {
        fn now_unix_ms(&self) -> Result<u64, ChainError> {
            Ok(self.0)
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One expensive identity fixture covers all release boundaries.
    fn trusted_time_and_unanimous_single_release_gate_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let (alice_private, alice_public) = deterministic_identity(0x11, "Alice")?;
        let (bob_private, bob_public) = deterministic_identity(0x22, "Bob")?;
        let (reader_private, reader_public) = deterministic_identity(0x33, "Reader")?;
        let alice = alice_private.unlock(b"test-only-passphrase")?;
        let bob = bob_private.unlock(b"test-only-passphrase")?;
        let reader = reader_private.unlock(b"test-only-passphrase")?;
        let group_proposal =
            deterministic_group("Release witnesses", 2, vec![alice_public, bob_public])?;
        let alice_acceptance = accept_group(&group_proposal, &alice)?;
        let bob_acceptance = accept_group(&group_proposal, &bob)?;
        let group = finalize_group(group_proposal, vec![alice_acceptance, bob_acceptance])?;
        let artifact = Artifact::file(b"threshold secret".to_vec(), false);
        let artifact = encode_artifact(&artifact, &ArtifactOptions::default())?.into_binary();
        let limits = ChainLimits::STANDARD;
        let proposal = create_quorum_capsule_proposal(
            group,
            &artifact,
            vec![reader_public],
            vec![
                alice.public_identity().clone(),
                bob.public_identity().clone(),
            ],
            QuorumProposalOptions::new(2, Some(2_000), Some(1)),
            &limits,
        )?;
        let envelope = finalize_capsule(
            proposal.clone(),
            vec![
                approve_capsule(&proposal, &alice, &limits)?,
                approve_capsule(&proposal, &bob, &limits)?,
            ],
            &limits,
        )?;
        let envelope_bytes = envelope.to_bytes(&limits)?;
        for length in [0, 4, envelope_bytes.len().saturating_sub(1)] {
            assert!(CapsuleEnvelope::from_bytes(&envelope_bytes[..length], &limits).is_err());
        }
        let envelope = CapsuleEnvelope::from_bytes(&envelope_bytes, &limits)?;
        let request = create_release_request(&envelope, &reader, &limits)?;
        let mut alice_ledger = MemoryReleaseLedger::default();
        assert!(matches!(
            grant_release(
                &envelope,
                &request,
                &alice,
                &FixedClock(1_999),
                &mut alice_ledger,
                &limits
            ),
            Err(ChainError::ReleaseNotYetAvailable)
        ));
        let alice_grant = grant_release(
            &envelope,
            &request,
            &alice,
            &FixedClock(2_000),
            &mut alice_ledger,
            &limits,
        )?;
        let mut bob_ledger = MemoryReleaseLedger::default();
        let bob_grant = grant_release(
            &envelope,
            &request,
            &bob,
            &FixedClock(2_001),
            &mut bob_ledger,
            &limits,
        )?;
        assert!(matches!(
            open_quorum_content(
                &envelope,
                &request,
                core::slice::from_ref(&alice_grant),
                &reader,
                &limits
            ),
            Err(ChainError::InsufficientApprovals)
        ));
        assert!(matches!(
            open_quorum_content(
                &envelope,
                &request,
                &[alice_grant.clone(), alice_grant.clone()],
                &reader,
                &limits
            ),
            Err(ChainError::DuplicateIdentity)
        ));
        assert!(matches!(
            open_quorum_content(
                &envelope,
                &request,
                &[alice_grant.clone(), bob_grant.clone()],
                &alice,
                &limits
            ),
            Err(ChainError::NotRecipient)
        ));
        let opened = open_quorum_content(
            &envelope,
            &request,
            &[alice_grant.clone(), bob_grant.clone()],
            &reader,
            &limits,
        )?;
        let OpenedContent::ExactArtifact(opened) = opened else {
            return Err("unexpected protected content kind".into());
        };
        assert_eq!(opened.artifact_binary(), artifact);
        let replay = grant_release(
            &envelope,
            &request,
            &alice,
            &FixedClock(3_000),
            &mut alice_ledger,
            &limits,
        )?;
        assert_eq!(replay.release_ordinal(), alice_grant.release_ordinal());
        let mut mutated: serde_json::Value = serde_json::from_slice(&bob_grant.to_json()?)?;
        mutated["observedUnixMs"] = serde_json::json!(2_002);
        let mut mutated_grant = serde_json::to_vec_pretty(&mutated)?;
        mutated_grant.push(b'\n');
        assert!(ReleaseGrant::from_json(&mutated_grant).is_err());
        let second_request = create_release_request(&envelope, &reader, &limits)?;
        assert!(matches!(
            grant_release(
                &envelope,
                &second_request,
                &alice,
                &FixedClock(3_000),
                &mut alice_ledger,
                &limits
            ),
            Err(ChainError::ReleaseLimitReached)
        ));
        Ok(())
    }

    #[test]
    fn memory_ledger_is_idempotent_and_scoped() -> Result<(), Box<dyn std::error::Error>> {
        let mut ledger = MemoryReleaseLedger::default();
        let authorization = ReleaseAuthorization {
            contract_id: [1; 32],
            proposal_id: [2; 32],
            request_id: [3; 32],
            maximum_successful_releases: Some(1),
        };
        assert_eq!(ledger.authorize(&authorization)?, 1);
        assert_eq!(ledger.authorize(&authorization)?, 1);
        assert!(matches!(
            ledger.authorize(&ReleaseAuthorization {
                request_id: [4; 32],
                ..authorization
            }),
            Err(ChainError::ReleaseLimitReached)
        ));
        Ok(())
    }
}
