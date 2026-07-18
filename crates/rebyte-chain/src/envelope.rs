// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::redundant_pub_crate)]

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::{
    Deserializable as _, OpModeR, OpModeS, Serializable as _, single_shot_open, single_shot_seal,
};
use rebyte_artifact_token::decode_artifact;
use rebyte_contract::{
    AccessContract, Capabilities, Capability, ContentCommitment, ContentKind, ContractError,
    PrincipalId, ReleasePolicy,
};
use rebyte_format::SecurityLimits;
use rebyte_semantic::{MAX_PATCH_BYTES, SemanticPatch, parse_patch};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{
    Reader, decode_array, decode_base64, domain_hash, encode_base64, put_bytes_u32, put_u16,
    put_u64,
};
use crate::identity::{ChainKem, HpkePublicKey};
use crate::secret_sharing::{SHARE_BYTES, split_secret};
use crate::{
    ChainError, GroupCertificate, GroupId, IdentityId, IdentityPublicDocument, UnlockedIdentity,
};

/// Text prefix for Base64URL-encoded encrypted capsule envelopes.
pub const CAPSULE_TOKEN_PREFIX: &str = "rbe2_";

const PROPOSAL_MAGIC: &[u8; 4] = b"RBEP";
const ENVELOPE_MAGIC: &[u8; 4] = b"RBEE";
const WIRE_VERSION: u16 = 2;
const CRYPTO_SUITE: u16 = 1;
const APPROVAL_VERSION: u16 = 1;
const APPROVAL_KIND: &str = "rebyte-chain-capsule-approval";
const PAYLOAD_AAD_DOMAIN: &[u8] = b"rebyte chain payload aad v2\0";
const HPKE_INFO_DOMAIN: &[u8] = b"rebyte chain hpke cek slot v2\0";
const APPROVAL_DOMAIN: &[u8] = b"rebyte chain capsule approval v2\0";
const MAX_GROUP_DOCUMENT_BYTES: usize = 1_024 * 1_024;
const MAX_ACCESS_CONTRACT_BYTES: usize = 16 * 1_024;
const MAX_IDENTITY_DOCUMENT_BYTES: usize = 64 * 1_024;
const MAX_RECIPIENTS: usize = 64;
const HPKE_ENCAPPED_KEY_BYTES: usize = 32;
const CEK_BYTES: usize = 32;
const HPKE_TAG_BYTES: usize = 16;
const HPKE_WRAPPED_CEK_BYTES: usize = CEK_BYTES + HPKE_TAG_BYTES;
const HPKE_WRAPPED_SHARE_BYTES: usize = SHARE_BYTES + HPKE_TAG_BYTES;
const PAYLOAD_NONCE_BYTES: usize = 24;
const PAYLOAD_TAG_BYTES: usize = 16;

/// Resource policy for encrypted Chain artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChainLimits {
    /// Limits used while verifying the embedded `.rba` artifact.
    pub artifact: SecurityLimits,
    /// Maximum binary `.rbe` or proposal size.
    pub max_envelope_bytes: u64,
    /// Maximum textual `rbe2_` token size.
    pub max_token_bytes: u64,
}

impl ChainLimits {
    /// Standard in-memory Chain policy over simple Rebyte artifacts.
    pub const STANDARD: Self = Self {
        artifact: SecurityLimits::SIMPLE_ARTIFACT,
        max_envelope_bytes: 38 * 1_024 * 1_024,
        max_token_bytes: 52 * 1_024 * 1_024,
    };
}

impl Default for ChainLimits {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// Conditions for witness-mediated content-key release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuorumProposalOptions {
    /// Number of distinct witness grants needed to open.
    pub threshold: u16,
    /// Earliest trusted Unix Epoch time in milliseconds.
    pub not_before_unix_ms: Option<u64>,
    /// Maximum distinct successful release sessions.
    ///
    /// A finite limit requires unanimous witnesses.
    pub maximum_successful_releases: Option<u32>,
}

impl QuorumProposalOptions {
    /// Creates a witness release policy.
    #[must_use]
    pub const fn new(
        threshold: u16,
        not_before_unix_ms: Option<u64>,
        maximum_successful_releases: Option<u32>,
    ) -> Self {
        Self {
            threshold,
            not_before_unix_ms,
            maximum_successful_releases,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeySlot {
    holder: IdentityPublicDocument,
    encapped_key: [u8; HPKE_ENCAPPED_KEY_BYTES],
    wrapped_key: Vec<u8>,
}

/// Encrypted artifact proposal awaiting the group's capsule threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleProposal {
    group: GroupCertificate,
    contract: AccessContract,
    proposal_nonce: [u8; 32],
    content_digest: [u8; 32],
    content_size: u64,
    payload_nonce: [u8; PAYLOAD_NONCE_BYTES],
    slots: Vec<KeySlot>,
    ciphertext: Vec<u8>,
    proposal_id: [u8; 32],
}

impl CapsuleProposal {
    /// Parses and structurally verifies canonical proposal bytes.
    ///
    /// This does not decrypt the artifact and does not make the proposal an
    /// authorized capsule.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, oversized, non-canonical or
    /// cryptographically inconsistent bytes.
    pub fn from_bytes(bytes: &[u8], limits: &ChainLimits) -> Result<Self, ChainError> {
        enforce_length(bytes.len(), limits.max_envelope_bytes)?;
        let mut reader = Reader::new(bytes);
        if &reader.array::<4>()? != PROPOSAL_MAGIC
            || reader.u16()? != WIRE_VERSION
            || reader.u16()? != CRYPTO_SUITE
        {
            return Err(ChainError::UnsupportedDocument);
        }
        let group_bytes = reader.bytes_u32(MAX_GROUP_DOCUMENT_BYTES)?;
        let group = GroupCertificate::from_json(&group_bytes)?;
        let contract_bytes = reader.bytes_u32(MAX_ACCESS_CONTRACT_BYTES)?;
        let contract =
            AccessContract::from_bytes(&contract_bytes).map_err(|_| ChainError::InvalidContract)?;
        let proposal_nonce = reader.array()?;
        let content_digest = reader.array()?;
        let content_size = reader.u64()?;
        let payload_nonce = reader.array()?;
        let slot_count = usize::from(reader.u16()?);
        if slot_count == 0 || slot_count > MAX_RECIPIENTS {
            return Err(ChainError::LimitExceeded);
        }
        let wrapped_key_bytes = wrapped_key_bytes(contract.release());
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let identity_bytes = reader.bytes_u32(MAX_IDENTITY_DOCUMENT_BYTES)?;
            let holder = IdentityPublicDocument::from_json(&identity_bytes)?;
            slots.push(KeySlot {
                holder,
                encapped_key: reader.array()?,
                wrapped_key: reader.take(wrapped_key_bytes)?.to_vec(),
            });
        }
        let maximum_ciphertext = usize::try_from(limits.artifact.max_capsule_bytes)
            .map_err(|_| ChainError::LengthOverflow)?
            .checked_add(PAYLOAD_TAG_BYTES)
            .ok_or(ChainError::LengthOverflow)?;
        let ciphertext = reader.bytes_u32(maximum_ciphertext)?;
        let proposal_id = reader.array()?;
        reader.finish()?;
        let proposal = Self {
            group,
            contract,
            proposal_nonce,
            content_digest,
            content_size,
            payload_nonce,
            slots,
            ciphertext,
            proposal_id,
        };
        proposal.validate(limits)?;
        if proposal.to_bytes(limits)?.as_slice() != bytes {
            return Err(ChainError::NonCanonicalEnvelope);
        }
        Ok(proposal)
    }

    /// Serializes canonical binary proposal bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if any field is invalid or the result exceeds
    /// configured limits.
    pub fn to_bytes(&self, limits: &ChainLimits) -> Result<Vec<u8>, ChainError> {
        self.validate(limits)?;
        let group_bytes = self.group.to_json()?;
        if group_bytes.len() > MAX_GROUP_DOCUMENT_BYTES {
            return Err(ChainError::LimitExceeded);
        }
        let mut output = Vec::new();
        output.extend_from_slice(PROPOSAL_MAGIC);
        put_u16(&mut output, WIRE_VERSION);
        put_u16(&mut output, CRYPTO_SUITE);
        put_bytes_u32(&mut output, &group_bytes)?;
        put_bytes_u32(
            &mut output,
            &self
                .contract
                .to_bytes()
                .map_err(|_| ChainError::InvalidContract)?,
        )?;
        output.extend_from_slice(&self.proposal_nonce);
        output.extend_from_slice(&self.content_digest);
        put_u64(&mut output, self.content_size);
        output.extend_from_slice(&self.payload_nonce);
        put_u16(
            &mut output,
            u16::try_from(self.slots.len()).map_err(|_| ChainError::LengthOverflow)?,
        );
        for slot in &self.slots {
            put_bytes_u32(&mut output, &slot.holder.to_json()?)?;
            output.extend_from_slice(&slot.encapped_key);
            output.extend_from_slice(&slot.wrapped_key);
        }
        put_bytes_u32(&mut output, &self.ciphertext)?;
        output.extend_from_slice(&self.proposal_id);
        enforce_length(output.len(), limits.max_envelope_bytes)?;
        Ok(output)
    }

    /// Returns the group whose members may approve this proposal.
    #[must_use]
    pub const fn group(&self) -> &GroupCertificate {
        &self.group
    }

    /// Returns the canonical access contract approved by the group.
    #[must_use]
    pub const fn contract(&self) -> &AccessContract {
        &self.contract
    }

    /// Returns the proposal fingerprint signed by every approval.
    #[must_use]
    pub const fn proposal_id(&self) -> &[u8; 32] {
        &self.proposal_id
    }

    /// Returns the digest of the exact protected plaintext content.
    #[must_use]
    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// Returns the exact protected plaintext length.
    #[must_use]
    pub const fn content_size(&self) -> u64 {
        self.content_size
    }

    /// Returns identities holding a direct CEK or quorum key share.
    #[must_use]
    pub fn key_holders(&self) -> Vec<&IdentityPublicDocument> {
        self.slots.iter().map(|slot| &slot.holder).collect()
    }

    pub(super) fn validate(&self, limits: &ChainLimits) -> Result<(), ChainError> {
        self.group.validate()?;
        if self.slots.is_empty() || self.slots.len() > MAX_RECIPIENTS {
            return Err(ChainError::LimitExceeded);
        }
        if self.content_size > limits.artifact.max_capsule_bytes {
            return Err(ChainError::LimitExceeded);
        }
        if self.contract.content().kind() == ContentKind::SemanticPatch
            && self.content_size > MAX_PATCH_BYTES
        {
            return Err(ChainError::LimitExceeded);
        }
        let expected_ciphertext = usize::try_from(self.content_size)
            .map_err(|_| ChainError::LengthOverflow)?
            .checked_add(PAYLOAD_TAG_BYTES)
            .ok_or(ChainError::LengthOverflow)?;
        if self.ciphertext.len() != expected_ciphertext {
            return Err(ChainError::IntegrityMismatch);
        }
        let mut previous = None;
        for slot in &self.slots {
            slot.holder.validate()?;
            if slot.wrapped_key.len() != wrapped_key_bytes(self.contract.release()) {
                return Err(ChainError::IntegrityMismatch);
            }
            let identity_id = slot.holder.identity_id()?;
            if previous.is_some_and(|value| value >= identity_id) {
                return Err(if previous == Some(identity_id) {
                    ChainError::DuplicateIdentity
                } else {
                    ChainError::NonCanonicalOrder
                });
            }
            previous = Some(identity_id);
        }
        validate_contract_bindings(
            &self.group,
            &self.contract,
            &self.content_digest,
            self.content_size,
            &self
                .slots
                .iter()
                .map(|slot| slot.holder.identity_id())
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        if calculate_proposal_id(self)? != self.proposal_id {
            return Err(ChainError::BindingMismatch);
        }
        Ok(())
    }
}

/// One group member's approval of an exact encrypted capsule proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapsuleApproval {
    schema_version: u16,
    kind: String,
    group_id: String,
    proposal_id: String,
    member_id: String,
    signature: String,
}

impl CapsuleApproval {
    /// Parses canonical approval JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, unsupported or non-canonical data.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let document: Self =
            serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        document.validate_shape()?;
        if document.to_json()?.as_slice() != bytes {
            return Err(ChainError::InvalidDocument);
        }
        Ok(document)
    }

    /// Serializes stable canonical JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::InvalidDocument`] if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, ChainError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| ChainError::InvalidDocument)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns the approving group member.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed identity encoding.
    pub fn member_id(&self) -> Result<IdentityId, ChainError> {
        self.validate_shape()?;
        Ok(IdentityId(decode_array(&self.member_id)?))
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != APPROVAL_VERSION || self.kind != APPROVAL_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        let _group_id: [u8; 32] = decode_array(&self.group_id)?;
        let _proposal_id: [u8; 32] = decode_array(&self.proposal_id)?;
        let _member_id: [u8; 32] = decode_array(&self.member_id)?;
        let _signature: [u8; 64] = decode_array(&self.signature)?;
        Ok(())
    }
}

/// Threshold-authorized encrypted capsule ready for a listed recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleEnvelope {
    proposal: CapsuleProposal,
    approvals: Vec<CapsuleApproval>,
    envelope_id: [u8; 32],
}

impl CapsuleEnvelope {
    /// Parses and fully verifies a binary encrypted capsule.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed encoding, an invalid group,
    /// insufficient approvals, wrong signing keys or binding changes.
    pub fn from_bytes(bytes: &[u8], limits: &ChainLimits) -> Result<Self, ChainError> {
        enforce_length(bytes.len(), limits.max_envelope_bytes)?;
        let mut reader = Reader::new(bytes);
        if &reader.array::<4>()? != ENVELOPE_MAGIC
            || reader.u16()? != WIRE_VERSION
            || reader.u16()? != CRYPTO_SUITE
        {
            return Err(ChainError::UnsupportedDocument);
        }
        let proposal_bytes = reader.bytes_u32(
            usize::try_from(limits.max_envelope_bytes).map_err(|_| ChainError::LengthOverflow)?,
        )?;
        let proposal = CapsuleProposal::from_bytes(&proposal_bytes, limits)?;
        let approval_count = usize::from(reader.u16()?);
        if approval_count == 0 || approval_count > proposal.group.proposal().members().len() {
            return Err(ChainError::InsufficientApprovals);
        }
        let group_id = proposal.group.group_id()?;
        let proposal_id = proposal.proposal_id;
        let mut approvals = Vec::with_capacity(approval_count);
        for _ in 0..approval_count {
            approvals.push(CapsuleApproval {
                schema_version: APPROVAL_VERSION,
                kind: APPROVAL_KIND.to_string(),
                group_id: group_id.to_base64(),
                proposal_id: encode_base64(&proposal_id),
                member_id: encode_base64(&reader.array::<32>()?),
                signature: encode_base64(&reader.array::<64>()?),
            });
        }
        let envelope_id = reader.array()?;
        reader.finish()?;
        let envelope = Self {
            proposal,
            approvals,
            envelope_id,
        };
        envelope.validate(limits)?;
        if envelope.to_bytes(limits)?.as_slice() != bytes {
            return Err(ChainError::NonCanonicalEnvelope);
        }
        Ok(envelope)
    }

    /// Decodes and verifies a strict `rbe2_` Base64URL token.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for invalid text, excessive length or any
    /// envelope verification failure.
    pub fn from_token(token: &str, limits: &ChainLimits) -> Result<Self, ChainError> {
        enforce_length(token.len(), limits.max_token_bytes)?;
        let encoded = token
            .strip_prefix(CAPSULE_TOKEN_PREFIX)
            .ok_or(ChainError::InvalidEncoding)?;
        let bytes = decode_base64(encoded)?;
        Self::from_bytes(&bytes, limits)
    }

    /// Serializes a canonical binary `.rbe`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if validation or a length bound fails.
    pub fn to_bytes(&self, limits: &ChainLimits) -> Result<Vec<u8>, ChainError> {
        self.validate(limits)?;
        let proposal_bytes = self.proposal.to_bytes(limits)?;
        let mut output = Vec::new();
        output.extend_from_slice(ENVELOPE_MAGIC);
        put_u16(&mut output, WIRE_VERSION);
        put_u16(&mut output, CRYPTO_SUITE);
        put_bytes_u32(&mut output, &proposal_bytes)?;
        put_u16(
            &mut output,
            u16::try_from(self.approvals.len()).map_err(|_| ChainError::LengthOverflow)?,
        );
        for approval in &self.approvals {
            output.extend_from_slice(approval.member_id()?.as_bytes());
            output.extend_from_slice(&decode_array::<64>(&approval.signature)?);
        }
        output.extend_from_slice(&self.envelope_id);
        enforce_length(output.len(), limits.max_envelope_bytes)?;
        Ok(output)
    }

    /// Encodes the same bytes as strict unpadded Base64URL.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the token exceeds its configured bound.
    pub fn to_token(&self, limits: &ChainLimits) -> Result<String, ChainError> {
        let bytes = self.to_bytes(limits)?;
        let token = format!("{CAPSULE_TOKEN_PREFIX}{}", encode_base64(&bytes));
        enforce_length(token.len(), limits.max_token_bytes)?;
        Ok(token)
    }

    /// Returns the verified encrypted proposal.
    #[must_use]
    pub const fn proposal(&self) -> &CapsuleProposal {
        &self.proposal
    }

    /// Returns the verified member approvals.
    #[must_use]
    pub fn approvals(&self) -> &[CapsuleApproval] {
        &self.approvals
    }

    /// Returns the complete capsule identifier.
    #[must_use]
    pub const fn envelope_id(&self) -> &[u8; 32] {
        &self.envelope_id
    }

    pub(super) fn validate(&self, limits: &ChainLimits) -> Result<(), ChainError> {
        self.proposal.validate(limits)?;
        let threshold = usize::from(self.proposal.group.capsule_threshold());
        if self.approvals.len() < threshold
            || self.approvals.len() > self.proposal.group.proposal().members().len()
        {
            return Err(ChainError::InsufficientApprovals);
        }
        let mut previous = None;
        for approval in &self.approvals {
            let member_id = approval.member_id()?;
            if previous.is_some_and(|value| value >= member_id) {
                return Err(if previous == Some(member_id) {
                    ChainError::DuplicateIdentity
                } else {
                    ChainError::NonCanonicalOrder
                });
            }
            verify_capsule_approval(&self.proposal, approval)?;
            previous = Some(member_id);
        }
        if calculate_envelope_id(&self.proposal, &self.approvals)? != self.envelope_id {
            return Err(ChainError::BindingMismatch);
        }
        Ok(())
    }
}

/// Successfully decrypted, digest-checked and artifact-verified capsule bytes.
#[derive(Clone)]
pub struct OpenedCapsule {
    artifact_binary: Vec<u8>,
    contract_id: rebyte_contract::ContractId,
    group_id: GroupId,
    proposal_id: [u8; 32],
    recipient_id: IdentityId,
}

/// Successfully decrypted, contract-bound and canonical semantic patch.
#[derive(Clone, PartialEq)]
pub struct OpenedSemanticPatch {
    patch: SemanticPatch,
    contract_id: rebyte_contract::ContractId,
    group_id: GroupId,
    proposal_id: [u8; 32],
    recipient_id: IdentityId,
}

impl OpenedSemanticPatch {
    /// Returns the validated semantic patch.
    #[must_use]
    pub const fn patch(&self) -> &SemanticPatch {
        &self.patch
    }

    /// Returns the contract that authorized patch decryption.
    #[must_use]
    pub const fn contract_id(&self) -> rebyte_contract::ContractId {
        self.contract_id
    }

    /// Returns the authorizing group.
    #[must_use]
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// Returns the authorized encrypted proposal.
    #[must_use]
    pub const fn proposal_id(&self) -> &[u8; 32] {
        &self.proposal_id
    }

    /// Returns the recipient identity used to decrypt the patch.
    #[must_use]
    pub const fn recipient_id(&self) -> IdentityId {
        self.recipient_id
    }
}

impl core::fmt::Debug for OpenedSemanticPatch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenedSemanticPatch")
            .field("patch", &"[REDACTED]")
            .field("contract_id", &self.contract_id)
            .field("group_id", &self.group_id)
            .field("proposal_id", &self.proposal_id)
            .field("recipient_id", &self.recipient_id)
            .finish()
    }
}

/// Fully authenticated content released by a direct or quorum policy.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum OpenedContent {
    /// Canonical byte-exact `.rba` content.
    ExactArtifact(OpenedCapsule),
    /// Canonical bounded semantic patch.
    SemanticPatch(OpenedSemanticPatch),
}

pub(super) struct DecryptedContent {
    bytes: Vec<u8>,
    content_kind: ContentKind,
    contract_id: rebyte_contract::ContractId,
    group_id: GroupId,
    proposal_id: [u8; 32],
    recipient_id: IdentityId,
}

impl core::fmt::Debug for OpenedCapsule {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenedCapsule")
            .field("artifact_binary", &"[REDACTED]")
            .field("artifact_bytes", &self.artifact_binary.len())
            .field("contract_id", &self.contract_id)
            .field("group_id", &self.group_id)
            .field("proposal_id", &self.proposal_id)
            .field("recipient_id", &self.recipient_id)
            .finish()
    }
}

impl OpenedCapsule {
    /// Returns exact canonical `.rba` bytes.
    #[must_use]
    pub fn artifact_binary(&self) -> &[u8] {
        &self.artifact_binary
    }

    /// Consumes the report and returns exact `.rba` bytes.
    #[must_use]
    pub fn into_artifact_binary(self) -> Vec<u8> {
        self.artifact_binary
    }

    /// Returns the exact access contract that authorized decryption.
    #[must_use]
    pub const fn contract_id(&self) -> rebyte_contract::ContractId {
        self.contract_id
    }

    /// Returns the authorizing group.
    #[must_use]
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// Returns the authorized encrypted proposal.
    #[must_use]
    pub const fn proposal_id(&self) -> &[u8; 32] {
        &self.proposal_id
    }

    /// Returns the recipient identity used to open the capsule.
    #[must_use]
    pub const fn recipient_id(&self) -> IdentityId {
        self.recipient_id
    }
}

/// Encrypts one verified `.rba` once and wraps its random CEK for every
/// explicitly listed recipient.
///
/// # Errors
///
/// Returns [`ChainError`] for an invalid group/artifact/recipient, duplicate
/// recipient, limit violation, unavailable entropy or encryption failure.
pub fn create_capsule_proposal(
    group: GroupCertificate,
    artifact_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    create_default_content_proposal(
        group,
        artifact_binary,
        recipients,
        ContentKind::ExactArtifact,
        Capabilities::APPLY_EXACT,
        limits,
    )
}

/// Encrypts one canonical semantic patch for explicit recipients.
///
/// # Errors
///
/// Returns [`ChainError`] for a non-canonical or invalid patch, group,
/// recipient, resource violation or cryptographic failure.
pub fn create_semantic_patch_proposal(
    group: GroupCertificate,
    patch_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    create_default_content_proposal(
        group,
        patch_binary,
        recipients,
        ContentKind::SemanticPatch,
        Capabilities::APPLY_PATCH,
        limits,
    )
}

/// Encrypts one exact artifact behind a fresh witness-quorum contract.
///
/// Recipient identities are committed to the contract but receive no direct
/// CEK slot. Witnesses instead receive independent threshold shares.
///
/// # Errors
///
/// Returns [`ChainError`] for invalid content, identities, threshold policy or
/// a cryptographic failure.
pub fn create_quorum_capsule_proposal(
    group: GroupCertificate,
    artifact_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    witnesses: Vec<IdentityPublicDocument>,
    options: QuorumProposalOptions,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    create_default_quorum_proposal(
        group,
        artifact_binary,
        recipients,
        witnesses,
        ContentKind::ExactArtifact,
        Capabilities::APPLY_EXACT,
        options,
        limits,
    )
}

/// Encrypts one semantic patch behind a fresh witness-quorum contract.
///
/// # Errors
///
/// Returns [`ChainError`] for invalid content, identities, threshold policy or
/// a cryptographic failure.
pub fn create_quorum_semantic_patch_proposal(
    group: GroupCertificate,
    patch_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    witnesses: Vec<IdentityPublicDocument>,
    options: QuorumProposalOptions,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    create_default_quorum_proposal(
        group,
        patch_binary,
        recipients,
        witnesses,
        ContentKind::SemanticPatch,
        Capabilities::APPLY_PATCH,
        options,
        limits,
    )
}

/// Encrypts one verified `.rba` under an explicit canonical access contract.
///
/// The current envelope implements only direct HPKE recipient release. Quorum,
/// time and usage policies are rejected until their key-share authorization
/// protocol is available; they are never silently weakened to local checks.
///
/// # Errors
///
/// Returns [`ChainError`] if the contract does not exactly bind the group,
/// content, recipients and sealing threshold, or requests an unsupported
/// release mechanism.
pub fn create_capsule_proposal_with_contract(
    group: GroupCertificate,
    artifact_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    contract: AccessContract,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    if contract.content().kind() != ContentKind::ExactArtifact {
        return Err(ChainError::InvalidContract);
    }
    create_content_proposal_with_contract(group, artifact_binary, recipients, contract, limits)
}

/// Encrypts canonical protected content under an explicit Access Contract.
///
/// Exact artifacts and semantic patches are validated by their own bounded
/// canonical decoders before encryption. The contract content kind selects the
/// decoder and is authenticated by every proposal approval.
///
/// # Errors
///
/// Returns [`ChainError`] for invalid content or a contract binding mismatch.
pub fn create_content_proposal_with_contract(
    group: GroupCertificate,
    content_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    contract: AccessContract,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    if !matches!(contract.release(), ReleasePolicy::DirectRecipients) {
        return Err(ChainError::UnsupportedReleasePolicy);
    }
    create_proposal_with_holders(group, content_binary, recipients, contract, limits)
}

/// Encrypts canonical content using witness-held threshold key shares.
///
/// The supplied identities must exactly match the canonically ordered witness
/// IDs committed by the contract. Recipients remain committed by ID and do not
/// receive a direct CEK slot.
///
/// # Errors
///
/// Returns [`ChainError`] for a non-quorum contract, mismatched witness,
/// invalid content or cryptographic failure.
pub fn create_quorum_content_proposal_with_contract(
    group: GroupCertificate,
    content_binary: &[u8],
    witnesses: Vec<IdentityPublicDocument>,
    contract: AccessContract,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    if !matches!(contract.release(), ReleasePolicy::Quorum(_)) {
        return Err(ChainError::UnsupportedReleasePolicy);
    }
    create_proposal_with_holders(group, content_binary, witnesses, contract, limits)
}

fn create_proposal_with_holders(
    group: GroupCertificate,
    content_binary: &[u8],
    holders: Vec<IdentityPublicDocument>,
    contract: AccessContract,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    group.validate()?;
    validate_plaintext_content(content_binary, contract.content().kind(), limits)?;
    let holders = canonical_identities(holders)?;
    let content_digest = protected_content_digest(content_binary);
    let content_size =
        u64::try_from(content_binary.len()).map_err(|_| ChainError::LengthOverflow)?;
    let holder_ids: Vec<_> = holders
        .iter()
        .map(IdentityPublicDocument::identity_id)
        .collect::<Result<_, _>>()?;
    validate_contract_bindings(
        &group,
        &contract,
        &content_digest,
        content_size,
        &holder_ids,
    )?;

    let group_id = group.group_id()?;
    if holders.is_empty() || holders.len() > MAX_RECIPIENTS {
        return Err(ChainError::LimitExceeded);
    }

    let mut cek = Zeroizing::new([0_u8; CEK_BYTES]);
    let mut proposal_nonce = [0_u8; 32];
    let mut payload_nonce = [0_u8; PAYLOAD_NONCE_BYTES];
    getrandom::fill(cek.as_mut()).map_err(|_| ChainError::EntropyUnavailable)?;
    getrandom::fill(&mut proposal_nonce).map_err(|_| ChainError::EntropyUnavailable)?;
    getrandom::fill(&mut payload_nonce).map_err(|_| ChainError::EntropyUnavailable)?;
    let core = proposal_core(&group, &contract, &proposal_nonce, &payload_nonce)?;
    let core_digest = domain_hash("Rebyte Chain proposal core digest v2 2026-07-18", &[&core]);
    let payload_cipher = XChaCha20Poly1305::new_from_slice(cek.as_ref())
        .map_err(|_| ChainError::CryptographicFailure)?;
    let ciphertext = payload_cipher
        .encrypt(
            &XNonce::from(payload_nonce),
            Payload {
                msg: content_binary,
                aad: &payload_aad(&core),
            },
        )
        .map_err(|_| ChainError::CryptographicFailure)?;
    let key_material = key_material_for_holders(&cek, contract.release(), holders.len())?;
    let mut slots = Vec::with_capacity(holders.len());
    for ((holder, holder_id), material) in holders.into_iter().zip(holder_ids).zip(key_material) {
        let public_key = HpkePublicKey::from_bytes(&holder.encryption_public_key()?)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        let info = key_slot_info(&group_id, &proposal_nonce, &holder_id, contract.release());
        let (encapped_key, wrapped_key) =
            single_shot_seal::<HpkeChaCha20Poly1305, HkdfSha256, ChainKem>(
                &OpModeS::Base,
                &public_key,
                &info,
                material.as_ref(),
                &core_digest,
            )
            .map_err(|_| ChainError::CryptographicFailure)?;
        let encapped_key: [u8; HPKE_ENCAPPED_KEY_BYTES] = encapped_key
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| ChainError::CryptographicFailure)?;
        if wrapped_key.len() != wrapped_key_bytes(contract.release()) {
            return Err(ChainError::CryptographicFailure);
        }
        slots.push(KeySlot {
            holder,
            encapped_key,
            wrapped_key,
        });
    }
    let mut proposal = CapsuleProposal {
        group,
        contract,
        proposal_nonce,
        content_digest,
        content_size,
        payload_nonce,
        slots,
        ciphertext,
        proposal_id: [0; 32],
    };
    proposal.proposal_id = calculate_proposal_id(&proposal)?;
    proposal.validate(limits)?;
    Ok(proposal)
}

fn create_default_content_proposal(
    group: GroupCertificate,
    content_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    kind: ContentKind,
    capabilities: Capabilities,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    group.validate()?;
    validate_plaintext_content(content_binary, kind, limits)?;
    let recipients = canonical_identities(recipients)?;
    let content_digest = protected_content_digest(content_binary);
    let content_size =
        u64::try_from(content_binary.len()).map_err(|_| ChainError::LengthOverflow)?;
    let group_id = group.group_id()?;
    let controllers = group
        .proposal()
        .members()
        .iter()
        .map(IdentityPublicDocument::identity_id)
        .map(|result| result.map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let recipient_ids = recipients
        .iter()
        .map(IdentityPublicDocument::identity_id)
        .map(|result| result.map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let contract = AccessContract::builder(
        PrincipalId::from_bytes(*group_id.as_bytes()),
        ContentCommitment::new(kind, content_digest, content_size),
    )
    .controllers(controllers, group.capsule_threshold())
    .recipients(recipient_ids)
    .capabilities(capabilities)
    .release(ReleasePolicy::DirectRecipients)
    .build()
    .map_err(map_contract_error)?;
    create_content_proposal_with_contract(group, content_binary, recipients, contract, limits)
}

#[allow(clippy::too_many_arguments)]
fn create_default_quorum_proposal(
    group: GroupCertificate,
    content_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    witnesses: Vec<IdentityPublicDocument>,
    kind: ContentKind,
    capabilities: Capabilities,
    options: QuorumProposalOptions,
    limits: &ChainLimits,
) -> Result<CapsuleProposal, ChainError> {
    group.validate()?;
    validate_plaintext_content(content_binary, kind, limits)?;
    let recipients = canonical_identities(recipients)?;
    let witnesses = canonical_identities(witnesses)?;
    let content_digest = protected_content_digest(content_binary);
    let content_size =
        u64::try_from(content_binary.len()).map_err(|_| ChainError::LengthOverflow)?;
    let group_id = group.group_id()?;
    let controllers = group
        .proposal()
        .members()
        .iter()
        .map(IdentityPublicDocument::identity_id)
        .map(|result| result.map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let recipient_ids = recipients
        .iter()
        .map(IdentityPublicDocument::identity_id)
        .map(|result| result.map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let witness_ids = witnesses
        .iter()
        .map(IdentityPublicDocument::identity_id)
        .map(|result| result.map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let release = rebyte_contract::QuorumRelease::new(
        witness_ids,
        options.threshold,
        options.not_before_unix_ms,
        options.maximum_successful_releases,
    )
    .map_err(map_contract_error)?;
    let contract = AccessContract::builder(
        PrincipalId::from_bytes(*group_id.as_bytes()),
        ContentCommitment::new(kind, content_digest, content_size),
    )
    .controllers(controllers, group.capsule_threshold())
    .recipients(recipient_ids)
    .capabilities(capabilities)
    .release(ReleasePolicy::Quorum(release))
    .build()
    .map_err(map_contract_error)?;
    create_quorum_content_proposal_with_contract(group, content_binary, witnesses, contract, limits)
}

/// Signs one exact encrypted proposal as a group member.
///
/// # Errors
///
/// Returns [`ChainError::NotGroupMember`] for a foreign identity or another
/// [`ChainError`] when the proposal is invalid.
pub fn approve_capsule(
    proposal: &CapsuleProposal,
    identity: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<CapsuleApproval, ChainError> {
    proposal.validate(limits)?;
    let group_id = proposal.group.group_id()?;
    if proposal
        .group
        .proposal()
        .member(&identity.identity_id())
        .is_none()
    {
        return Err(ChainError::NotGroupMember);
    }
    let message = approval_message(&group_id, &proposal.proposal_id, &identity.identity_id());
    Ok(CapsuleApproval {
        schema_version: APPROVAL_VERSION,
        kind: APPROVAL_KIND.to_string(),
        group_id: group_id.to_base64(),
        proposal_id: encode_base64(&proposal.proposal_id),
        member_id: identity.identity_id().to_base64(),
        signature: encode_base64(&identity.sign(&message)),
    })
}

/// Verifies a capsule threshold and produces a portable encrypted envelope.
///
/// # Errors
///
/// Returns [`ChainError`] for insufficient, duplicate, foreign, rebound or
/// invalid member approvals.
pub fn finalize_capsule(
    proposal: CapsuleProposal,
    mut approvals: Vec<CapsuleApproval>,
    limits: &ChainLimits,
) -> Result<CapsuleEnvelope, ChainError> {
    proposal.validate(limits)?;
    for approval in &approvals {
        approval.validate_shape()?;
    }
    approvals.sort_by_key(|approval| approval.member_id().unwrap_or(IdentityId([0; 32])));
    if approvals.windows(2).any(|pair| {
        pair.first().and_then(|item| item.member_id().ok())
            == pair.get(1).and_then(|item| item.member_id().ok())
    }) {
        return Err(ChainError::DuplicateIdentity);
    }
    let envelope_id = calculate_envelope_id(&proposal, &approvals)?;
    let envelope = CapsuleEnvelope {
        proposal,
        approvals,
        envelope_id,
    };
    envelope.validate(limits)?;
    Ok(envelope)
}

/// Opens a fully authorized capsule for one explicitly listed recipient.
///
/// The returned `.rba` bytes are released only after HPKE, payload AEAD,
/// exact length, digest and inner artifact verification all succeed.
///
/// # Errors
///
/// Returns [`ChainError`] for an invalid capsule, unlisted identity, wrong
/// private material, authentication failure or reconstructed artifact mismatch.
pub fn open_capsule(
    envelope: &CapsuleEnvelope,
    recipient: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<OpenedCapsule, ChainError> {
    if envelope.proposal.contract.content().kind() != ContentKind::ExactArtifact {
        return Err(ChainError::InvalidContent);
    }
    let opened = decrypt_content(envelope, recipient, limits)?;
    Ok(OpenedCapsule {
        artifact_binary: opened.bytes,
        contract_id: opened.contract_id,
        group_id: opened.group_id,
        proposal_id: opened.proposal_id,
        recipient_id: opened.recipient_id,
    })
}

/// Opens a fully authorized canonical semantic patch.
///
/// # Errors
///
/// Returns [`ChainError`] unless the envelope contract binds semantic-patch
/// content and all consensus, recipient, AEAD, digest and canonical checks
/// succeed.
pub fn open_semantic_patch(
    envelope: &CapsuleEnvelope,
    recipient: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<OpenedSemanticPatch, ChainError> {
    if envelope.proposal.contract.content().kind() != ContentKind::SemanticPatch {
        return Err(ChainError::InvalidContent);
    }
    let opened = decrypt_content(envelope, recipient, limits)?;
    let patch = parse_patch(&opened.bytes).map_err(|_| ChainError::InvalidContent)?;
    Ok(OpenedSemanticPatch {
        patch,
        contract_id: opened.contract_id,
        group_id: opened.group_id,
        proposal_id: opened.proposal_id,
        recipient_id: opened.recipient_id,
    })
}

fn decrypt_content(
    envelope: &CapsuleEnvelope,
    recipient: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<DecryptedContent, ChainError> {
    envelope.validate(limits)?;
    if !matches!(
        envelope.proposal.contract.release(),
        ReleasePolicy::DirectRecipients
    ) {
        return Err(ChainError::UnsupportedReleasePolicy);
    }
    if !envelope
        .proposal
        .contract
        .capabilities()
        .contains(Capability::Decrypt)
    {
        return Err(ChainError::InvalidContract);
    }
    let recipient_id = recipient.identity_id();
    let slot = envelope
        .proposal
        .slots
        .iter()
        .find(|slot| {
            slot.holder
                .identity_id()
                .is_ok_and(|candidate| candidate == recipient_id)
        })
        .ok_or(ChainError::NotRecipient)?;
    let group_id = envelope.proposal.group.group_id()?;
    let core = proposal_core(
        &envelope.proposal.group,
        &envelope.proposal.contract,
        &envelope.proposal.proposal_nonce,
        &envelope.proposal.payload_nonce,
    )?;
    let core_digest = domain_hash("Rebyte Chain proposal core digest v2 2026-07-18", &[&core]);
    let encapped_key = <ChainKem as hpke::Kem>::EncappedKey::from_bytes(&slot.encapped_key)
        .map_err(|_| ChainError::CryptographicFailure)?;
    let info = key_slot_info(
        &group_id,
        &envelope.proposal.proposal_nonce,
        &recipient_id,
        envelope.proposal.contract.release(),
    );
    let cek = Zeroizing::new(
        single_shot_open::<HpkeChaCha20Poly1305, HkdfSha256, ChainKem>(
            &OpModeR::Base,
            &recipient.hpke_private_key(),
            &encapped_key,
            &info,
            &slot.wrapped_key,
            &core_digest,
        )
        .map_err(|_| ChainError::CryptographicFailure)?,
    );
    if cek.len() != CEK_BYTES {
        return Err(ChainError::CryptographicFailure);
    }
    decrypt_payload_with_cek(envelope, recipient_id, cek.as_slice(), limits)
}

pub(super) fn decrypt_payload_with_cek(
    envelope: &CapsuleEnvelope,
    recipient_id: IdentityId,
    cek: &[u8],
    limits: &ChainLimits,
) -> Result<DecryptedContent, ChainError> {
    envelope.validate(limits)?;
    if !envelope
        .proposal
        .contract
        .recipients()
        .contains(&principal_id(recipient_id))
    {
        return Err(ChainError::NotRecipient);
    }
    if cek.len() != CEK_BYTES {
        return Err(ChainError::CryptographicFailure);
    }
    let group_id = envelope.proposal.group.group_id()?;
    let core = proposal_core(
        &envelope.proposal.group,
        &envelope.proposal.contract,
        &envelope.proposal.proposal_nonce,
        &envelope.proposal.payload_nonce,
    )?;
    let payload_cipher =
        XChaCha20Poly1305::new_from_slice(cek).map_err(|_| ChainError::CryptographicFailure)?;
    let content_binary = payload_cipher
        .decrypt(
            &XNonce::from(envelope.proposal.payload_nonce),
            Payload {
                msg: &envelope.proposal.ciphertext,
                aad: &payload_aad(&core),
            },
        )
        .map_err(|_| ChainError::CryptographicFailure)?;
    if u64::try_from(content_binary.len()).map_err(|_| ChainError::LengthOverflow)?
        != envelope.proposal.content_size
        || protected_content_digest(&content_binary) != envelope.proposal.content_digest
    {
        return Err(ChainError::IntegrityMismatch);
    }
    validate_plaintext_content(
        &content_binary,
        envelope.proposal.contract.content().kind(),
        limits,
    )?;
    Ok(DecryptedContent {
        bytes: content_binary,
        content_kind: envelope.proposal.contract.content().kind(),
        contract_id: envelope.proposal.contract.contract_id(),
        group_id,
        proposal_id: envelope.proposal.proposal_id,
        recipient_id,
    })
}

pub(super) fn unwrap_quorum_share(
    envelope: &CapsuleEnvelope,
    witness: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<Zeroizing<[u8; SHARE_BYTES]>, ChainError> {
    envelope.validate(limits)?;
    let ReleasePolicy::Quorum(policy) = envelope.proposal.contract.release() else {
        return Err(ChainError::UnsupportedReleasePolicy);
    };
    let witness_id = witness.identity_id();
    if !policy.witnesses().contains(&principal_id(witness_id)) {
        return Err(ChainError::NotWitness);
    }
    let slot = envelope
        .proposal
        .slots
        .iter()
        .find(|slot| {
            slot.holder
                .identity_id()
                .is_ok_and(|candidate| candidate == witness_id)
        })
        .ok_or(ChainError::NotWitness)?;
    let group_id = envelope.proposal.group.group_id()?;
    let core = proposal_core(
        &envelope.proposal.group,
        &envelope.proposal.contract,
        &envelope.proposal.proposal_nonce,
        &envelope.proposal.payload_nonce,
    )?;
    let core_digest = domain_hash("Rebyte Chain proposal core digest v2 2026-07-18", &[&core]);
    let encapped_key = <ChainKem as hpke::Kem>::EncappedKey::from_bytes(&slot.encapped_key)
        .map_err(|_| ChainError::CryptographicFailure)?;
    let info = key_slot_info(
        &group_id,
        &envelope.proposal.proposal_nonce,
        &witness_id,
        envelope.proposal.contract.release(),
    );
    let share = Zeroizing::new(
        single_shot_open::<HpkeChaCha20Poly1305, HkdfSha256, ChainKem>(
            &OpModeR::Base,
            &witness.hpke_private_key(),
            &encapped_key,
            &info,
            &slot.wrapped_key,
            &core_digest,
        )
        .map_err(|_| ChainError::CryptographicFailure)?,
    );
    if share.len() != SHARE_BYTES {
        return Err(ChainError::InvalidShare);
    }
    let mut bounded_share = Zeroizing::new([0_u8; SHARE_BYTES]);
    bounded_share.as_mut().copy_from_slice(&share);
    let expected_x = policy
        .witnesses()
        .iter()
        .position(|candidate| candidate == &principal_id(witness_id))
        .and_then(|index| u8::try_from(index.saturating_add(1)).ok())
        .ok_or(ChainError::InvalidShare)?;
    if bounded_share[0] != expected_x {
        return Err(ChainError::InvalidShare);
    }
    Ok(bounded_share)
}

pub(super) fn opened_content(decrypted: DecryptedContent) -> Result<OpenedContent, ChainError> {
    match decrypted.content_kind {
        ContentKind::ExactArtifact => Ok(OpenedContent::ExactArtifact(OpenedCapsule {
            artifact_binary: decrypted.bytes,
            contract_id: decrypted.contract_id,
            group_id: decrypted.group_id,
            proposal_id: decrypted.proposal_id,
            recipient_id: decrypted.recipient_id,
        })),
        ContentKind::SemanticPatch => {
            let patch = parse_patch(&decrypted.bytes).map_err(|_| ChainError::InvalidContent)?;
            Ok(OpenedContent::SemanticPatch(OpenedSemanticPatch {
                patch,
                contract_id: decrypted.contract_id,
                group_id: decrypted.group_id,
                proposal_id: decrypted.proposal_id,
                recipient_id: decrypted.recipient_id,
            }))
        }
        _ => Err(ChainError::InvalidContent),
    }
}

fn verify_capsule_approval(
    proposal: &CapsuleProposal,
    approval: &CapsuleApproval,
) -> Result<(), ChainError> {
    approval.validate_shape()?;
    let group_id = proposal.group.group_id()?;
    let member_id = approval.member_id()?;
    if decode_array::<32>(&approval.group_id)? != group_id.0
        || decode_array::<32>(&approval.proposal_id)? != proposal.proposal_id
    {
        return Err(ChainError::BindingMismatch);
    }
    let member = proposal
        .group
        .proposal()
        .member(&member_id)
        .ok_or(ChainError::NotGroupMember)?;
    let verifying_key = VerifyingKey::from_bytes(&member.signing_public_key()?)
        .map_err(|_| ChainError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(
            &approval_message(&group_id, &proposal.proposal_id, &member_id),
            &Signature::from_bytes(&decode_array(&approval.signature)?),
        )
        .map_err(|_| ChainError::InvalidSignature)
}

fn proposal_core(
    group: &GroupCertificate,
    contract: &AccessContract,
    proposal_nonce: &[u8; 32],
    payload_nonce: &[u8; PAYLOAD_NONCE_BYTES],
) -> Result<Vec<u8>, ChainError> {
    let group_id = group.group_id()?;
    let group_digest = domain_hash(
        "Rebyte Chain group certificate digest v2 2026-07-18",
        &[&group.to_json()?],
    );
    let contract_bytes = contract
        .to_bytes()
        .map_err(|_| ChainError::InvalidContract)?;
    let mut core = Vec::new();
    core.extend_from_slice(b"rebyte chain capsule proposal core v2\0");
    put_u16(&mut core, WIRE_VERSION);
    put_u16(&mut core, CRYPTO_SUITE);
    core.extend_from_slice(group_id.as_bytes());
    core.extend_from_slice(&group_digest);
    put_bytes_u32(&mut core, &contract_bytes)?;
    core.extend_from_slice(proposal_nonce);
    core.extend_from_slice(payload_nonce);
    Ok(core)
}

fn calculate_proposal_id(proposal: &CapsuleProposal) -> Result<[u8; 32], ChainError> {
    let core = proposal_core(
        &proposal.group,
        &proposal.contract,
        &proposal.proposal_nonce,
        &proposal.payload_nonce,
    )?;
    let mut slots = Vec::new();
    for slot in &proposal.slots {
        slots.extend_from_slice(slot.holder.identity_id()?.as_bytes());
        slots.extend_from_slice(&slot.encapped_key);
        slots.extend_from_slice(&slot.wrapped_key);
    }
    let ciphertext_digest = domain_hash(
        "Rebyte Chain ciphertext digest v2 2026-07-18",
        &[&proposal.ciphertext],
    );
    Ok(domain_hash(
        "Rebyte Chain capsule proposal id v2 2026-07-18",
        &[&core, &slots, &ciphertext_digest],
    ))
}

fn calculate_envelope_id(
    proposal: &CapsuleProposal,
    approvals: &[CapsuleApproval],
) -> Result<[u8; 32], ChainError> {
    let mut approval_bytes = Vec::new();
    for approval in approvals {
        approval_bytes.extend_from_slice(approval.member_id()?.as_bytes());
        approval_bytes.extend_from_slice(&decode_array::<64>(&approval.signature)?);
    }
    Ok(domain_hash(
        "Rebyte Chain capsule envelope id v2 2026-07-18",
        &[&proposal.proposal_id, &approval_bytes],
    ))
}

fn protected_content_digest(content_binary: &[u8]) -> [u8; 32] {
    domain_hash(
        "Rebyte Chain protected content digest v2 2026-07-18",
        &[content_binary],
    )
}

fn key_material_for_holders(
    cek: &[u8; CEK_BYTES],
    release: &ReleasePolicy,
    holder_count: usize,
) -> Result<Vec<Zeroizing<Vec<u8>>>, ChainError> {
    match release {
        ReleasePolicy::DirectRecipients => Ok((0..holder_count)
            .map(|_| Zeroizing::new(cek.to_vec()))
            .collect()),
        ReleasePolicy::Quorum(policy) => {
            let share_count = u8::try_from(holder_count).map_err(|_| ChainError::LengthOverflow)?;
            let threshold =
                u8::try_from(policy.threshold()).map_err(|_| ChainError::InvalidThreshold)?;
            split_secret(cek, share_count, threshold).map(|shares| {
                shares
                    .into_iter()
                    .map(|share| Zeroizing::new(share.as_ref().to_vec()))
                    .collect()
            })
        }
        _ => Err(ChainError::UnsupportedReleasePolicy),
    }
}

const fn wrapped_key_bytes(release: &ReleasePolicy) -> usize {
    match release {
        ReleasePolicy::DirectRecipients => HPKE_WRAPPED_CEK_BYTES,
        ReleasePolicy::Quorum(_) => HPKE_WRAPPED_SHARE_BYTES,
        _ => 0,
    }
}

fn validate_plaintext_content(
    content_binary: &[u8],
    kind: ContentKind,
    limits: &ChainLimits,
) -> Result<(), ChainError> {
    match kind {
        ContentKind::ExactArtifact => {
            enforce_length(content_binary.len(), limits.artifact.max_capsule_bytes)?;
            decode_artifact(content_binary, &limits.artifact)
                .map(|_| ())
                .map_err(|_| ChainError::InvalidArtifact)
        }
        ContentKind::SemanticPatch => {
            enforce_length(content_binary.len(), MAX_PATCH_BYTES)?;
            let patch = parse_patch(content_binary).map_err(|_| ChainError::InvalidContent)?;
            if patch
                .to_json_bytes()
                .map_err(|_| ChainError::InvalidContent)?
                .as_slice()
                != content_binary
            {
                return Err(ChainError::InvalidContent);
            }
            Ok(())
        }
        _ => Err(ChainError::InvalidContent),
    }
}

fn payload_aad(core: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAYLOAD_AAD_DOMAIN.len().saturating_add(core.len()));
    aad.extend_from_slice(PAYLOAD_AAD_DOMAIN);
    aad.extend_from_slice(core);
    aad
}

fn key_slot_info(
    group_id: &GroupId,
    proposal_nonce: &[u8; 32],
    holder_id: &IdentityId,
    release: &ReleasePolicy,
) -> Vec<u8> {
    let domain = match release {
        ReleasePolicy::DirectRecipients => HPKE_INFO_DOMAIN,
        ReleasePolicy::Quorum(_) => b"rebyte chain hpke witness share slot v2\0",
        _ => b"rebyte chain hpke unsupported slot v2\0",
    };
    let mut info = Vec::with_capacity(domain.len().saturating_add(96));
    info.extend_from_slice(domain);
    info.extend_from_slice(group_id.as_bytes());
    info.extend_from_slice(proposal_nonce);
    info.extend_from_slice(holder_id.as_bytes());
    info
}

fn approval_message(group_id: &GroupId, proposal_id: &[u8; 32], member_id: &IdentityId) -> Vec<u8> {
    let mut message = Vec::with_capacity(APPROVAL_DOMAIN.len().saturating_add(96));
    message.extend_from_slice(APPROVAL_DOMAIN);
    message.extend_from_slice(group_id.as_bytes());
    message.extend_from_slice(proposal_id);
    message.extend_from_slice(member_id.as_bytes());
    message
}

fn canonical_identities(
    mut recipients: Vec<IdentityPublicDocument>,
) -> Result<Vec<IdentityPublicDocument>, ChainError> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(ChainError::LimitExceeded);
    }
    for recipient in &recipients {
        recipient.validate()?;
    }
    recipients.sort_by_key(|recipient| recipient.identity_id().unwrap_or(IdentityId([0; 32])));
    if recipients.windows(2).any(|pair| {
        pair.first().and_then(|item| item.identity_id().ok())
            == pair.get(1).and_then(|item| item.identity_id().ok())
    }) {
        return Err(ChainError::DuplicateIdentity);
    }
    Ok(recipients)
}

fn validate_contract_bindings(
    group: &GroupCertificate,
    contract: &AccessContract,
    content_digest: &[u8; 32],
    content_size: u64,
    holder_ids: &[IdentityId],
) -> Result<(), ChainError> {
    let contract_bytes = contract
        .to_bytes()
        .map_err(|_| ChainError::InvalidContract)?;
    if contract_bytes.len() > MAX_ACCESS_CONTRACT_BYTES {
        return Err(ChainError::LimitExceeded);
    }
    let group_id = group.group_id()?;
    if contract.group_id() != PrincipalId::from_bytes(*group_id.as_bytes())
        || contract.seal_threshold() != group.capsule_threshold()
        || contract.content().digest() != content_digest
        || contract.content().size() != content_size
    {
        return Err(ChainError::InvalidContract);
    }
    let controllers = group
        .proposal()
        .members()
        .iter()
        .map(IdentityPublicDocument::identity_id)
        .map(|result| result.map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let holders = holder_ids
        .iter()
        .copied()
        .map(principal_id)
        .collect::<Vec<_>>();
    if contract.controllers() != controllers
        || !contract.capabilities().contains(Capability::Decrypt)
    {
        return Err(ChainError::InvalidContract);
    }
    match contract.release() {
        ReleasePolicy::DirectRecipients if contract.recipients() == holders => Ok(()),
        ReleasePolicy::Quorum(policy) if policy.witnesses() == holders => Ok(()),
        ReleasePolicy::DirectRecipients | ReleasePolicy::Quorum(_) => {
            Err(ChainError::InvalidContract)
        }
        _ => Err(ChainError::UnsupportedReleasePolicy),
    }
}

const fn principal_id(identity_id: IdentityId) -> PrincipalId {
    PrincipalId::from_bytes(*identity_id.as_bytes())
}

const fn map_contract_error(error: ContractError) -> ChainError {
    match error {
        ContractError::EntropyUnavailable => ChainError::EntropyUnavailable,
        ContractError::LimitExceeded | ContractError::LengthOverflow => ChainError::LimitExceeded,
        _ => ChainError::InvalidContract,
    }
}

fn enforce_length(length: usize, maximum: u64) -> Result<(), ChainError> {
    let length = u64::try_from(length).map_err(|_| ChainError::LengthOverflow)?;
    if length > maximum {
        Err(ChainError::LimitExceeded)
    } else {
        Ok(())
    }
}
