// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::redundant_pub_crate)]

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::codec::{decode_array, domain_hash, encode_base64, put_bytes_u16, put_u16, put_u32};
use crate::{ChainError, IdentityId, IdentityPublicDocument, UnlockedIdentity};

const DOCUMENT_VERSION: u16 = 1;
const PROPOSAL_KIND: &str = "rebyte-chain-group-proposal";
const ACCEPTANCE_KIND: &str = "rebyte-chain-group-acceptance";
const CERTIFICATE_KIND: &str = "rebyte-chain-group-certificate";
const GROUP_BODY_DOMAIN: &[u8] = b"rebyte chain group body v1\0";
const GROUP_ACCEPTANCE_DOMAIN: &[u8] = b"rebyte chain group acceptance v1\0";
const MAX_GROUP_MEMBERS: usize = 64;
const MAX_GROUP_NAME_BYTES: usize = 256;

/// Immutable identifier of one exact group composition and policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GroupId(pub(crate) [u8; 32]);

impl GroupId {
    /// Returns the binary group identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns canonical Base64URL without padding.
    #[must_use]
    pub fn to_base64(&self) -> String {
        encode_base64(&self.0)
    }
}

/// Proposed group membership requiring unanimous formation acceptance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupProposal {
    schema_version: u16,
    kind: String,
    display_name: String,
    group_nonce: String,
    capsule_threshold: u16,
    members: Vec<IdentityPublicDocument>,
    group_id: String,
}

impl GroupProposal {
    /// Creates a canonical group proposal with a fresh random group nonce.
    ///
    /// Every member must later accept this exact proposal. `capsule_threshold`
    /// controls how many group members must approve each capsule.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for invalid names, members, duplicates,
    /// thresholds, limits or unavailable entropy.
    pub fn new(
        display_name: &str,
        capsule_threshold: u16,
        members: Vec<IdentityPublicDocument>,
    ) -> Result<Self, ChainError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ChainError::EntropyUnavailable)?;
        Self::with_nonce(display_name, capsule_threshold, members, nonce)
    }

    /// Parses a canonical group proposal.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, unsupported, non-canonical or
    /// cryptographically inconsistent data.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let document: Self =
            serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        document.validate()?;
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

    /// Returns the immutable group identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] when the proposal is invalid.
    pub fn group_id(&self) -> Result<GroupId, ChainError> {
        self.validate()?;
        self.group_id_unchecked()
    }

    // Callers must have validated this proposal on the current data.
    pub(crate) fn group_id_unchecked(&self) -> Result<GroupId, ChainError> {
        Ok(GroupId(decode_array(&self.group_id)?))
    }

    /// Returns the human-readable group label.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the capsule approval threshold.
    #[must_use]
    pub const fn capsule_threshold(&self) -> u16 {
        self.capsule_threshold
    }

    /// Returns canonically ordered member identity packages.
    #[must_use]
    pub fn members(&self) -> &[IdentityPublicDocument] {
        &self.members
    }

    // Callers must have validated this proposal on the current data.
    pub(crate) fn member(&self, id: &IdentityId) -> Option<&IdentityPublicDocument> {
        self.members.iter().find(|member| {
            member
                .identity_id_unchecked()
                .is_ok_and(|candidate| candidate == *id)
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != PROPOSAL_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        validate_group_name(&self.display_name)?;
        if self.members.is_empty() || self.members.len() > MAX_GROUP_MEMBERS {
            return Err(ChainError::LimitExceeded);
        }
        let member_count =
            u16::try_from(self.members.len()).map_err(|_| ChainError::LengthOverflow)?;
        if self.capsule_threshold == 0 || self.capsule_threshold > member_count {
            return Err(ChainError::InvalidThreshold);
        }
        let mut previous = None;
        for member in &self.members {
            member.validate()?;
            let identity_id = member.identity_id_unchecked()?;
            if previous.is_some_and(|value| value >= identity_id) {
                return Err(if previous == Some(identity_id) {
                    ChainError::DuplicateIdentity
                } else {
                    ChainError::NonCanonicalOrder
                });
            }
            previous = Some(identity_id);
        }
        let nonce: [u8; 32] = decode_array(&self.group_nonce)?;
        let expected = calculate_group_id(
            &self.display_name,
            &nonce,
            self.capsule_threshold,
            &self.members,
        )?;
        if decode_array::<32>(&self.group_id)? != expected.0 {
            return Err(ChainError::BindingMismatch);
        }
        Ok(())
    }

    fn with_nonce(
        display_name: &str,
        capsule_threshold: u16,
        mut members: Vec<IdentityPublicDocument>,
        nonce: [u8; 32],
    ) -> Result<Self, ChainError> {
        validate_group_name(display_name)?;
        for member in &members {
            member.validate()?;
        }
        members.sort_by_cached_key(|member| {
            member
                .identity_id_unchecked()
                .unwrap_or(IdentityId([0; 32]))
        });
        if members.windows(2).any(|pair| {
            pair.first()
                .and_then(|left| left.identity_id_unchecked().ok())
                == pair
                    .get(1)
                    .and_then(|right| right.identity_id_unchecked().ok())
        }) {
            return Err(ChainError::DuplicateIdentity);
        }
        let member_count = u16::try_from(members.len()).map_err(|_| ChainError::LengthOverflow)?;
        if members.is_empty() || members.len() > MAX_GROUP_MEMBERS {
            return Err(ChainError::LimitExceeded);
        }
        if capsule_threshold == 0 || capsule_threshold > member_count {
            return Err(ChainError::InvalidThreshold);
        }
        let group_id = calculate_group_id(display_name, &nonce, capsule_threshold, &members)?;
        let proposal = Self {
            schema_version: DOCUMENT_VERSION,
            kind: PROPOSAL_KIND.to_string(),
            display_name: display_name.to_string(),
            group_nonce: encode_base64(&nonce),
            capsule_threshold,
            members,
            group_id: group_id.to_base64(),
        };
        proposal.validate()?;
        Ok(proposal)
    }
}

/// One member's proof that it accepted an exact group proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupAcceptance {
    schema_version: u16,
    kind: String,
    group_id: String,
    member_id: String,
    signature: String,
}

impl GroupAcceptance {
    /// Parses a canonical group acceptance document.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed or non-canonical bytes.
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

    /// Returns the accepting member identity.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for invalid encoding.
    pub fn member_id(&self) -> Result<IdentityId, ChainError> {
        self.validate_shape()?;
        Ok(IdentityId(decode_array(&self.member_id)?))
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != ACCEPTANCE_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        let _group_id: [u8; 32] = decode_array(&self.group_id)?;
        let _member_id: [u8; 32] = decode_array(&self.member_id)?;
        let _signature: [u8; 64] = decode_array(&self.signature)?;
        Ok(())
    }
}

/// Unanimously formed group certificate and its capsule threshold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupCertificate {
    schema_version: u16,
    kind: String,
    proposal: GroupProposal,
    acceptances: Vec<GroupAcceptance>,
}

impl GroupCertificate {
    /// Parses and fully verifies a canonical group certificate.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if any member is missing, duplicated, rebound or
    /// signed with a private key different from the declared public key.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let document: Self =
            serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        document.validate()?;
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

    /// Returns the exact accepted proposal.
    #[must_use]
    pub const fn proposal(&self) -> &GroupProposal {
        &self.proposal
    }

    /// Returns the verified group identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the certificate is invalid.
    pub fn group_id(&self) -> Result<GroupId, ChainError> {
        self.validate()?;
        self.proposal.group_id_unchecked()
    }

    // Callers must have validated this certificate on the current data.
    pub(crate) fn group_id_unchecked(&self) -> Result<GroupId, ChainError> {
        self.proposal.group_id_unchecked()
    }

    /// Returns the verified capsule approval threshold.
    #[must_use]
    pub const fn capsule_threshold(&self) -> u16 {
        self.proposal.capsule_threshold
    }

    /// Returns all formation acceptances in canonical member order.
    #[must_use]
    pub fn acceptances(&self) -> &[GroupAcceptance] {
        &self.acceptances
    }

    pub(crate) fn validate(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != CERTIFICATE_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        self.proposal.validate()?;
        if self.acceptances.len() != self.proposal.members.len() {
            return Err(ChainError::IncompleteGroup);
        }
        let group_id = self.proposal.group_id_unchecked()?;
        for (member, acceptance) in self.proposal.members.iter().zip(&self.acceptances) {
            verify_acceptance(&group_id, member, acceptance)?;
        }
        Ok(())
    }
}

/// Signs one exact group proposal with a declared member identity.
///
/// # Errors
///
/// Returns [`ChainError::NotGroupMember`] if the unlocked identity was not
/// listed, or another [`ChainError`] if the proposal is invalid.
pub fn accept_group(
    proposal: &GroupProposal,
    identity: &UnlockedIdentity,
) -> Result<GroupAcceptance, ChainError> {
    proposal.validate()?;
    if proposal.member(&identity.identity_id()).is_none() {
        return Err(ChainError::NotGroupMember);
    }
    let group_id = proposal.group_id_unchecked()?;
    let message = acceptance_message(&group_id, &identity.identity_id());
    Ok(GroupAcceptance {
        schema_version: DOCUMENT_VERSION,
        kind: ACCEPTANCE_KIND.to_string(),
        group_id: group_id.to_base64(),
        member_id: identity.identity_id().to_base64(),
        signature: encode_base64(&identity.sign(&message)),
    })
}

/// Verifies unanimous formation and builds a canonical group certificate.
///
/// # Errors
///
/// Returns [`ChainError`] for missing, duplicate, foreign or invalid
/// acceptances. Group formation always requires every declared member.
pub fn finalize_group(
    proposal: GroupProposal,
    mut acceptances: Vec<GroupAcceptance>,
) -> Result<GroupCertificate, ChainError> {
    proposal.validate()?;
    for acceptance in &acceptances {
        acceptance.validate_shape()?;
    }
    acceptances
        .sort_by_cached_key(|acceptance| acceptance.member_id().unwrap_or(IdentityId([0; 32])));
    if acceptances.windows(2).any(|pair| {
        pair.first().and_then(|item| item.member_id().ok())
            == pair.get(1).and_then(|item| item.member_id().ok())
    }) {
        return Err(ChainError::DuplicateIdentity);
    }
    let certificate = GroupCertificate {
        schema_version: DOCUMENT_VERSION,
        kind: CERTIFICATE_KIND.to_string(),
        proposal,
        acceptances,
    };
    certificate.validate()?;
    Ok(certificate)
}

// Callers must have validated the proposal that produced `group_id` and every
// listed member on the current data.
pub(crate) fn verify_acceptance(
    group_id: &GroupId,
    member: &IdentityPublicDocument,
    acceptance: &GroupAcceptance,
) -> Result<(), ChainError> {
    acceptance.validate_shape()?;
    let member_id = member.identity_id_unchecked()?;
    if decode_array::<32>(&acceptance.group_id)? != group_id.0
        || acceptance.member_id()? != member_id
    {
        return Err(ChainError::BindingMismatch);
    }
    let public_key = VerifyingKey::from_bytes(&member.signing_public_key()?)
        .map_err(|_| ChainError::InvalidPublicKey)?;
    public_key
        .verify_strict(
            &acceptance_message(group_id, &member_id),
            &Signature::from_bytes(&decode_array(&acceptance.signature)?),
        )
        .map_err(|_| ChainError::InvalidSignature)
}

// Callers must have validated every listed member on the current data.
fn calculate_group_id(
    display_name: &str,
    nonce: &[u8; 32],
    capsule_threshold: u16,
    members: &[IdentityPublicDocument],
) -> Result<GroupId, ChainError> {
    let member_count = u16::try_from(members.len()).map_err(|_| ChainError::LengthOverflow)?;
    let mut body = Vec::new();
    body.extend_from_slice(GROUP_BODY_DOMAIN);
    put_u16(&mut body, DOCUMENT_VERSION);
    put_bytes_u16(&mut body, display_name.as_bytes())?;
    body.extend_from_slice(nonce);
    put_u16(&mut body, capsule_threshold);
    put_u16(&mut body, member_count);
    for member in members {
        let member_bytes = member.canonical_member_bytes_unchecked()?;
        put_u32(
            &mut body,
            u32::try_from(member_bytes.len()).map_err(|_| ChainError::LengthOverflow)?,
        );
        body.extend_from_slice(&member_bytes);
    }
    Ok(GroupId(domain_hash(
        "Rebyte Chain group id v1 2026-07-17",
        &[&body],
    )))
}

fn acceptance_message(group_id: &GroupId, member_id: &IdentityId) -> Vec<u8> {
    let mut message = Vec::with_capacity(GROUP_ACCEPTANCE_DOMAIN.len().saturating_add(64));
    message.extend_from_slice(GROUP_ACCEPTANCE_DOMAIN);
    message.extend_from_slice(group_id.as_bytes());
    message.extend_from_slice(member_id.as_bytes());
    message
}

fn validate_group_name(value: &str) -> Result<(), ChainError> {
    if value.is_empty()
        || value.len() > MAX_GROUP_NAME_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '\u{7f}')
    {
        Err(ChainError::InvalidName)
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn deterministic_group(
    display_name: &str,
    threshold: u16,
    members: Vec<IdentityPublicDocument>,
) -> Result<GroupProposal, ChainError> {
    GroupProposal::with_nonce(display_name, threshold, members, [0x77; 32])
}

#[cfg(test)]
pub(crate) fn replace_acceptance_signature(
    mut target: GroupAcceptance,
    source: &GroupAcceptance,
) -> GroupAcceptance {
    target.signature.clone_from(&source.signature);
    target
}
