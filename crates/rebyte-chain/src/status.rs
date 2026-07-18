// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed administrative status documents for Chain identities.
//!
//! A status document is the identity owner's portable, verifiable statement
//! that an identity must no longer be admitted to new groups, recipient lists
//! or witness sets. Like RAP key status, `retired` communicates planned
//! removal and `revoked` communicates compromise; Chain has no trusted time,
//! so both reject the identity for every new operation while historical
//! envelopes remain openable. Distribution is offline and best-effort: a peer
//! that never receives the document cannot enforce it.

#![allow(clippy::redundant_pub_crate)]

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::codec::{decode_array, encode_base64, put_u16};
use crate::{ChainError, IdentityId, IdentityPublicDocument, UnlockedIdentity};

const DOCUMENT_VERSION: u16 = 1;
const STATUS_KIND: &str = "rebyte-chain-identity-status";
const STATUS_SIGNATURE_DOMAIN: &[u8] = b"rebyte chain identity status v1\0";
const RETIRED: &str = "retired";
const REVOKED: &str = "revoked";

/// Administrative status the identity owner assigns to its own identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IdentityStatus {
    /// Planned removal; the identity must not join new operations.
    Retired,
    /// Compromise; the identity must not join new operations.
    Revoked,
}

impl IdentityStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Retired => RETIRED,
            Self::Revoked => REVOKED,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Retired => 1,
            Self::Revoked => 2,
        }
    }
}

/// Portable owner-signed statement retiring or revoking one identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityStatusDocument {
    schema_version: u16,
    kind: String,
    status: String,
    public_identity: IdentityPublicDocument,
    signature: String,
}

impl IdentityStatusDocument {
    /// Parses and verifies one canonical signed status document.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, non-canonical, unsupported or
    /// invalidly signed data.
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

    /// Returns the declared administrative status.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::UnsupportedDocument`] for an unknown status.
    pub fn status(&self) -> Result<IdentityStatus, ChainError> {
        match self.status.as_str() {
            RETIRED => Ok(IdentityStatus::Retired),
            REVOKED => Ok(IdentityStatus::Revoked),
            _ => Err(ChainError::UnsupportedDocument),
        }
    }

    /// Returns the identity this document retires or revokes.
    #[must_use]
    pub const fn public_identity(&self) -> &IdentityPublicDocument {
        &self.public_identity
    }

    /// Returns the verified identity fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] when the document is invalid.
    pub fn identity_id(&self) -> Result<IdentityId, ChainError> {
        self.validate_shape()?;
        self.public_identity.identity_id_unchecked()
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != STATUS_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        let status = self.status()?;
        self.public_identity.validate()?;
        let signature: [u8; 64] = decode_array(&self.signature)?;
        let message = status_message(status, &self.public_identity)?;
        let verifying_key = VerifyingKey::from_bytes(&self.public_identity.signing_public_key()?)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        verifying_key
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| ChainError::InvalidSignature)
    }
}

/// Issues an owner-signed status document for the unlocked identity.
///
/// # Errors
///
/// Returns [`ChainError`] when the public identity or signing fails
/// validation.
pub fn issue_identity_status(
    identity: &UnlockedIdentity,
    status: IdentityStatus,
) -> Result<IdentityStatusDocument, ChainError> {
    let message = status_message(status, identity.public_identity())?;
    let document = IdentityStatusDocument {
        schema_version: DOCUMENT_VERSION,
        kind: STATUS_KIND.to_string(),
        status: status.as_str().to_string(),
        public_identity: identity.public_identity().clone(),
        signature: encode_base64(&identity.sign(&message)),
    };
    document.validate_shape()?;
    Ok(document)
}

/// Rejects any listed identity that a verified status document denies.
///
/// # Errors
///
/// Returns [`ChainError::IdentityMismatch`] naming no identity when one of
/// `identity_ids` is retired or revoked, or another [`ChainError`] for an
/// invalid status document.
pub fn deny_statused_identities(
    status_documents: &[IdentityStatusDocument],
    identity_ids: &[IdentityId],
) -> Result<(), ChainError> {
    for document in status_documents {
        let denied = document.identity_id()?;
        if identity_ids.contains(&denied) {
            return Err(ChainError::IdentityMismatch);
        }
    }
    Ok(())
}

fn status_message(
    status: IdentityStatus,
    public: &IdentityPublicDocument,
) -> Result<Vec<u8>, ChainError> {
    let public_bytes = public.canonical_member_bytes()?;
    let mut message = Vec::with_capacity(
        STATUS_SIGNATURE_DOMAIN
            .len()
            .saturating_add(public_bytes.len())
            .saturating_add(3),
    );
    message.extend_from_slice(STATUS_SIGNATURE_DOMAIN);
    put_u16(&mut message, DOCUMENT_VERSION);
    message.push(status.code());
    message.extend_from_slice(&public_bytes);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::{
        IdentityStatus, IdentityStatusDocument, deny_statused_identities, issue_identity_status,
    };
    use crate::identity::deterministic_identity;

    const TEST_PASSPHRASE: &[u8] = b"test-only-passphrase";

    #[test]
    fn status_documents_round_trip_and_bind_the_status() -> Result<(), Box<dyn std::error::Error>> {
        let (private, public) = deterministic_identity(0x51, "Status owner")?;
        let identity = private.unlock(TEST_PASSPHRASE)?;
        let document = issue_identity_status(&identity, IdentityStatus::Revoked)?;
        let bytes = document.to_json()?;
        let parsed = IdentityStatusDocument::from_json(&bytes)?;
        assert_eq!(parsed.status()?, IdentityStatus::Revoked);
        assert_eq!(parsed.identity_id()?, public.identity_id()?);
        let mut flipped: serde_json::Value = serde_json::from_slice(&bytes)?;
        flipped["status"] = serde_json::json!("retired");
        let mut flipped_bytes = serde_json::to_vec_pretty(&flipped)?;
        flipped_bytes.push(b'\n');
        assert!(IdentityStatusDocument::from_json(&flipped_bytes).is_err());
        Ok(())
    }

    #[test]
    fn foreign_signatures_and_denied_identities_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (owner_private, owner_public) = deterministic_identity(0x52, "Owner")?;
        let (other_private, other_public) = deterministic_identity(0x53, "Other")?;
        let owner = owner_private.unlock(TEST_PASSPHRASE)?;
        let other = other_private.unlock(TEST_PASSPHRASE)?;
        let owner_status = issue_identity_status(&owner, IdentityStatus::Retired)?;
        let other_status = issue_identity_status(&other, IdentityStatus::Revoked)?;
        let mut forged: serde_json::Value = serde_json::from_slice(&owner_status.to_json()?)?;
        let donor: serde_json::Value = serde_json::from_slice(&other_status.to_json()?)?;
        forged["signature"] = donor["signature"].clone();
        let mut forged_bytes = serde_json::to_vec_pretty(&forged)?;
        forged_bytes.push(b'\n');
        assert!(IdentityStatusDocument::from_json(&forged_bytes).is_err());

        let owner_id = owner_public.identity_id()?;
        let other_id = other_public.identity_id()?;
        assert!(
            deny_statused_identities(core::slice::from_ref(&owner_status), &[owner_id]).is_err()
        );
        deny_statused_identities(core::slice::from_ref(&owner_status), &[other_id])?;
        deny_statused_identities(&[], &[owner_id, other_id])?;
        Ok(())
    }
}
