// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Threshold Shamir backup shares for one complete Chain identity.
//!
//! A backup splits both private seeds into `N` signed share documents with a
//! recovery threshold `T`. Any `T` distinct shares reconstruct the identity
//! without the original passphrase, so every share must be guarded and
//! distributed like a secret. Fewer than `T` shares reveal nothing about the
//! seeds.

#![allow(clippy::redundant_pub_crate)]

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{decode_array, encode_base64, put_u16};
use crate::identity::{reencrypt_identity, unlocked_from_seeds};
use crate::secret_sharing::{SHARE_BYTES, combine_shares, split_secret};
use crate::{ChainError, EncryptedIdentityDocument, IdentityPublicDocument, UnlockedIdentity};

const DOCUMENT_VERSION: u16 = 1;
const SHARE_KIND: &str = "rebyte-chain-identity-backup-share";
const SHARE_SIGNATURE_DOMAIN: &[u8] = b"rebyte chain identity backup share v1\0";
const MIN_BACKUP_THRESHOLD: u16 = 2;
const MAX_BACKUP_SHARES: u16 = 64;

/// One signed Shamir share of a complete private Chain identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBackupShare {
    schema_version: u16,
    kind: String,
    share_count: u16,
    threshold: u16,
    public_identity: IdentityPublicDocument,
    signing_share: String,
    encryption_share: String,
    signature: String,
}

impl IdentityBackupShare {
    /// Parses and verifies one canonical signed backup share.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, non-canonical, unsupported or
    /// invalidly signed data.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let share: Self = serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        share.validate_shape()?;
        if share.to_json()?.as_slice() != bytes {
            return Err(ChainError::InvalidDocument);
        }
        Ok(share)
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

    /// Returns the one-based Shamir coordinate of this share.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] when the share is invalid.
    pub fn share_index(&self) -> Result<u8, ChainError> {
        self.validate_shape()?;
        let share: [u8; SHARE_BYTES] = decode_array(&self.signing_share)?;
        Ok(share[0])
    }

    /// Returns the identity this share can help reconstruct.
    #[must_use]
    pub const fn public_identity(&self) -> &IdentityPublicDocument {
        &self.public_identity
    }

    /// Returns the configured recovery threshold.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Returns the total number of issued shares.
    #[must_use]
    pub const fn share_count(&self) -> u16 {
        self.share_count
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != SHARE_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        validate_backup_parameters(self.share_count, self.threshold)?;
        self.public_identity.validate()?;
        let signing_share: [u8; SHARE_BYTES] = decode_array(&self.signing_share)?;
        let encryption_share: [u8; SHARE_BYTES] = decode_array(&self.encryption_share)?;
        if signing_share[0] == 0
            || signing_share[0] != encryption_share[0]
            || u16::from(signing_share[0]) > self.share_count
        {
            return Err(ChainError::InvalidShare);
        }
        let signature: [u8; 64] = decode_array(&self.signature)?;
        let message = share_message(
            self.share_count,
            self.threshold,
            &signing_share,
            &encryption_share,
            &self.public_identity,
        )?;
        let verifying_key = VerifyingKey::from_bytes(&self.public_identity.signing_public_key()?)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        verifying_key
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| ChainError::InvalidSignature)
    }
}

/// Splits an unlocked identity into `share_count` signed backup shares.
///
/// Distribute each share to a different trustee. Any `threshold` shares
/// reconstruct the complete identity without a passphrase; store them
/// accordingly.
///
/// # Errors
///
/// Returns [`ChainError::InvalidThreshold`] for parameters outside
/// `2 <= threshold <= share_count <= 64`, or another [`ChainError`] when
/// entropy or signing fails.
pub fn backup_identity(
    identity: &UnlockedIdentity,
    share_count: u8,
    threshold: u8,
) -> Result<Vec<IdentityBackupShare>, ChainError> {
    validate_backup_parameters(u16::from(share_count), u16::from(threshold))?;
    let signing_seed = identity.signing_seed();
    let signing_shares = split_secret(&signing_seed, share_count, threshold)?;
    let encryption_shares = split_secret(identity.encryption_ikm(), share_count, threshold)?;
    let mut shares = Vec::with_capacity(usize::from(share_count));
    for (signing_share, encryption_share) in signing_shares.iter().zip(&encryption_shares) {
        let message = share_message(
            u16::from(share_count),
            u16::from(threshold),
            signing_share,
            encryption_share,
            identity.public_identity(),
        )?;
        let share = IdentityBackupShare {
            schema_version: DOCUMENT_VERSION,
            kind: SHARE_KIND.to_string(),
            share_count: u16::from(share_count),
            threshold: u16::from(threshold),
            public_identity: identity.public_identity().clone(),
            signing_share: encode_base64(signing_share.as_ref()),
            encryption_share: encode_base64(encryption_share.as_ref()),
            signature: encode_base64(&identity.sign(&message)),
        };
        share.validate_shape()?;
        shares.push(share);
    }
    Ok(shares)
}

/// Reconstructs an identity from exactly `threshold` distinct shares.
///
/// The reconstructed seeds are verified against the embedded public identity
/// before a fresh encrypted document is produced under `passphrase`.
///
/// # Errors
///
/// Returns [`ChainError`] for invalid, mixed, duplicate, insufficient or
/// excess shares, a weak passphrase, or seeds that do not match the declared
/// public identity.
pub fn restore_identity(
    shares: &[IdentityBackupShare],
    passphrase: &[u8],
) -> Result<(EncryptedIdentityDocument, IdentityPublicDocument), ChainError> {
    let first = shares.first().ok_or(ChainError::InvalidShare)?;
    first.validate_shape()?;
    let threshold = first.threshold;
    if shares.len() != usize::from(threshold) {
        return Err(ChainError::InvalidShare);
    }
    let mut signing_shares: Vec<Zeroizing<[u8; SHARE_BYTES]>> = Vec::with_capacity(shares.len());
    let mut encryption_shares: Vec<Zeroizing<[u8; SHARE_BYTES]>> = Vec::with_capacity(shares.len());
    for share in shares {
        share.validate_shape()?;
        if share.threshold != threshold
            || share.share_count != first.share_count
            || share.public_identity != first.public_identity
        {
            return Err(ChainError::BindingMismatch);
        }
        signing_shares.push(Zeroizing::new(decode_array(&share.signing_share)?));
        encryption_shares.push(Zeroizing::new(decode_array(&share.encryption_share)?));
    }
    signing_shares.sort_unstable_by_key(|share| share[0]);
    encryption_shares.sort_unstable_by_key(|share| share[0]);
    let threshold = u8::try_from(threshold).map_err(|_| ChainError::InvalidThreshold)?;
    let signing_seed = combine_shares(&signing_shares, threshold)?;
    let encryption_ikm = combine_shares(&encryption_shares, threshold)?;
    let unlocked = unlocked_from_seeds(
        &signing_seed,
        encryption_ikm.clone(),
        first.public_identity.clone(),
    )?;
    let private = reencrypt_identity(
        first.public_identity.clone(),
        &signing_seed,
        &encryption_ikm,
        passphrase,
    )?;
    Ok((private, unlocked.public_identity().clone()))
}

const fn validate_backup_parameters(share_count: u16, threshold: u16) -> Result<(), ChainError> {
    if threshold < MIN_BACKUP_THRESHOLD
        || threshold > share_count
        || share_count > MAX_BACKUP_SHARES
    {
        Err(ChainError::InvalidThreshold)
    } else {
        Ok(())
    }
}

fn share_message(
    share_count: u16,
    threshold: u16,
    signing_share: &[u8; SHARE_BYTES],
    encryption_share: &[u8; SHARE_BYTES],
    public: &IdentityPublicDocument,
) -> Result<Vec<u8>, ChainError> {
    let public_bytes = public.canonical_member_bytes()?;
    let mut message = Vec::with_capacity(
        SHARE_SIGNATURE_DOMAIN
            .len()
            .saturating_add(SHARE_BYTES * 2)
            .saturating_add(public_bytes.len())
            .saturating_add(6),
    );
    message.extend_from_slice(SHARE_SIGNATURE_DOMAIN);
    put_u16(&mut message, DOCUMENT_VERSION);
    put_u16(&mut message, share_count);
    put_u16(&mut message, threshold);
    message.extend_from_slice(signing_share.as_ref());
    message.extend_from_slice(encryption_share.as_ref());
    message.extend_from_slice(&public_bytes);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::{IdentityBackupShare, backup_identity, restore_identity};
    use crate::identity::deterministic_identity;

    const TEST_PASSPHRASE: &[u8] = b"test-only-passphrase";
    const NEW_PASSPHRASE: &[u8] = b"fresh-recovery-passphrase";

    #[test]
    fn threshold_shares_restore_the_exact_identity() -> Result<(), Box<dyn std::error::Error>> {
        let (private, public) = deterministic_identity(0x31, "Backup owner")?;
        let identity = private.unlock(TEST_PASSPHRASE)?;
        let shares = backup_identity(&identity, 5, 3)?;
        assert_eq!(shares.len(), 5);
        let selected = vec![shares[4].clone(), shares[0].clone(), shares[2].clone()];
        let (restored_private, restored_public) = restore_identity(&selected, NEW_PASSPHRASE)?;
        assert_eq!(restored_public, public);
        let restored = restored_private.unlock(NEW_PASSPHRASE)?;
        assert_eq!(restored.identity_id(), identity.identity_id());
        assert_eq!(restored.sign(b"probe"), identity.sign(b"probe"));
        assert!(restored_private.unlock(TEST_PASSPHRASE).is_err());
        Ok(())
    }

    #[test]
    fn shares_round_trip_canonically_and_reject_tampering() -> Result<(), Box<dyn std::error::Error>>
    {
        let (private, _) = deterministic_identity(0x32, "Tamper owner")?;
        let identity = private.unlock(TEST_PASSPHRASE)?;
        let shares = backup_identity(&identity, 3, 2)?;
        let bytes = shares[1].to_json()?;
        let parsed = IdentityBackupShare::from_json(&bytes)?;
        assert_eq!(parsed, shares[1]);
        assert_eq!(parsed.share_index()?, 2);
        let mut mutated: serde_json::Value = serde_json::from_slice(&bytes)?;
        mutated["threshold"] = serde_json::json!(3);
        let mut mutated_bytes = serde_json::to_vec_pretty(&mutated)?;
        mutated_bytes.push(b'\n');
        assert!(IdentityBackupShare::from_json(&mutated_bytes).is_err());
        Ok(())
    }

    #[test]
    fn wrong_share_sets_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (first_private, _) = deterministic_identity(0x33, "First owner")?;
        let (second_private, _) = deterministic_identity(0x44, "Second owner")?;
        let first = first_private.unlock(TEST_PASSPHRASE)?;
        let second = second_private.unlock(TEST_PASSPHRASE)?;
        let first_shares = backup_identity(&first, 3, 2)?;
        let second_shares = backup_identity(&second, 3, 2)?;
        assert!(restore_identity(&first_shares[..1], NEW_PASSPHRASE).is_err());
        assert!(restore_identity(&first_shares, NEW_PASSPHRASE).is_err());
        assert!(
            restore_identity(
                &[first_shares[0].clone(), first_shares[0].clone()],
                NEW_PASSPHRASE
            )
            .is_err()
        );
        assert!(
            restore_identity(
                &[first_shares[0].clone(), second_shares[1].clone()],
                NEW_PASSPHRASE
            )
            .is_err()
        );
        assert!(backup_identity(&first, 3, 1).is_err());
        assert!(backup_identity(&first, 2, 3).is_err());
        Ok(())
    }
}
