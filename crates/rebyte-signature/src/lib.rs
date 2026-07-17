// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 verification and local publisher trust policy for RAP v1.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use rebyte_format::{Digest32, KeyId};
use rebyte_integrity::{key_id, signature_message};

const MAX_PUBLISHER_NAME_BYTES: usize = 256;

/// Environment in which a trusted key is authorized.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TrustChannel {
    /// Public production artifacts.
    Production,
    /// Pre-production artifacts requiring explicit opt-in.
    Staging,
    /// Local development artifacts requiring explicit opt-in.
    Development,
}

/// Administrative status of a key in the local keyring.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KeyStatus {
    /// The key may be accepted according to its channel.
    Active,
    /// The key is no longer accepted because RAP v1 has no trusted timestamp.
    Retired,
    /// The key is known to be unsafe and is never accepted.
    Revoked,
}

/// Public key and local authorization metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPublicKey {
    id: KeyId,
    public_key: [u8; 32],
    display_name: String,
    channel: TrustChannel,
    status: KeyStatus,
}

impl TrustedPublicKey {
    /// Creates a key entry and derives its immutable RAP key ID.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::InvalidPublisherName`] for an empty or
    /// oversized display name, or [`SignatureError::InvalidPublicKey`] when
    /// Ed25519 rejects the encoded point.
    pub fn new(
        display_name: &str,
        public_key: [u8; 32],
        channel: TrustChannel,
        status: KeyStatus,
    ) -> Result<Self, SignatureError> {
        validate_name(display_name)?;
        VerifyingKey::from_bytes(&public_key).map_err(|_| SignatureError::InvalidPublicKey)?;
        Ok(Self {
            id: key_id(&public_key),
            public_key,
            display_name: display_name.to_string(),
            channel,
            status,
        })
    }

    /// Returns the derived publisher key ID.
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    /// Returns the encoded Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the trusted local display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the local trust channel.
    #[must_use]
    pub const fn channel(&self) -> TrustChannel {
        self.channel
    }

    /// Returns the local administrative status.
    #[must_use]
    pub const fn status(&self) -> KeyStatus {
        self.status
    }
}

/// Small explicit keyring used for trust decisions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedKeyring {
    keys: Vec<TrustedPublicKey>,
}

impl TrustedKeyring {
    /// Validates uniqueness and builds a keyring.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::DuplicateKey`] if two entries derive the same
    /// key ID.
    pub fn new(keys: Vec<TrustedPublicKey>) -> Result<Self, SignatureError> {
        for (position, key) in keys.iter().enumerate() {
            if keys
                .get(..position)
                .is_some_and(|previous| previous.iter().any(|candidate| candidate.id == key.id))
            {
                return Err(SignatureError::DuplicateKey);
            }
        }
        Ok(Self { keys })
    }

    /// Returns the trusted entry for `id`, if present.
    #[must_use]
    pub fn get(&self, id: &KeyId) -> Option<&TrustedPublicKey> {
        self.keys.iter().find(|key| key.id == *id)
    }

    /// Returns the number of trusted entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns whether the keyring is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Channels a caller explicitly permits for this verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    /// Permit active staging publishers.
    pub allow_staging: bool,
    /// Permit active development publishers.
    pub allow_development: bool,
}

impl VerificationPolicy {
    /// Production-only trust policy.
    pub const PRODUCTION: Self = Self {
        allow_staging: false,
        allow_development: false,
    };
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// Trusted publisher information returned after signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPublisher {
    /// Publisher fingerprint.
    pub key_id: KeyId,
    /// Trusted local display name.
    pub display_name: String,
    /// Accepted trust channel.
    pub channel: TrustChannel,
}

/// Restricted signing interface implemented by signer adapters.
pub trait Signer {
    /// Adapter-specific signing error.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Returns the encoded Ed25519 public key corresponding to the signer.
    fn public_key(&self) -> [u8; 32];

    /// Signs an already domain-separated fixed RAP message.
    ///
    /// # Errors
    ///
    /// Returns the adapter-specific error without exposing private material.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
}

/// Verifies key identity, local trust policy and an Ed25519 signature.
///
/// # Errors
///
/// Returns [`SignatureError`] when the key is unknown or disallowed, public
/// key material is malformed, or the signature does not authenticate `digest`.
pub fn verify_signature(
    publisher_key_id: &KeyId,
    digest: &Digest32,
    signature_bytes: &[u8; 64],
    policy: &VerificationPolicy,
    keyring: &TrustedKeyring,
) -> Result<VerifiedPublisher, SignatureError> {
    let trusted = keyring
        .get(publisher_key_id)
        .ok_or(SignatureError::UnknownKey)?;
    enforce_policy(trusted, policy)?;
    let verifying_key = VerifyingKey::from_bytes(trusted.public_key())
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(&signature_message(digest), &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    Ok(VerifiedPublisher {
        key_id: trusted.id(),
        display_name: trusted.display_name().to_string(),
        channel: trusted.channel(),
    })
}

/// Signature and trust-policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureError {
    /// Publisher display name was empty or oversized.
    InvalidPublisherName,
    /// Ed25519 public key bytes were invalid.
    InvalidPublicKey,
    /// Two keyring entries had the same fingerprint.
    DuplicateKey,
    /// Capsule key ID was not present in the local keyring.
    UnknownKey,
    /// Publisher channel requires explicit opt-in.
    DisallowedChannel,
    /// Publisher key has been retired.
    RetiredKey,
    /// Publisher key has been revoked.
    RevokedKey,
    /// Ed25519 signature verification failed.
    InvalidSignature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublisherName => "invalid publisher display name",
            Self::InvalidPublicKey => "invalid Ed25519 public key",
            Self::DuplicateKey => "duplicate publisher key ID",
            Self::UnknownKey => "unknown publisher key",
            Self::DisallowedChannel => "publisher trust channel is not allowed",
            Self::RetiredKey => "publisher key is retired",
            Self::RevokedKey => "publisher key is revoked",
            Self::InvalidSignature => "invalid capsule signature",
        })
    }
}

impl core::error::Error for SignatureError {}

const fn validate_name(name: &str) -> Result<(), SignatureError> {
    if name.is_empty() || name.len() > MAX_PUBLISHER_NAME_BYTES {
        Err(SignatureError::InvalidPublisherName)
    } else {
        Ok(())
    }
}

const fn enforce_policy(
    key: &TrustedPublicKey,
    policy: &VerificationPolicy,
) -> Result<(), SignatureError> {
    match key.status {
        KeyStatus::Retired => return Err(SignatureError::RetiredKey),
        KeyStatus::Revoked => return Err(SignatureError::RevokedKey),
        KeyStatus::Active => {}
    }
    match key.channel {
        TrustChannel::Production => Ok(()),
        TrustChannel::Staging if policy.allow_staging => Ok(()),
        TrustChannel::Development if policy.allow_development => Ok(()),
        TrustChannel::Staging | TrustChannel::Development => Err(SignatureError::DisallowedChannel),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rebyte_format::Digest32;
    use rebyte_integrity::{key_id, signature_message};

    use super::{
        KeyStatus, SignatureError, TrustChannel, TrustedKeyring, TrustedPublicKey,
        VerificationPolicy, verify_signature,
    };

    // This deterministic key is public test material and must never be trusted
    // outside these tests.
    const TEST_SECRET: [u8; 32] = [0x42; 32];

    fn signed_fixture(
        channel: TrustChannel,
        status: KeyStatus,
    ) -> Result<([u8; 64], Digest32, TrustedKeyring), SignatureError> {
        let signing_key = SigningKey::from_bytes(&TEST_SECRET);
        let public_key = signing_key.verifying_key().to_bytes();
        let digest = Digest32([7; 32]);
        let signature = signing_key.sign(&signature_message(&digest)).to_bytes();
        let trusted = TrustedPublicKey::new("test-only", public_key, channel, status)?;
        let keyring = TrustedKeyring::new(vec![trusted])?;
        Ok((signature, digest, keyring))
    }

    #[test]
    fn production_signature_is_accepted() -> Result<(), SignatureError> {
        let (signature, digest, keyring) =
            signed_fixture(TrustChannel::Production, KeyStatus::Active)?;
        let id = key_id(
            &SigningKey::from_bytes(&TEST_SECRET)
                .verifying_key()
                .to_bytes(),
        );
        let publisher = verify_signature(
            &id,
            &digest,
            &signature,
            &VerificationPolicy::PRODUCTION,
            &keyring,
        )?;
        assert_eq!(publisher.display_name, "test-only");
        Ok(())
    }

    #[test]
    fn development_requires_opt_in() -> Result<(), SignatureError> {
        let (signature, digest, keyring) =
            signed_fixture(TrustChannel::Development, KeyStatus::Active)?;
        let id = key_id(
            &SigningKey::from_bytes(&TEST_SECRET)
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(
            verify_signature(
                &id,
                &digest,
                &signature,
                &VerificationPolicy::PRODUCTION,
                &keyring,
            ),
            Err(SignatureError::DisallowedChannel)
        );
        let policy = VerificationPolicy {
            allow_staging: false,
            allow_development: true,
        };
        assert!(verify_signature(&id, &digest, &signature, &policy, &keyring).is_ok());
        Ok(())
    }

    #[test]
    fn modified_signature_is_rejected() -> Result<(), SignatureError> {
        let (mut signature, digest, keyring) =
            signed_fixture(TrustChannel::Production, KeyStatus::Active)?;
        signature[0] ^= 1;
        let id = key_id(
            &SigningKey::from_bytes(&TEST_SECRET)
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(
            verify_signature(
                &id,
                &digest,
                &signature,
                &VerificationPolicy::PRODUCTION,
                &keyring,
            ),
            Err(SignatureError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn revoked_key_is_rejected_before_crypto() -> Result<(), SignatureError> {
        let (signature, digest, keyring) =
            signed_fixture(TrustChannel::Production, KeyStatus::Revoked)?;
        let id = key_id(
            &SigningKey::from_bytes(&TEST_SECRET)
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(
            verify_signature(
                &id,
                &digest,
                &signature,
                &VerificationPolicy::PRODUCTION,
                &keyring,
            ),
            Err(SignatureError::RevokedKey)
        );
        Ok(())
    }
}
