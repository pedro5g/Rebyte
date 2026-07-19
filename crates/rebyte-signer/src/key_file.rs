// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned encrypted local-key documents.

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use rebyte_format::KeyId;
use rebyte_integrity::key_id;
use rebyte_signature::{KeyStatus, Signer, TrustChannel, TrustedPublicKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DOCUMENT_VERSION: u16 = 1;
const PRIVATE_KIND: &str = "rebyte-ed25519-private-key";
const PUBLIC_KIND: &str = "rebyte-ed25519-public-key";
const ENCRYPTION: &str = "argon2id-xchacha20poly1305-v2";
const ENCRYPTION_V1: &str = "argon2id-xchacha20poly1305-v1";
const AAD_DOMAIN: &[u8] = b"rebyte:local-key:v1\0";
const SECRET_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const MIN_PASSPHRASE_BYTES: usize = 12;
const MAX_PASSPHRASE_BYTES: usize = 1_024;
// RFC 9106 high-memory profile: one pass over 256 MiB across four lanes.
// Lanes are computed sequentially by the argon2 crate today; a parallel
// implementation may later cut wall-clock time without a format change.
const KDF_COST: KdfCost = KdfCost {
    memory_kib: 262_144,
    iterations: 1,
    lanes: 4,
};
// v1 documents froze the original 64 MiB, three-pass, single-lane profile.
const KDF_COST_V1: KdfCost = KdfCost {
    memory_kib: 65_536,
    iterations: 3,
    lanes: 1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KdfCost {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

/// JSON document containing an encrypted Ed25519 seed and its public identity.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedPrivateKeyDocument {
    schema_version: u16,
    kind: String,
    encryption: String,
    public_key: String,
    key_id: String,
    salt: String,
    nonce: String,
    encrypted_seed: String,
}

impl fmt::Debug for EncryptedPrivateKeyDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedPrivateKeyDocument")
            .field("schema_version", &self.schema_version)
            .field("kind", &self.kind)
            .field("public_key", &self.public_key)
            .field("key_id", &self.key_id)
            .field("encrypted_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl EncryptedPrivateKeyDocument {
    /// Parses a strict versioned private-key JSON document.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] for malformed JSON, unknown fields,
    /// non-canonical encodings or unsupported document algorithms.
    pub fn from_json(bytes: &[u8]) -> Result<Self, KeyDocumentError> {
        let document: Self =
            serde_json::from_slice(bytes).map_err(|_| KeyDocumentError::InvalidDocument)?;
        document.validate()?;
        Ok(document)
    }

    /// Serializes the document as stable pretty JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError::InvalidDocument`] if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, KeyDocumentError> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|_| KeyDocumentError::InvalidDocument)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Decrypts and validates the seed using the supplied passphrase.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] for a weak passphrase, authentication
    /// failure, invalid public identity or unsupported document parameters.
    pub fn unlock(&self, passphrase: &[u8]) -> Result<LocalKeySigner, KeyDocumentError> {
        validate_passphrase(passphrase)?;
        let fields = self.decode_fields()?;
        let key = derive_encryption_key(passphrase, &fields.salt, self.kdf_cost()?)?;
        let cipher = XChaCha20Poly1305::new(&Key::from(*key));
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(fields.nonce),
                    Payload {
                        msg: &fields.encrypted_seed,
                        aad: &associated_data(
                            &fields.public_key,
                            &fields.key_id,
                            &fields.salt,
                            &fields.nonce,
                        ),
                    },
                )
                .map_err(|_| KeyDocumentError::AuthenticationFailed)?,
        );
        if plaintext.len() != SECRET_BYTES {
            return Err(KeyDocumentError::InvalidDocument);
        }
        let mut seed = Zeroizing::new([0_u8; SECRET_BYTES]);
        seed.as_mut().copy_from_slice(&plaintext);
        let signer = LocalKeySigner {
            key: SigningKey::from_bytes(&seed),
        };
        if signer.public_key() != fields.public_key || key_id(&fields.public_key) != fields.key_id {
            return Err(KeyDocumentError::IdentityMismatch);
        }
        Ok(signer)
    }

    /// Returns the public-key fingerprint stored in the document.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] if the document fields are malformed.
    pub fn key_id(&self) -> Result<KeyId, KeyDocumentError> {
        self.decode_fields().map(|fields| fields.key_id)
    }

    /// Returns the exact passphrase-encryption scheme label of this document.
    #[must_use]
    pub fn encryption_scheme(&self) -> &str {
        &self.encryption
    }

    fn kdf_cost(&self) -> Result<KdfCost, KeyDocumentError> {
        match self.encryption.as_str() {
            ENCRYPTION => Ok(KDF_COST),
            ENCRYPTION_V1 => Ok(KDF_COST_V1),
            _ => Err(KeyDocumentError::UnsupportedDocument),
        }
    }

    fn validate(&self) -> Result<(), KeyDocumentError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != PRIVATE_KIND {
            return Err(KeyDocumentError::UnsupportedDocument);
        }
        self.kdf_cost()?;
        let fields = self.decode_fields()?;
        if key_id(&fields.public_key) != fields.key_id
            || fields.encrypted_seed.len() != SECRET_BYTES + TAG_BYTES
        {
            return Err(KeyDocumentError::IdentityMismatch);
        }
        Ok(())
    }

    fn decode_fields(&self) -> Result<DecodedPrivateFields, KeyDocumentError> {
        Ok(DecodedPrivateFields {
            public_key: decode_array(&self.public_key)?,
            key_id: KeyId(decode_array(&self.key_id)?),
            salt: decode_array(&self.salt)?,
            nonce: decode_array(&self.nonce)?,
            encrypted_seed: decode_canonical(&self.encrypted_seed)?,
        })
    }
}

/// Versioned public trust entry safe to distribute with a deployment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicKeyDocument {
    schema_version: u16,
    kind: String,
    display_name: String,
    channel: DocumentChannel,
    status: DocumentStatus,
    public_key: String,
    key_id: String,
}

impl PublicKeyDocument {
    /// Creates an active public trust document from a validated key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] if the publisher name or key is invalid.
    pub fn new(
        display_name: &str,
        public_key: [u8; 32],
        channel: TrustChannel,
    ) -> Result<Self, KeyDocumentError> {
        let trusted = TrustedPublicKey::new(display_name, public_key, channel, KeyStatus::Active)
            .map_err(|_| KeyDocumentError::InvalidPublicKey)?;
        Ok(Self {
            schema_version: DOCUMENT_VERSION,
            kind: PUBLIC_KIND.to_string(),
            display_name: display_name.to_string(),
            channel: DocumentChannel::from_trust(channel)?,
            status: DocumentStatus::Active,
            public_key: encode(&public_key),
            key_id: encode(trusted.id().as_bytes()),
        })
    }

    /// Parses and fully validates a strict public-key JSON document.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] for malformed JSON, unknown fields,
    /// unsupported versions, invalid Ed25519 points or fingerprint mismatch.
    pub fn from_json(bytes: &[u8]) -> Result<Self, KeyDocumentError> {
        let document: Self =
            serde_json::from_slice(bytes).map_err(|_| KeyDocumentError::InvalidDocument)?;
        document.to_trusted_key()?;
        Ok(document)
    }

    /// Serializes the public document as stable pretty JSON with a newline.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError::InvalidDocument`] if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, KeyDocumentError> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|_| KeyDocumentError::InvalidDocument)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Converts the document into a validated local trust entry.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] if identity, channel, status or key bytes
    /// are invalid.
    pub fn to_trusted_key(&self) -> Result<TrustedPublicKey, KeyDocumentError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != PUBLIC_KIND {
            return Err(KeyDocumentError::UnsupportedDocument);
        }
        let public_key = decode_array(&self.public_key)?;
        let claimed_id = KeyId(decode_array(&self.key_id)?);
        let trusted = TrustedPublicKey::new(
            &self.display_name,
            public_key,
            self.channel.to_trust(),
            self.status.to_status(),
        )
        .map_err(|_| KeyDocumentError::InvalidPublicKey)?;
        if trusted.id() != claimed_id {
            return Err(KeyDocumentError::IdentityMismatch);
        }
        Ok(trusted)
    }

    /// Returns the validated publisher display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the validated local trust channel.
    #[must_use]
    pub const fn channel(&self) -> TrustChannel {
        self.channel.to_trust()
    }

    /// Returns the local administrative status represented by the document.
    #[must_use]
    pub const fn status(&self) -> KeyStatus {
        self.status.to_status()
    }

    /// Changes local trust status without changing the public-key identity.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError::UnsupportedDocument`] for future status
    /// variants unknown to this document version, or
    /// [`KeyDocumentError::InvalidStatusTransition`] when attempting to make a
    /// retired or revoked key active again.
    pub fn with_status(mut self, status: KeyStatus) -> Result<Self, KeyDocumentError> {
        let next = DocumentStatus::from_status(status)?;
        let permitted = matches!(
            (self.status, next),
            (DocumentStatus::Active, _)
                | (
                    DocumentStatus::Retired,
                    DocumentStatus::Retired | DocumentStatus::Revoked
                )
                | (DocumentStatus::Revoked, DocumentStatus::Revoked)
        );
        if !permitted {
            return Err(KeyDocumentError::InvalidStatusTransition);
        }
        self.status = next;
        Ok(self)
    }

    /// Returns the public-key fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] when its canonical encoding is invalid.
    pub fn key_id(&self) -> Result<KeyId, KeyDocumentError> {
        decode_array(&self.key_id).map(KeyId)
    }

    /// Returns the encoded Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyDocumentError`] when its canonical encoding is invalid.
    pub fn public_key(&self) -> Result<[u8; 32], KeyDocumentError> {
        decode_array(&self.public_key)
    }
}

/// Generates a new random Ed25519 key protected by a passphrase.
///
/// Randomness comes directly from the operating system. The returned public
/// document is active and can be distributed to verifier keyrings.
///
/// # Errors
///
/// Returns [`KeyDocumentError`] if entropy is unavailable, the passphrase is
/// outside the supported bounds, metadata is invalid or encryption fails.
pub fn generate_encrypted_key(
    passphrase: &[u8],
    display_name: &str,
    channel: TrustChannel,
) -> Result<(EncryptedPrivateKeyDocument, PublicKeyDocument), KeyDocumentError> {
    validate_passphrase(passphrase)?;
    let mut seed = Zeroizing::new([0_u8; SECRET_BYTES]);
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(seed.as_mut()).map_err(|_| KeyDocumentError::EntropyUnavailable)?;
    getrandom::fill(&mut salt).map_err(|_| KeyDocumentError::EntropyUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| KeyDocumentError::EntropyUnavailable)?;
    encrypt_seed(&seed, passphrase, salt, nonce, display_name, channel)
}

/// In-memory signer unlocked from an encrypted local-key document.
pub struct LocalKeySigner {
    key: SigningKey,
}

impl fmt::Debug for LocalKeySigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalKeySigner")
            .field("public_key", &self.public_key())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Signer for LocalKeySigner {
    type Error = core::convert::Infallible;

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok(ed25519_dalek::Signer::sign(&self.key, message).to_bytes())
    }
}

/// Encrypted or public key-document failure without secret-bearing context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyDocumentError {
    /// The operating system did not provide cryptographic randomness.
    EntropyUnavailable,
    /// Passphrase is shorter than 12 or longer than 1024 bytes.
    InvalidPassphrase,
    /// JSON shape or canonical Base64URL data is invalid.
    InvalidDocument,
    /// Version, kind or cryptographic algorithm is unsupported.
    UnsupportedDocument,
    /// Argon2id key derivation could not be configured or completed.
    KeyDerivation,
    /// XChaCha20-Poly1305 encryption failed.
    EncryptionFailed,
    /// Passphrase is wrong or authenticated key bytes were modified.
    AuthenticationFailed,
    /// Public key or publisher metadata is invalid.
    InvalidPublicKey,
    /// Public key and fingerprint do not match the protected seed.
    IdentityMismatch,
    /// Local trust status attempted to reactivate a retired or revoked key.
    InvalidStatusTransition,
}

impl fmt::Display for KeyDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "operating-system entropy is unavailable",
            Self::InvalidPassphrase => "passphrase must contain 12 to 1024 bytes",
            Self::InvalidDocument => "invalid key document",
            Self::UnsupportedDocument => "unsupported key document version or algorithm",
            Self::KeyDerivation => "key derivation failed",
            Self::EncryptionFailed => "private-key encryption failed",
            Self::AuthenticationFailed => "wrong passphrase or modified private-key document",
            Self::InvalidPublicKey => "invalid publisher name or Ed25519 public key",
            Self::IdentityMismatch => "public key fingerprint does not match key material",
            Self::InvalidStatusTransition => {
                "retired or revoked publisher keys cannot be reactivated"
            }
        })
    }
}

impl std::error::Error for KeyDocumentError {}

struct DecodedPrivateFields {
    public_key: [u8; 32],
    key_id: KeyId,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    encrypted_seed: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DocumentChannel {
    Production,
    Staging,
    Development,
}

impl DocumentChannel {
    const fn from_trust(channel: TrustChannel) -> Result<Self, KeyDocumentError> {
        match channel {
            TrustChannel::Production => Ok(Self::Production),
            TrustChannel::Staging => Ok(Self::Staging),
            TrustChannel::Development => Ok(Self::Development),
            _ => Err(KeyDocumentError::UnsupportedDocument),
        }
    }

    const fn to_trust(self) -> TrustChannel {
        match self {
            Self::Production => TrustChannel::Production,
            Self::Staging => TrustChannel::Staging,
            Self::Development => TrustChannel::Development,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DocumentStatus {
    Active,
    Retired,
    Revoked,
}

impl DocumentStatus {
    const fn from_status(status: KeyStatus) -> Result<Self, KeyDocumentError> {
        match status {
            KeyStatus::Active => Ok(Self::Active),
            KeyStatus::Retired => Ok(Self::Retired),
            KeyStatus::Revoked => Ok(Self::Revoked),
            _ => Err(KeyDocumentError::UnsupportedDocument),
        }
    }

    const fn to_status(self) -> KeyStatus {
        match self {
            Self::Active => KeyStatus::Active,
            Self::Retired => KeyStatus::Retired,
            Self::Revoked => KeyStatus::Revoked,
        }
    }
}

fn encrypt_seed(
    seed: &[u8; SECRET_BYTES],
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    display_name: &str,
    channel: TrustChannel,
) -> Result<(EncryptedPrivateKeyDocument, PublicKeyDocument), KeyDocumentError> {
    let private = encrypt_private_seed(seed, passphrase, salt, nonce)?;
    let public_key = decode_array(&private.public_key)?;
    let public = PublicKeyDocument::new(display_name, public_key, channel)?;
    Ok((private, public))
}

fn encrypt_private_seed(
    seed: &[u8; SECRET_BYTES],
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<EncryptedPrivateKeyDocument, KeyDocumentError> {
    encrypt_private_seed_at(seed, passphrase, salt, nonce, ENCRYPTION, KDF_COST)
}

fn encrypt_private_seed_at(
    seed: &[u8; SECRET_BYTES],
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    scheme: &str,
    cost: KdfCost,
) -> Result<EncryptedPrivateKeyDocument, KeyDocumentError> {
    let signing_key = SigningKey::from_bytes(seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let fingerprint = key_id(&public_key);
    let key = derive_encryption_key(passphrase, &salt, cost)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let encrypted_seed = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: seed,
                aad: &associated_data(&public_key, &fingerprint, &salt, &nonce),
            },
        )
        .map_err(|_| KeyDocumentError::EncryptionFailed)?;
    Ok(EncryptedPrivateKeyDocument {
        schema_version: DOCUMENT_VERSION,
        kind: PRIVATE_KIND.to_string(),
        encryption: scheme.to_string(),
        public_key: encode(&public_key),
        key_id: encode(fingerprint.as_bytes()),
        salt: encode(&salt),
        nonce: encode(&nonce),
        encrypted_seed: encode(&encrypted_seed),
    })
}

/// Re-encrypts a private key under a new passphrase and the current KDF cost.
///
/// The key itself never changes: the same seed is wrapped again with a fresh
/// salt and nonce, upgrading any v1 document to the current Argon2id
/// profile. Pass the same passphrase twice to upgrade in place.
///
/// # Errors
///
/// Returns [`KeyDocumentError`] for a wrong current passphrase, a weak new
/// passphrase, unavailable entropy or a failed encryption.
pub fn rekey_encrypted_key(
    document: &EncryptedPrivateKeyDocument,
    passphrase: &[u8],
    new_passphrase: &[u8],
) -> Result<EncryptedPrivateKeyDocument, KeyDocumentError> {
    document.validate()?;
    validate_passphrase(new_passphrase)?;
    let signer = document.unlock(passphrase)?;
    let seed = Zeroizing::new(signer.key.to_bytes());
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut salt).map_err(|_| KeyDocumentError::EntropyUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| KeyDocumentError::EntropyUnavailable)?;
    encrypt_private_seed(&seed, new_passphrase, salt, nonce)
}

fn derive_encryption_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
    cost: KdfCost,
) -> Result<Zeroizing<[u8; 32]>, KeyDocumentError> {
    let params = Params::new(
        cost.memory_kib,
        cost.iterations,
        cost.lanes,
        Some(SECRET_BYTES),
    )
    .map_err(|_| KeyDocumentError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; SECRET_BYTES]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| KeyDocumentError::KeyDerivation)?;
    Ok(key)
}

fn associated_data(
    public_key: &[u8; 32],
    fingerprint: &KeyId,
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Vec<u8> {
    let capacity = AAD_DOMAIN
        .len()
        .saturating_add(public_key.len())
        .saturating_add(fingerprint.as_bytes().len())
        .saturating_add(salt.len())
        .saturating_add(nonce.len());
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(public_key);
    aad.extend_from_slice(fingerprint.as_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), KeyDocumentError> {
    if (MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&passphrase.len()) {
        Ok(())
    } else {
        Err(KeyDocumentError::InvalidPassphrase)
    }
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_canonical(value: &str) -> Result<Vec<u8>, KeyDocumentError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(KeyDocumentError::InvalidDocument);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| KeyDocumentError::InvalidDocument)?;
    if encode(&decoded) != value {
        return Err(KeyDocumentError::InvalidDocument);
    }
    Ok(decoded)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], KeyDocumentError> {
    decode_canonical(value)?
        .as_slice()
        .try_into()
        .map_err(|_| KeyDocumentError::InvalidDocument)
}

#[cfg(test)]
mod tests {
    use rebyte_signature::{KeyStatus, Signer, TrustChannel};

    use super::{
        ENCRYPTION, ENCRYPTION_V1, EncryptedPrivateKeyDocument, KDF_COST_V1, KeyDocumentError,
        PublicKeyDocument, encrypt_private_seed_at, encrypt_seed, rekey_encrypted_key,
    };

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    #[test]
    fn v1_documents_still_unlock_and_rekey_to_v2() -> Result<(), Box<dyn std::error::Error>> {
        let legacy = encrypt_private_seed_at(
            &[0x42; 32],
            PASSPHRASE,
            [0x11; 16],
            [0x22; 24],
            ENCRYPTION_V1,
            KDF_COST_V1,
        )?;
        assert_eq!(legacy.encryption_scheme(), ENCRYPTION_V1);
        let legacy = EncryptedPrivateKeyDocument::from_json(&legacy.to_json()?)?;
        let signer = legacy.unlock(PASSPHRASE)?;

        let upgraded = rekey_encrypted_key(&legacy, PASSPHRASE, b"an even longer passphrase")?;
        assert_eq!(upgraded.encryption_scheme(), ENCRYPTION);
        assert!(upgraded.unlock(PASSPHRASE).is_err());
        assert_eq!(
            upgraded.unlock(b"an even longer passphrase")?.public_key(),
            signer.public_key()
        );
        assert_eq!(upgraded.key_id()?, legacy.key_id()?);
        Ok(())
    }

    fn fixture() -> Result<(EncryptedPrivateKeyDocument, PublicKeyDocument), KeyDocumentError> {
        encrypt_seed(
            &[0x42; 32],
            PASSPHRASE,
            [0x11; 16],
            [0x22; 24],
            "Production publisher",
            TrustChannel::Production,
        )
    }

    #[test]
    fn encrypted_document_round_trips_and_signs() -> Result<(), Box<dyn std::error::Error>> {
        let (private, public) = fixture()?;
        let debug = format!("{private:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&private.encrypted_seed));
        assert!(!debug.contains(&private.salt));
        let parsed_private = EncryptedPrivateKeyDocument::from_json(&private.to_json()?)?;
        let parsed_public = PublicKeyDocument::from_json(&public.to_json()?)?;
        let signer = parsed_private.unlock(PASSPHRASE)?;
        assert_eq!(signer.public_key(), parsed_public.public_key()?);
        assert_eq!(parsed_private.key_id()?, parsed_public.key_id()?);
        assert_ne!(signer.sign(b"message")?, [0; 64]);
        assert_eq!(parsed_public.to_trusted_key()?.status(), KeyStatus::Active);
        Ok(())
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (private, _) = fixture()?;
        assert!(matches!(
            private.unlock(b"a different long passphrase"),
            Err(KeyDocumentError::AuthenticationFailed)
        ));
        let mut document: serde_json::Value = serde_json::from_slice(&private.to_json()?)?;
        document["nonce"] = serde_json::Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        let bytes = serde_json::to_vec(&document)?;
        let parsed = EncryptedPrivateKeyDocument::from_json(&bytes)?;
        assert!(matches!(
            parsed.unlock(PASSPHRASE),
            Err(KeyDocumentError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn unknown_fields_and_weak_passphrases_are_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_, public) = fixture()?;
        let mut document: serde_json::Value = serde_json::from_slice(&public.to_json()?)?;
        document["unexpected"] = serde_json::Value::Bool(true);
        assert!(matches!(
            PublicKeyDocument::from_json(&serde_json::to_vec(&document)?),
            Err(KeyDocumentError::InvalidDocument)
        ));
        let (private, _) = fixture()?;
        assert!(matches!(
            private.unlock(b"short"),
            Err(KeyDocumentError::InvalidPassphrase)
        ));
        Ok(())
    }

    #[test]
    fn trust_status_only_moves_toward_revocation() -> Result<(), Box<dyn std::error::Error>> {
        let (_, public) = fixture()?;
        let retired = public.with_status(KeyStatus::Retired)?;
        assert!(matches!(
            retired.clone().with_status(KeyStatus::Active),
            Err(KeyDocumentError::InvalidStatusTransition)
        ));
        let revoked = retired.with_status(KeyStatus::Revoked)?;
        assert!(matches!(
            revoked.with_status(KeyStatus::Active),
            Err(KeyDocumentError::InvalidStatusTransition)
        ));
        Ok(())
    }
}
