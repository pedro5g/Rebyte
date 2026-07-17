// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::redundant_pub_crate)]

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable as _, Kem as _, Serializable as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ChainError;
use crate::codec::{decode_array, domain_hash, encode_base64, put_bytes_u16, put_u16, put_u32};

const DOCUMENT_VERSION: u16 = 1;
const PUBLIC_KIND: &str = "rebyte-chain-identity-public";
const PRIVATE_KIND: &str = "rebyte-chain-identity-private";
const PRIVATE_ENCRYPTION: &str = "argon2id-xchacha20poly1305-v1";
const SIGNATURE_DOMAIN: &[u8] = b"rebyte chain identity proof v1\0";
const PRIVATE_AAD_DOMAIN: &[u8] = b"rebyte chain private identity v1\0";
const MIN_PASSPHRASE_BYTES: usize = 12;
const MAX_PASSPHRASE_BYTES: usize = 1_024;
const MAX_NAME_BYTES: usize = 256;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const SEED_BYTES: usize = 32;
const SECRET_PLAINTEXT_BYTES: usize = SEED_BYTES * 2;
const TAG_BYTES: usize = 16;
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_LANES: u32 = 1;

pub(crate) type ChainKem = X25519HkdfSha256;
pub(crate) type HpkePrivateKey = <ChainKem as hpke::Kem>::PrivateKey;
pub(crate) type HpkePublicKey = <ChainKem as hpke::Kem>::PublicKey;

/// Domain-separated identity fingerprint covering both purpose-specific keys.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityId(pub(crate) [u8; 32]);

impl IdentityId {
    /// Returns the binary 32-byte identity.
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

/// Distributable identity package binding signing and HPKE public keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityPublicDocument {
    schema_version: u16,
    kind: String,
    display_name: String,
    signing_public_key: String,
    encryption_public_key: String,
    package_nonce: String,
    identity_id: String,
    proof_signature: String,
}

impl IdentityPublicDocument {
    /// Parses a canonical, self-signed public identity document.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed JSON, unsupported fields,
    /// non-canonical serialization, key mismatch or an invalid proof.
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

    /// Returns the validated identity fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the public package is invalid.
    pub fn identity_id(&self) -> Result<IdentityId, ChainError> {
        self.validate()?;
        Ok(IdentityId(decode_array(&self.identity_id)?))
    }

    /// Returns the human-readable identity name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the validated Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed or invalid public key bytes.
    pub fn signing_public_key(&self) -> Result<[u8; 32], ChainError> {
        let bytes = decode_array(&self.signing_public_key)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| ChainError::InvalidPublicKey)?;
        Ok(bytes)
    }

    /// Returns the validated X25519 HPKE public key.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed public key bytes.
    pub fn encryption_public_key(&self) -> Result<[u8; 32], ChainError> {
        let bytes = decode_array(&self.encryption_public_key)?;
        HpkePublicKey::from_bytes(&bytes).map_err(|_| ChainError::InvalidPublicKey)?;
        Ok(bytes)
    }

    pub(crate) fn validate(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != PUBLIC_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        validate_name(&self.display_name)?;
        let signing_public_key = self.signing_public_key()?;
        let encryption_public_key = self.encryption_public_key()?;
        let package_nonce = decode_array(&self.package_nonce)?;
        let proof_signature: [u8; 64] = decode_array(&self.proof_signature)?;
        let message = identity_message(
            &self.display_name,
            &signing_public_key,
            &encryption_public_key,
            &package_nonce,
        )?;
        let verifying_key = VerifyingKey::from_bytes(&signing_public_key)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        verifying_key
            .verify(&message, &Signature::from_bytes(&proof_signature))
            .map_err(|_| ChainError::InvalidSignature)?;
        let expected = identity_id(&message, &proof_signature);
        if decode_array::<32>(&self.identity_id)? != expected.0 {
            return Err(ChainError::IdentityMismatch);
        }
        Ok(())
    }

    pub(crate) fn canonical_member_bytes(&self) -> Result<Vec<u8>, ChainError> {
        self.validate()?;
        let mut bytes = identity_message(
            &self.display_name,
            &self.signing_public_key()?,
            &self.encryption_public_key()?,
            &decode_array(&self.package_nonce)?,
        )?;
        bytes.extend_from_slice(&decode_array::<64>(&self.proof_signature)?);
        Ok(bytes)
    }
}

/// Passphrase-protected identity containing independent signing and HPKE seeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedIdentityDocument {
    schema_version: u16,
    kind: String,
    encryption: String,
    kdf_memory_kib: u32,
    kdf_iterations: u32,
    kdf_lanes: u32,
    public_identity: IdentityPublicDocument,
    salt: String,
    nonce: String,
    encrypted_secrets: String,
}

impl EncryptedIdentityDocument {
    /// Parses and validates a canonical encrypted identity document.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed JSON, invalid public identity,
    /// unsupported KDF parameters or non-canonical bytes.
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

    /// Returns the embedded validated public identity.
    #[must_use]
    pub const fn public_identity(&self) -> &IdentityPublicDocument {
        &self.public_identity
    }

    /// Decrypts and validates both purpose-specific private seeds.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for a weak or incorrect passphrase, modified
    /// document, failed KDF, or public/private identity mismatch.
    pub fn unlock(&self, passphrase: &[u8]) -> Result<UnlockedIdentity, ChainError> {
        self.validate()?;
        validate_passphrase(passphrase)?;
        let salt = decode_array(&self.salt)?;
        let nonce = decode_array(&self.nonce)?;
        let encrypted =
            decode_array::<{ SECRET_PLAINTEXT_BYTES + TAG_BYTES }>(&self.encrypted_secrets)?;
        let key = derive_encryption_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| ChainError::CryptographicFailure)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &encrypted,
                        aad: &private_aad(&self.public_identity, &salt, &nonce)?,
                    },
                )
                .map_err(|_| ChainError::AuthenticationFailed)?,
        );
        let signing_seed: [u8; SEED_BYTES] = plaintext
            .get(..SEED_BYTES)
            .ok_or(ChainError::IdentityMismatch)?
            .try_into()
            .map_err(|_| ChainError::IdentityMismatch)?;
        let encryption_ikm: [u8; SEED_BYTES] = plaintext
            .get(SEED_BYTES..SECRET_PLAINTEXT_BYTES)
            .ok_or(ChainError::IdentityMismatch)?
            .try_into()
            .map_err(|_| ChainError::IdentityMismatch)?;
        unlocked_from_seeds(
            &signing_seed,
            Zeroizing::new(encryption_ikm),
            self.public_identity.clone(),
        )
    }

    fn validate(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION
            || self.kind != PRIVATE_KIND
            || self.encryption != PRIVATE_ENCRYPTION
            || self.kdf_memory_kib != KDF_MEMORY_KIB
            || self.kdf_iterations != KDF_ITERATIONS
            || self.kdf_lanes != KDF_LANES
        {
            return Err(ChainError::UnsupportedDocument);
        }
        self.public_identity.validate()?;
        let _salt: [u8; SALT_BYTES] = decode_array(&self.salt)?;
        let _nonce: [u8; NONCE_BYTES] = decode_array(&self.nonce)?;
        let _encrypted: [u8; SECRET_PLAINTEXT_BYTES + TAG_BYTES] =
            decode_array(&self.encrypted_secrets)?;
        Ok(())
    }
}

/// Unlocked in-memory identity with redacted debug output.
pub struct UnlockedIdentity {
    signing_key: SigningKey,
    encryption_ikm: Zeroizing<[u8; SEED_BYTES]>,
    public_identity: IdentityPublicDocument,
    identity_id: IdentityId,
}

impl UnlockedIdentity {
    /// Returns the public identity corresponding to these secrets.
    #[must_use]
    pub const fn public_identity(&self) -> &IdentityPublicDocument {
        &self.public_identity
    }

    /// Returns the immutable identity fingerprint.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub(crate) fn hpke_private_key(&self) -> HpkePrivateKey {
        ChainKem::derive_keypair(self.encryption_ikm.as_ref()).0
    }
}

impl fmt::Debug for UnlockedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedIdentity")
            .field("identity_id", &self.identity_id)
            .field("secret", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Generates a fresh independent signing and encryption identity.
///
/// # Errors
///
/// Returns [`ChainError`] if entropy, passphrase validation, key derivation,
/// public identity validation or authenticated encryption fails.
pub fn generate_identity(
    display_name: &str,
    passphrase: &[u8],
) -> Result<(EncryptedIdentityDocument, IdentityPublicDocument), ChainError> {
    validate_name(display_name)?;
    validate_passphrase(passphrase)?;
    let mut signing_seed = Zeroizing::new([0_u8; SEED_BYTES]);
    let mut encryption_ikm = Zeroizing::new([0_u8; SEED_BYTES]);
    let mut package_nonce = [0_u8; SEED_BYTES];
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(signing_seed.as_mut()).map_err(|_| ChainError::EntropyUnavailable)?;
    getrandom::fill(encryption_ikm.as_mut()).map_err(|_| ChainError::EntropyUnavailable)?;
    getrandom::fill(&mut package_nonce).map_err(|_| ChainError::EntropyUnavailable)?;
    getrandom::fill(&mut salt).map_err(|_| ChainError::EntropyUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| ChainError::EntropyUnavailable)?;
    let material = IdentityRandomMaterial {
        signing_seed,
        encryption_ikm,
        package_nonce,
        salt,
        nonce,
    };
    create_identity_documents(display_name, passphrase, &material)
}

struct IdentityRandomMaterial {
    signing_seed: Zeroizing<[u8; SEED_BYTES]>,
    encryption_ikm: Zeroizing<[u8; SEED_BYTES]>,
    package_nonce: [u8; SEED_BYTES],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
}

fn create_identity_documents(
    display_name: &str,
    passphrase: &[u8],
    material: &IdentityRandomMaterial,
) -> Result<(EncryptedIdentityDocument, IdentityPublicDocument), ChainError> {
    let signing_key = SigningKey::from_bytes(&material.signing_seed);
    let signing_public_key = signing_key.verifying_key().to_bytes();
    let (_, encryption_public_key) = ChainKem::derive_keypair(material.encryption_ikm.as_ref());
    let encryption_public_key: [u8; 32] = encryption_public_key
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::InvalidPublicKey)?;
    let message = identity_message(
        display_name,
        &signing_public_key,
        &encryption_public_key,
        &material.package_nonce,
    )?;
    let proof_signature = signing_key.sign(&message).to_bytes();
    let fingerprint = identity_id(&message, &proof_signature);
    let public = IdentityPublicDocument {
        schema_version: DOCUMENT_VERSION,
        kind: PUBLIC_KIND.to_string(),
        display_name: display_name.to_string(),
        signing_public_key: encode_base64(&signing_public_key),
        encryption_public_key: encode_base64(&encryption_public_key),
        package_nonce: encode_base64(&material.package_nonce),
        identity_id: fingerprint.to_base64(),
        proof_signature: encode_base64(&proof_signature),
    };
    public.validate()?;

    let mut secrets = Zeroizing::new([0_u8; SECRET_PLAINTEXT_BYTES]);
    secrets
        .get_mut(..SEED_BYTES)
        .ok_or(ChainError::LengthOverflow)?
        .copy_from_slice(material.signing_seed.as_ref());
    secrets
        .get_mut(SEED_BYTES..)
        .ok_or(ChainError::LengthOverflow)?
        .copy_from_slice(material.encryption_ikm.as_ref());
    let key = derive_encryption_key(passphrase, &material.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| ChainError::CryptographicFailure)?;
    let encrypted = cipher
        .encrypt(
            &XNonce::from(material.nonce),
            Payload {
                msg: secrets.as_ref(),
                aad: &private_aad(&public, &material.salt, &material.nonce)?,
            },
        )
        .map_err(|_| ChainError::EncryptionFailed)?;
    let private = EncryptedIdentityDocument {
        schema_version: DOCUMENT_VERSION,
        kind: PRIVATE_KIND.to_string(),
        encryption: PRIVATE_ENCRYPTION.to_string(),
        kdf_memory_kib: KDF_MEMORY_KIB,
        kdf_iterations: KDF_ITERATIONS,
        kdf_lanes: KDF_LANES,
        public_identity: public.clone(),
        salt: encode_base64(&material.salt),
        nonce: encode_base64(&material.nonce),
        encrypted_secrets: encode_base64(&encrypted),
    };
    private.validate()?;
    Ok((private, public))
}

fn unlocked_from_seeds(
    signing_seed: &[u8; SEED_BYTES],
    encryption_ikm: Zeroizing<[u8; SEED_BYTES]>,
    public_identity: IdentityPublicDocument,
) -> Result<UnlockedIdentity, ChainError> {
    let signing_key = SigningKey::from_bytes(signing_seed);
    if signing_key.verifying_key().to_bytes() != public_identity.signing_public_key()? {
        return Err(ChainError::IdentityMismatch);
    }
    let (_, encryption_public_key) = ChainKem::derive_keypair(encryption_ikm.as_ref());
    if encryption_public_key.to_bytes().as_slice()
        != public_identity.encryption_public_key()?.as_slice()
    {
        return Err(ChainError::IdentityMismatch);
    }
    let identity_id = public_identity.identity_id()?;
    Ok(UnlockedIdentity {
        signing_key,
        encryption_ikm,
        public_identity,
        identity_id,
    })
}

fn identity_message(
    display_name: &str,
    signing_public_key: &[u8; 32],
    encryption_public_key: &[u8; 32],
    package_nonce: &[u8; 32],
) -> Result<Vec<u8>, ChainError> {
    validate_name(display_name)?;
    let mut message = Vec::with_capacity(160_usize.saturating_add(display_name.len()));
    message.extend_from_slice(SIGNATURE_DOMAIN);
    put_u16(&mut message, DOCUMENT_VERSION);
    put_bytes_u16(&mut message, display_name.as_bytes())?;
    message.extend_from_slice(signing_public_key);
    message.extend_from_slice(encryption_public_key);
    message.extend_from_slice(package_nonce);
    Ok(message)
}

fn identity_id(message: &[u8], signature: &[u8; 64]) -> IdentityId {
    IdentityId(domain_hash(
        "Rebyte Chain identity id v1 2026-07-17",
        &[message, signature],
    ))
}

fn private_aad(
    public: &IdentityPublicDocument,
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>, ChainError> {
    let public_bytes = public.canonical_member_bytes()?;
    let mut aad = Vec::with_capacity(
        PRIVATE_AAD_DOMAIN
            .len()
            .saturating_add(public_bytes.len())
            .saturating_add(SALT_BYTES)
            .saturating_add(NONCE_BYTES)
            .saturating_add(12),
    );
    aad.extend_from_slice(PRIVATE_AAD_DOMAIN);
    put_u32(&mut aad, KDF_MEMORY_KIB);
    put_u32(&mut aad, KDF_ITERATIONS);
    put_u32(&mut aad, KDF_LANES);
    aad.extend_from_slice(&public_bytes);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    Ok(aad)
}

fn derive_encryption_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, ChainError> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_LANES, Some(SEED_BYTES))
        .map_err(|_| ChainError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; SEED_BYTES]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| ChainError::KeyDerivation)?;
    Ok(key)
}

fn validate_name(value: &str) -> Result<(), ChainError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '\u{7f}')
    {
        Err(ChainError::InvalidName)
    } else {
        Ok(())
    }
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), ChainError> {
    if (MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&passphrase.len()) {
        Ok(())
    } else {
        Err(ChainError::InvalidPassphrase)
    }
}

#[cfg(test)]
pub(crate) fn deterministic_identity(
    marker: u8,
    display_name: &str,
) -> Result<(EncryptedIdentityDocument, IdentityPublicDocument), ChainError> {
    let material = IdentityRandomMaterial {
        signing_seed: Zeroizing::new([marker; 32]),
        encryption_ikm: Zeroizing::new([marker.wrapping_add(1); 32]),
        package_nonce: [marker.wrapping_add(2); 32],
        salt: [marker.wrapping_add(3); 16],
        nonce: [marker.wrapping_add(4); 24],
    };
    create_identity_documents(display_name, b"test-only-passphrase", &material)
}
