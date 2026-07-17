// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain-separated BLAKE3 hashing for RAP v1.

#![no_std]
#![forbid(unsafe_code)]

use rebyte_format::{Digest32, KeyId};
use subtle::ConstantTimeEq as _;

/// BLAKE3 derive-key context for reconstructed file bytes.
pub const FILE_CONTEXT: &str = "rebyte:v1:file";
/// BLAKE3 derive-key context for canonical manifest bytes.
pub const MANIFEST_CONTEXT: &str = "rebyte:v1:manifest";
/// BLAKE3 derive-key context for compressed payload bytes.
pub const PAYLOAD_CONTEXT: &str = "rebyte:v1:payload";
/// BLAKE3 derive-key context for the signed capsule root.
pub const CAPSULE_CONTEXT: &str = "rebyte:v1:capsule";
/// BLAKE3 derive-key context for public-key fingerprints.
pub const KEY_ID_CONTEXT: &str = "rebyte:v1:key-id";
/// Prefix of the Ed25519 message signed by RAP v1.
pub const SIGNATURE_DOMAIN: &[u8; 20] = b"rebyte:v1:signature\0";

/// Incremental hasher bound to one RAP v1 semantic domain.
pub struct DomainHasher(blake3::Hasher);

impl DomainHasher {
    /// Creates an incremental file-content hasher.
    #[must_use]
    pub fn file() -> Self {
        Self::new(FILE_CONTEXT)
    }

    /// Creates an incremental manifest hasher.
    #[must_use]
    pub fn manifest() -> Self {
        Self::new(MANIFEST_CONTEXT)
    }

    /// Creates an incremental payload hasher.
    #[must_use]
    pub fn payload() -> Self {
        Self::new(PAYLOAD_CONTEXT)
    }

    /// Creates an incremental capsule-root hasher.
    #[must_use]
    pub fn capsule() -> Self {
        Self::new(CAPSULE_CONTEXT)
    }

    /// Adds bytes without allocating.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Finishes the domain-separated digest.
    #[must_use]
    pub fn finalize(self) -> Digest32 {
        Digest32(*self.0.finalize().as_bytes())
    }

    fn new(context: &str) -> Self {
        Self(blake3::Hasher::new_derive_key(context))
    }
}

/// Hashes reconstructed bytes in the file domain.
#[must_use]
pub fn file_digest(bytes: &[u8]) -> Digest32 {
    hash_one(DomainHasher::file(), bytes)
}

/// Hashes canonical manifest bytes for diagnostics and vectors.
#[must_use]
pub fn manifest_digest(bytes: &[u8]) -> Digest32 {
    hash_one(DomainHasher::manifest(), bytes)
}

/// Hashes compressed payload bytes for diagnostics and vectors.
#[must_use]
pub fn payload_digest(bytes: &[u8]) -> Digest32 {
    hash_one(DomainHasher::payload(), bytes)
}

/// Hashes the canonical signed capsule parts in their exact wire order.
#[must_use]
pub fn capsule_digest(header: &[u8], manifest: &[u8], compressed_payload: &[u8]) -> Digest32 {
    let mut hasher = DomainHasher::capsule();
    hasher.update(header);
    hasher.update(manifest);
    hasher.update(compressed_payload);
    hasher.finalize()
}

/// Derives the stable RAP key ID from a 32-byte Ed25519 public key.
#[must_use]
pub fn key_id(public_key: &[u8; 32]) -> KeyId {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ID_CONTEXT);
    hasher.update(public_key);
    KeyId(*hasher.finalize().as_bytes())
}

/// Builds the fixed Ed25519 message for a capsule digest.
#[must_use]
pub const fn signature_message(digest: &Digest32) -> [u8; 52] {
    let mut message = [0_u8; 52];
    let (domain, digest_output) = message.split_at_mut(SIGNATURE_DOMAIN.len());
    domain.copy_from_slice(SIGNATURE_DOMAIN);
    digest_output.copy_from_slice(digest.as_bytes());
    message
}

/// Compares two digest values without data-dependent early exit.
#[must_use]
pub fn digest_matches(expected: &Digest32, actual: &Digest32) -> bool {
    bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
}

fn hash_one(mut hasher: DomainHasher, bytes: &[u8]) -> Digest32 {
    hasher.update(bytes);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{
        DomainHasher, capsule_digest, digest_matches, file_digest, key_id, manifest_digest,
        payload_digest, signature_message,
    };
    use rebyte_format::Digest32;

    #[test]
    fn incremental_and_one_shot_file_hashes_match() {
        let mut hasher = DomainHasher::file();
        hasher.update(b"hello");
        hasher.update(b" world");
        assert_eq!(hasher.finalize(), file_digest(b"hello world"));
    }

    #[test]
    fn domains_cannot_be_substituted() {
        let bytes = b"same bytes";
        assert_ne!(file_digest(bytes), manifest_digest(bytes));
        assert_ne!(manifest_digest(bytes), payload_digest(bytes));
        assert_ne!(payload_digest(bytes), capsule_digest(&[], &[], bytes));
    }

    #[test]
    fn capsule_part_boundaries_are_fixed_by_canonical_encoding() {
        let first = capsule_digest(b"header", b"manifest", b"payload");
        let second = capsule_digest(b"headermanifest", b"", b"payload");
        assert_eq!(first, second);
    }

    #[test]
    fn signature_message_contains_domain_and_digest() {
        let digest = Digest32([0x5a; 32]);
        let message = signature_message(&digest);
        assert!(message.starts_with(b"rebyte:v1:signature\0"));
        assert!(message.ends_with(digest.as_bytes()));
    }

    #[test]
    fn key_ids_and_digest_comparison_are_stable() {
        assert_eq!(key_id(&[7; 32]), key_id(&[7; 32]));
        assert_ne!(key_id(&[7; 32]), key_id(&[8; 32]));
        assert!(digest_matches(&Digest32([1; 32]), &Digest32([1; 32])));
        assert!(!digest_matches(&Digest32([1; 32]), &Digest32([2; 32])));
    }
}
