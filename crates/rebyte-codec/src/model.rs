//! In-memory representation of untrusted decoded envelope bytes.

use alloc::vec::Vec;
use rebyte_format::{CapsuleHeaderV1, CapsuleManifestV1, Digest32};

/// Fixed-size Ed25519 signature bytes carried by an envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureBytes(pub [u8; 64]);

impl SignatureBytes {
    /// Returns the raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// A structurally decoded but cryptographically untrusted capsule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedCapsule {
    /// Canonical header.
    pub header: CapsuleHeaderV1,
    /// Canonical manifest.
    pub manifest: CapsuleManifestV1,
    /// Compressed payload bytes exactly as signed.
    pub compressed_payload: Vec<u8>,
    /// Claimed capsule root digest.
    pub capsule_digest: Digest32,
    /// Claimed Ed25519 signature.
    pub signature: SignatureBytes,
}
