//! Typestate verification and signing composition for RAP v1.

#![forbid(unsafe_code)]

use std::fmt;

use rebyte_codec::{
    CodecError, DecodedCapsule, SignatureBytes, decode_capsule, decode_token, encode_capsule,
    encode_header, encode_manifest, encode_token,
};
use rebyte_compression::{CompressionError, decompress};
use rebyte_format::{
    CapsuleHeaderV1, CapsuleManifestV1, ContentKind, Digest32, HEADER_SIZE_V1, ProtocolVersion,
    RelativeArtifactPath, SecurityLimits, SignatureAlgorithm,
};
use rebyte_integrity::{capsule_digest, digest_matches, file_digest, key_id, signature_message};
use rebyte_pack::UnsignedCapsule;
use rebyte_signature::{
    SignatureError, Signer, TrustedKeyring, VerificationPolicy, VerifiedPublisher, verify_signature,
};

/// Borrowed capsule representation accepted by the verifier.
#[derive(Clone, Copy, Debug)]
pub enum CapsuleInput<'a> {
    /// Complete binary `.rbc` envelope.
    Binary(&'a [u8]),
    /// Complete unpadded `rb1_` token.
    Token(&'a str),
}

/// Raw bytes which have not passed structural validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedCapsule {
    bytes: Vec<u8>,
}

impl UnverifiedCapsule {
    /// Adapts binary or textual input while enforcing its outer limit.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::Codec`] for an invalid or oversized token,
    /// or [`VerificationError::InputTooLarge`] for oversized binary input.
    pub fn from_input(
        input: CapsuleInput<'_>,
        limits: &SecurityLimits,
    ) -> Result<Self, VerificationError> {
        let bytes = match input {
            CapsuleInput::Binary(bytes) => {
                let actual =
                    u64::try_from(bytes.len()).map_err(|_| VerificationError::LengthOverflow)?;
                if actual > limits.max_capsule_bytes {
                    return Err(VerificationError::InputTooLarge {
                        max: limits.max_capsule_bytes,
                        actual,
                    });
                }
                bytes.to_vec()
            }
            CapsuleInput::Token(token) => decode_token(token, limits)?,
        };
        Ok(Self { bytes })
    }

    /// Performs bounded parsing and canonical structural validation.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::Codec`] when the envelope is malformed or
    /// not canonical.
    pub fn decode(
        self,
        limits: &SecurityLimits,
    ) -> Result<StructurallyValidCapsule, VerificationError> {
        let decoded = decode_capsule(&self.bytes, limits)?;
        let header_bytes = encode_header(&decoded.header)?;
        let manifest_bytes = encode_manifest(&decoded.manifest)?;
        Ok(StructurallyValidCapsule {
            decoded,
            header_bytes,
            manifest_bytes,
        })
    }
}

/// Canonically parsed capsule that is still cryptographically untrusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructurallyValidCapsule {
    decoded: DecodedCapsule,
    header_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
}

impl StructurallyValidCapsule {
    /// Returns the untrusted but structurally bounded header for inspection.
    #[must_use]
    pub const fn header(&self) -> &CapsuleHeaderV1 {
        &self.decoded.header
    }

    /// Returns the untrusted but structurally bounded manifest for inspection.
    #[must_use]
    pub const fn manifest(&self) -> &CapsuleManifestV1 {
        &self.decoded.manifest
    }

    /// Returns the untrusted claimed capsule digest for inspection.
    #[must_use]
    pub const fn claimed_capsule_digest(&self) -> Digest32 {
        self.decoded.capsule_digest
    }

    /// Verifies capsule digest, key policy and Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::CapsuleDigestMismatch`] or a typed
    /// signature/trust error.
    pub fn verify_signature(
        self,
        policy: &VerificationPolicy,
        keyring: &TrustedKeyring,
    ) -> Result<SignatureVerifiedCapsule, VerificationError> {
        let actual_digest = capsule_digest(
            &self.header_bytes,
            &self.manifest_bytes,
            &self.decoded.compressed_payload,
        );
        if !digest_matches(&self.decoded.capsule_digest, &actual_digest) {
            return Err(VerificationError::CapsuleDigestMismatch);
        }
        let publisher = verify_signature(
            &self.decoded.header.publisher_key_id,
            &actual_digest,
            self.decoded.signature.as_bytes(),
            policy,
            keyring,
        )?;
        Ok(SignatureVerifiedCapsule {
            decoded: self.decoded,
            publisher,
        })
    }
}

/// Capsule whose publisher and signed compressed bytes are authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureVerifiedCapsule {
    decoded: DecodedCapsule,
    publisher: VerifiedPublisher,
}

impl SignatureVerifiedCapsule {
    /// Decompresses within limits and verifies every file digest.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError`] for bounded decompression, invalid text,
    /// range mismatch or any file digest mismatch.
    pub fn verify_payload(
        self,
        limits: &SecurityLimits,
    ) -> Result<PayloadVerifiedCapsule, VerificationError> {
        let payload = decompress(
            &self.decoded.compressed_payload,
            self.decoded.header.compression,
            self.decoded.header.uncompressed_payload_size,
            limits,
        )?;
        let mut files = Vec::with_capacity(self.decoded.manifest.files.len());
        for entry in &self.decoded.manifest.files {
            let start =
                usize::try_from(entry.offset).map_err(|_| VerificationError::LengthOverflow)?;
            let size =
                usize::try_from(entry.size).map_err(|_| VerificationError::LengthOverflow)?;
            let end = start
                .checked_add(size)
                .ok_or(VerificationError::LengthOverflow)?;
            let bytes = payload
                .get(start..end)
                .ok_or(VerificationError::PayloadRangeMismatch)?;
            if entry.content_kind == ContentKind::TextUtf8 && core::str::from_utf8(bytes).is_err() {
                return Err(VerificationError::InvalidTextContent);
            }
            if !digest_matches(&entry.digest, &file_digest(bytes)) {
                return Err(VerificationError::FileDigestMismatch);
            }
            files.push(VerifiedFile {
                path: entry.path.clone(),
                bytes: bytes.to_vec(),
                executable: entry.executable,
                content_kind: entry.content_kind,
            });
        }
        Ok(PayloadVerifiedCapsule {
            header: self.decoded.header,
            manifest: self.decoded.manifest,
            publisher: self.publisher,
            capsule_digest: self.decoded.capsule_digest,
            files,
        })
    }
}

/// Capsule whose signature and reconstructed payload are both verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadVerifiedCapsule {
    header: CapsuleHeaderV1,
    manifest: CapsuleManifestV1,
    publisher: VerifiedPublisher,
    capsule_digest: Digest32,
    files: Vec<VerifiedFile>,
}

impl PayloadVerifiedCapsule {
    /// Completes the typestate transition accepted by filesystem consumers.
    #[must_use]
    pub fn finish(self) -> FullyVerifiedCapsule {
        FullyVerifiedCapsule {
            header: self.header,
            manifest: self.manifest,
            publisher: self.publisher,
            capsule_digest: self.capsule_digest,
            files: self.files,
        }
    }
}

/// Fully authenticated and byte-verified file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFile {
    /// Portable target path.
    pub path: RelativeArtifactPath,
    /// Exact reconstructed bytes.
    pub bytes: Vec<u8>,
    /// Portable executable flag.
    pub executable: bool,
    /// Informational content classification.
    pub content_kind: ContentKind,
}

/// Only capsule state accepted by diff and apply APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullyVerifiedCapsule {
    header: CapsuleHeaderV1,
    manifest: CapsuleManifestV1,
    publisher: VerifiedPublisher,
    capsule_digest: Digest32,
    files: Vec<VerifiedFile>,
}

impl FullyVerifiedCapsule {
    /// Returns the authenticated header.
    #[must_use]
    pub const fn header(&self) -> &CapsuleHeaderV1 {
        &self.header
    }

    /// Returns the authenticated manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CapsuleManifestV1 {
        &self.manifest
    }

    /// Returns the trusted publisher decision.
    #[must_use]
    pub const fn publisher(&self) -> &VerifiedPublisher {
        &self.publisher
    }

    /// Returns the authenticated capsule root digest.
    #[must_use]
    pub const fn capsule_digest(&self) -> Digest32 {
        self.capsule_digest
    }

    /// Returns all authenticated files in canonical path order.
    #[must_use]
    pub fn files(&self) -> &[VerifiedFile] {
        &self.files
    }
}

/// Verifies a capsule with RAP v1 resource limits.
///
/// # Errors
///
/// Returns [`VerificationError`] at the first failed structural, trust,
/// signature, decompression or file-integrity stage.
pub fn verify_capsule(
    input: CapsuleInput<'_>,
    policy: &VerificationPolicy,
    keyring: &TrustedKeyring,
) -> Result<FullyVerifiedCapsule, VerificationError> {
    verify_capsule_with_limits(input, &SecurityLimits::V1, policy, keyring)
}

/// Verifies a capsule with caller-supplied defensive limits.
///
/// # Errors
///
/// Returns [`VerificationError`] at the first failed structural, trust,
/// signature, decompression or file-integrity stage.
pub fn verify_capsule_with_limits(
    input: CapsuleInput<'_>,
    limits: &SecurityLimits,
    policy: &VerificationPolicy,
    keyring: &TrustedKeyring,
) -> Result<FullyVerifiedCapsule, VerificationError> {
    UnverifiedCapsule::from_input(input, limits)?
        .decode(limits)?
        .verify_signature(policy, keyring)?
        .verify_payload(limits)
        .map(PayloadVerifiedCapsule::finish)
}

/// Complete signed envelope ready for binary or token transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCapsule {
    bytes: Vec<u8>,
}

impl SignedCapsule {
    /// Returns the final `.rbc` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the value and returns the final `.rbc` bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Encodes the final bytes as an unpadded `rb1_` token.
    #[must_use]
    pub fn to_token(&self) -> String {
        encode_token(&self.bytes)
    }
}

/// Adds publisher identity, root digest and signature to packed material.
///
/// # Errors
///
/// Returns [`SignCapsuleError`] when lengths cannot be represented, canonical
/// encoding fails or the restricted signer adapter fails.
pub fn sign_capsule<S: Signer>(
    unsigned: &UnsignedCapsule,
    signer: &S,
) -> Result<SignedCapsule, SignCapsuleError<S::Error>> {
    let manifest_bytes = encode_manifest(&unsigned.manifest).map_err(SignCapsuleError::Codec)?;
    let manifest_size =
        u64::try_from(manifest_bytes.len()).map_err(|_| SignCapsuleError::LengthOverflow)?;
    let payload_size = u64::try_from(unsigned.compressed_payload.len())
        .map_err(|_| SignCapsuleError::LengthOverflow)?;
    let file_count = u32::try_from(unsigned.manifest.files.len())
        .map_err(|_| SignCapsuleError::LengthOverflow)?;
    let header = CapsuleHeaderV1 {
        protocol_version: ProtocolVersion::V1,
        header_size: HEADER_SIZE_V1,
        flags: 0,
        compression: unsigned.compression,
        signature: SignatureAlgorithm::Ed25519,
        manifest_size,
        compressed_payload_size: payload_size,
        uncompressed_payload_size: unsigned.uncompressed_payload_size,
        file_count,
        publisher_key_id: key_id(&signer.public_key()),
    };
    let header_bytes = encode_header(&header).map_err(SignCapsuleError::Codec)?;
    let digest = capsule_digest(&header_bytes, &manifest_bytes, &unsigned.compressed_payload);
    let signature = signer
        .sign(&signature_message(&digest))
        .map_err(SignCapsuleError::Signer)?;
    let decoded = DecodedCapsule {
        header,
        manifest: unsigned.manifest.clone(),
        compressed_payload: unsigned.compressed_payload.clone(),
        capsule_digest: digest,
        signature: SignatureBytes(signature),
    };
    let bytes = encode_capsule(&decoded).map_err(SignCapsuleError::Codec)?;
    Ok(SignedCapsule { bytes })
}

/// Verification pipeline failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerificationError {
    /// Binary input exceeded local policy.
    InputTooLarge {
        /// Maximum bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Structural or token codec failure.
    Codec(CodecError),
    /// Claimed root digest did not authenticate signed bytes.
    CapsuleDigestMismatch,
    /// Publisher trust or Ed25519 verification failure.
    Signature(SignatureError),
    /// Bounded payload decompression failure.
    Compression(CompressionError),
    /// A manifest file range was outside the reconstructed payload.
    PayloadRangeMismatch,
    /// A file marked as text was not valid UTF-8.
    InvalidTextContent,
    /// A reconstructed file did not match its signed digest.
    FileDigestMismatch,
    /// Platform length conversion or arithmetic overflowed.
    LengthOverflow,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { max, actual } => {
                write!(formatter, "capsule has {actual} bytes; maximum is {max}")
            }
            Self::Codec(error) => write!(formatter, "capsule structure is invalid: {error}"),
            Self::CapsuleDigestMismatch => formatter.write_str("capsule digest mismatch"),
            Self::Signature(error) => write!(formatter, "capsule is not trusted: {error}"),
            Self::Compression(error) => write!(formatter, "payload is invalid: {error}"),
            Self::PayloadRangeMismatch => formatter.write_str("payload file range mismatch"),
            Self::InvalidTextContent => formatter.write_str("text file is not valid UTF-8"),
            Self::FileDigestMismatch => formatter.write_str("file digest mismatch"),
            Self::LengthOverflow => formatter.write_str("verification length overflow"),
        }
    }
}

impl std::error::Error for VerificationError {}

impl From<CodecError> for VerificationError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<SignatureError> for VerificationError {
    fn from(value: SignatureError) -> Self {
        Self::Signature(value)
    }
}

impl From<CompressionError> for VerificationError {
    fn from(value: CompressionError) -> Self {
        Self::Compression(value)
    }
}

/// Failure while converting packed material into a signed envelope.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignCapsuleError<E> {
    /// Canonical envelope encoding failed.
    Codec(CodecError),
    /// Signer adapter failed without exposing secret data.
    Signer(E),
    /// Platform length conversion overflowed.
    LengthOverflow,
}

impl<E: fmt::Display> fmt::Display for SignCapsuleError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "cannot encode signed capsule: {error}"),
            Self::Signer(error) => write!(formatter, "signer failed: {error}"),
            Self::LengthOverflow => formatter.write_str("signed capsule length overflow"),
        }
    }
}

impl<E> std::error::Error for SignCapsuleError<E> where E: std::error::Error + Send + Sync + 'static {}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;
    use std::fmt;

    use ed25519_dalek::SigningKey;
    use rebyte_format::CompressionAlgorithm;
    use rebyte_pack::{ArtifactFile, PackError, PackOptions, pack};
    use rebyte_signature::{
        KeyStatus, Signer, TrustChannel, TrustedKeyring, TrustedPublicKey, VerificationPolicy,
    };

    use super::{CapsuleInput, SignCapsuleError, VerificationError, sign_capsule, verify_capsule};

    const TEST_SECRET: [u8; 32] = [0x24; 32];

    struct TestSigner(SigningKey);

    impl Signer for TestSigner {
        type Error = Infallible;

        fn public_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }

        fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            Ok(ed25519_dalek::Signer::sign(&self.0, message).to_bytes())
        }
    }

    fn fixture() -> Result<(Vec<u8>, TrustedKeyring), FixtureError> {
        let signer = TestSigner(SigningKey::from_bytes(&TEST_SECRET));
        let trusted = TrustedPublicKey::new(
            "test-only",
            signer.public_key(),
            TrustChannel::Development,
            KeyStatus::Active,
        )?;
        let keyring = TrustedKeyring::new(vec![trusted])?;
        let mut options = PackOptions::new("tests")?;
        options.compression = CompressionAlgorithm::None;
        let unsigned = pack(
            &[
                ArtifactFile::new("src/a.txt", b"alpha\n".to_vec())?,
                ArtifactFile::new("src/b.bin", vec![0, 1, 2])?,
            ],
            &options,
        )?;
        let envelope = sign_capsule(&unsigned, &signer)?;
        Ok((envelope.into_bytes(), keyring))
    }

    fn development_policy() -> VerificationPolicy {
        VerificationPolicy {
            allow_staging: false,
            allow_development: true,
        }
    }

    #[test]
    fn pack_sign_verify_reconstructs_exact_files() -> Result<(), FixtureError> {
        let (bytes, keyring) = fixture()?;
        let verified = verify_capsule(
            CapsuleInput::Binary(&bytes),
            &development_policy(),
            &keyring,
        )?;
        assert_eq!(verified.files().len(), 2);
        assert_eq!(verified.files()[0].bytes, b"alpha\n");
        assert_eq!(verified.files()[1].bytes, [0, 1, 2]);
        Ok(())
    }

    #[test]
    fn token_input_has_same_result() -> Result<(), FixtureError> {
        let (bytes, keyring) = fixture()?;
        let token = rebyte_codec::encode_token(&bytes);
        let binary = verify_capsule(
            CapsuleInput::Binary(&bytes),
            &development_policy(),
            &keyring,
        )?;
        let textual = verify_capsule(CapsuleInput::Token(&token), &development_policy(), &keyring)?;
        assert_eq!(binary, textual);
        Ok(())
    }

    #[test]
    fn modified_signature_is_rejected() -> Result<(), FixtureError> {
        let (mut bytes, keyring) = fixture()?;
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        assert!(matches!(
            verify_capsule(
                CapsuleInput::Binary(&bytes),
                &development_policy(),
                &keyring,
            ),
            Err(VerificationError::Signature(_))
        ));
        Ok(())
    }

    #[derive(Debug)]
    enum FixtureError {
        Pack(PackError),
        Signature(rebyte_signature::SignatureError),
        Sign(SignCapsuleError<Infallible>),
        Verify(VerificationError),
    }

    impl fmt::Display for FixtureError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Pack(error) => error.fmt(formatter),
                Self::Signature(error) => error.fmt(formatter),
                Self::Sign(error) => error.fmt(formatter),
                Self::Verify(error) => error.fmt(formatter),
            }
        }
    }

    impl std::error::Error for FixtureError {}

    impl From<PackError> for FixtureError {
        fn from(value: PackError) -> Self {
            Self::Pack(value)
        }
    }

    impl From<rebyte_signature::SignatureError> for FixtureError {
        fn from(value: rebyte_signature::SignatureError) -> Self {
            Self::Signature(value)
        }
    }

    impl From<SignCapsuleError<Infallible>> for FixtureError {
        fn from(value: SignCapsuleError<Infallible>) -> Self {
            Self::Sign(value)
        }
    }

    impl From<VerificationError> for FixtureError {
        fn from(value: VerificationError) -> Self {
            Self::Verify(value)
        }
    }
}
