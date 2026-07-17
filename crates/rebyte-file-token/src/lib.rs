// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, bounded and unsigned single-file reconstruction tokens.
//!
//! An `rf1_` token contains the complete file, optionally compressed, plus a
//! domain-separated BLAKE3 digest. It detects accidental or hostile mutation,
//! but it does not authenticate a publisher. Use signed RAP capsules whenever
//! the origin of the bytes matters.

#![forbid(unsafe_code)]

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rebyte_compression::{CompressionError, compress, decompress};
use rebyte_format::{CompressionAlgorithm, Digest32, SecurityLimits};
use rebyte_integrity::{digest_matches, file_digest};

/// Text prefix for a Rebyte File Token v1.
pub const FILE_TOKEN_PREFIX: &str = "rf1_";

/// Fixed byte length of the File Token v1 binary header.
pub const FILE_TOKEN_HEADER_SIZE: usize = 56;

const MAGIC: [u8; 4] = *b"RBFT";
const VERSION: u8 = 1;
const RESERVED: [u8; 2] = [0; 2];

/// Selects how file bytes are stored in a new token.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum FileTokenCompression {
    /// Use Zstandard only when it produces fewer stored bytes.
    #[default]
    Auto,
    /// Always store one deterministic Zstandard frame.
    Zstd,
    /// Store the original bytes without compression.
    None,
}

/// Encoding policy for a new file token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FileTokenOptions {
    /// Compression selection policy.
    pub compression: FileTokenCompression,
    /// Resource limits enforced during both encoding and self-verification.
    pub limits: SecurityLimits,
}

impl FileTokenOptions {
    /// Returns these options with a selected compression policy.
    #[must_use]
    pub const fn with_compression(mut self, compression: FileTokenCompression) -> Self {
        self.compression = compression;
        self
    }

    /// Returns these options with caller-selected resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: SecurityLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Default for FileTokenOptions {
    fn default() -> Self {
        Self {
            compression: FileTokenCompression::Auto,
            limits: SecurityLimits::SIMPLE_ARTIFACT,
        }
    }
}

/// Canonical encoded token and its verified metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct EncodedFileToken {
    token: String,
    digest: Digest32,
    original_size: u64,
    stored_size: u64,
    compression: CompressionAlgorithm,
}

impl EncodedFileToken {
    /// Returns the complete `rf1_` token.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Consumes the report and returns the complete token.
    #[must_use]
    pub fn into_token(self) -> String {
        self.token
    }

    /// Returns the domain-separated digest of the original bytes.
    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Returns the original file length.
    #[must_use]
    pub const fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Returns the compressed or verbatim payload length.
    #[must_use]
    pub const fn stored_size(&self) -> u64 {
        self.stored_size
    }

    /// Returns the algorithm selected for the stored payload.
    #[must_use]
    pub const fn compression(&self) -> CompressionAlgorithm {
        self.compression
    }
}

impl fmt::Debug for EncodedFileToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedFileToken")
            .field("token", &"[redacted]")
            .field("digest", &self.digest)
            .field("original_size", &self.original_size)
            .field("stored_size", &self.stored_size)
            .field("compression", &self.compression)
            .finish()
    }
}

/// Reconstructed bytes and verified token metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct DecodedFileToken {
    bytes: Vec<u8>,
    digest: Digest32,
    original_size: u64,
    stored_size: u64,
    compression: CompressionAlgorithm,
}

impl DecodedFileToken {
    /// Returns the exact reconstructed bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the report and returns the exact reconstructed bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the verified domain-separated file digest.
    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Returns the reconstructed byte length.
    #[must_use]
    pub const fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Returns the compressed or verbatim payload length.
    #[must_use]
    pub const fn stored_size(&self) -> u64 {
        self.stored_size
    }

    /// Returns the algorithm declared by the verified token.
    #[must_use]
    pub const fn compression(&self) -> CompressionAlgorithm {
        self.compression
    }
}

impl fmt::Debug for DecodedFileToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedFileToken")
            .field("bytes", &"[redacted]")
            .field("digest", &self.digest)
            .field("original_size", &self.original_size)
            .field("stored_size", &self.stored_size)
            .field("compression", &self.compression)
            .finish()
    }
}

/// Failure to encode or verify an unsigned file token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FileTokenError {
    /// Original file bytes exceeded the configured single-file limit.
    FileTooLarge {
        /// Maximum permitted byte length.
        max: u64,
        /// Observed or declared byte length.
        actual: u64,
    },
    /// Text token exceeded the configured token limit.
    TokenTooLarge {
        /// Maximum permitted byte length.
        max: u64,
        /// Observed byte length.
        actual: u64,
    },
    /// Token did not begin with `rf1_`.
    InvalidPrefix,
    /// Token contained padding, whitespace or non-Base64URL bytes.
    InvalidAlphabet,
    /// Token payload was not canonical unpadded Base64URL.
    InvalidBase64,
    /// Decoded bytes ended before the complete fixed header.
    UnexpectedEof,
    /// Binary magic was not `RBFT`.
    InvalidMagic,
    /// File Token protocol version is unsupported.
    UnsupportedVersion(u8),
    /// Stored compression algorithm is unsupported.
    UnsupportedCompression(u8),
    /// A reserved header byte was nonzero.
    NonZeroReserved,
    /// Declared payload length differed from the exact remaining bytes.
    PayloadLengthMismatch,
    /// Checked length conversion or arithmetic overflowed.
    LengthOverflow,
    /// Compression or bounded decompression failed.
    Compression(CompressionError),
    /// Reconstructed bytes did not match the embedded file digest.
    DigestMismatch,
}

impl fmt::Display for FileTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooLarge { max, actual } => {
                write!(formatter, "file has {actual} bytes; maximum is {max}")
            }
            Self::TokenTooLarge { max, actual } => {
                write!(formatter, "file token has {actual} bytes; maximum is {max}")
            }
            Self::InvalidPrefix => formatter.write_str("invalid file-token prefix"),
            Self::InvalidAlphabet => formatter.write_str("invalid file-token alphabet"),
            Self::InvalidBase64 => formatter.write_str("invalid file-token Base64URL payload"),
            Self::UnexpectedEof => formatter.write_str("file token is truncated"),
            Self::InvalidMagic => formatter.write_str("invalid file-token magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported file-token version {version}")
            }
            Self::UnsupportedCompression(algorithm) => {
                write!(formatter, "unsupported file-token compression {algorithm}")
            }
            Self::NonZeroReserved => formatter.write_str("file-token reserved field is nonzero"),
            Self::PayloadLengthMismatch => {
                formatter.write_str("file-token payload length mismatch")
            }
            Self::LengthOverflow => formatter.write_str("file-token length overflow"),
            Self::Compression(error) => write!(formatter, "file-token compression failed: {error}"),
            Self::DigestMismatch => formatter.write_str("file-token digest mismatch"),
        }
    }
}

impl std::error::Error for FileTokenError {}

impl From<CompressionError> for FileTokenError {
    fn from(value: CompressionError) -> Self {
        Self::Compression(value)
    }
}

/// Encodes exact file bytes into one canonical, unpadded `rf1_` token.
///
/// `Auto` tries deterministic Zstandard and keeps it only when it is smaller
/// than the original. The result is decoded and digest-verified before it is
/// returned.
///
/// # Errors
///
/// Returns [`FileTokenError`] when bytes exceed `options.limits`, compression
/// fails, checked arithmetic overflows, or self-verification fails.
pub fn encode_file_token(
    bytes: &[u8],
    options: &FileTokenOptions,
) -> Result<EncodedFileToken, FileTokenError> {
    let original_size = usize_to_u64(bytes.len())?;
    enforce_file_size(original_size, &options.limits)?;
    let (compression, payload) = select_payload(bytes, options)?;
    let stored_size = usize_to_u64(payload.len())?;
    let digest = file_digest(bytes);
    let binary_size = FILE_TOKEN_HEADER_SIZE
        .checked_add(payload.len())
        .ok_or(FileTokenError::LengthOverflow)?;
    let binary_size_u64 = usize_to_u64(binary_size)?;
    if binary_size_u64 > options.limits.max_capsule_bytes {
        return Err(FileTokenError::TokenTooLarge {
            max: options.limits.max_capsule_bytes,
            actual: binary_size_u64,
        });
    }

    let mut binary = Vec::with_capacity(binary_size);
    binary.extend_from_slice(&MAGIC);
    binary.push(VERSION);
    binary.push(compression as u8);
    binary.extend_from_slice(&RESERVED);
    binary.extend_from_slice(&original_size.to_be_bytes());
    binary.extend_from_slice(&stored_size.to_be_bytes());
    binary.extend_from_slice(digest.as_bytes());
    binary.extend_from_slice(&payload);

    let token = format!("{FILE_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(binary));
    let token_size = usize_to_u64(token.len())?;
    if token_size > options.limits.max_token_bytes {
        return Err(FileTokenError::TokenTooLarge {
            max: options.limits.max_token_bytes,
            actual: token_size,
        });
    }
    let verified = decode_file_token(&token, &options.limits)?;
    if verified.bytes() != bytes {
        return Err(FileTokenError::DigestMismatch);
    }
    Ok(EncodedFileToken {
        token,
        digest,
        original_size,
        stored_size,
        compression,
    })
}

/// Decodes, bounds, decompresses and digest-verifies an `rf1_` token.
///
/// # Errors
///
/// Returns [`FileTokenError`] for non-canonical Base64URL, malformed or
/// unsupported headers, inconsistent lengths, decompression-limit failures or
/// a digest mismatch. No reconstructed bytes are returned before every check
/// succeeds.
pub fn decode_file_token(
    token: &str,
    limits: &SecurityLimits,
) -> Result<DecodedFileToken, FileTokenError> {
    let token_size = usize_to_u64(token.len())?;
    if token_size > limits.max_token_bytes {
        return Err(FileTokenError::TokenTooLarge {
            max: limits.max_token_bytes,
            actual: token_size,
        });
    }
    let payload_text = token
        .strip_prefix(FILE_TOKEN_PREFIX)
        .ok_or(FileTokenError::InvalidPrefix)?;
    if payload_text.is_empty()
        || payload_text
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(FileTokenError::InvalidAlphabet);
    }
    let binary = URL_SAFE_NO_PAD
        .decode(payload_text)
        .map_err(|_| FileTokenError::InvalidBase64)?;
    if URL_SAFE_NO_PAD.encode(&binary) != payload_text {
        return Err(FileTokenError::InvalidBase64);
    }
    let binary_size = usize_to_u64(binary.len())?;
    if binary_size > limits.max_capsule_bytes {
        return Err(FileTokenError::TokenTooLarge {
            max: limits.max_capsule_bytes,
            actual: binary_size,
        });
    }
    if binary.len() < FILE_TOKEN_HEADER_SIZE {
        return Err(FileTokenError::UnexpectedEof);
    }
    if binary.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(FileTokenError::InvalidMagic);
    }
    let version = *binary.get(4).ok_or(FileTokenError::UnexpectedEof)?;
    if version != VERSION {
        return Err(FileTokenError::UnsupportedVersion(version));
    }
    let algorithm = *binary.get(5).ok_or(FileTokenError::UnexpectedEof)?;
    let compression = match algorithm {
        0 => CompressionAlgorithm::None,
        1 => CompressionAlgorithm::Zstd,
        _ => return Err(FileTokenError::UnsupportedCompression(algorithm)),
    };
    if binary.get(6..8) != Some(RESERVED.as_slice()) {
        return Err(FileTokenError::NonZeroReserved);
    }
    let original_size = read_u64(&binary, 8)?;
    enforce_file_size(original_size, limits)?;
    let stored_size = read_u64(&binary, 16)?;
    let stored_size_usize =
        usize::try_from(stored_size).map_err(|_| FileTokenError::LengthOverflow)?;
    let expected_size = FILE_TOKEN_HEADER_SIZE
        .checked_add(stored_size_usize)
        .ok_or(FileTokenError::LengthOverflow)?;
    if binary.len() != expected_size {
        return Err(FileTokenError::PayloadLengthMismatch);
    }
    let digest_bytes = binary
        .get(24..FILE_TOKEN_HEADER_SIZE)
        .ok_or(FileTokenError::UnexpectedEof)?;
    let mut digest_array = [0_u8; 32];
    digest_array.copy_from_slice(digest_bytes);
    let expected_digest = Digest32(digest_array);
    let stored = binary
        .get(FILE_TOKEN_HEADER_SIZE..)
        .ok_or(FileTokenError::UnexpectedEof)?;
    let bytes = decompress(stored, compression, original_size, limits)?;
    let actual_digest = file_digest(&bytes);
    if !digest_matches(&expected_digest, &actual_digest) {
        return Err(FileTokenError::DigestMismatch);
    }
    Ok(DecodedFileToken {
        bytes,
        digest: actual_digest,
        original_size,
        stored_size,
        compression,
    })
}

fn select_payload(
    bytes: &[u8],
    options: &FileTokenOptions,
) -> Result<(CompressionAlgorithm, Vec<u8>), FileTokenError> {
    match options.compression {
        FileTokenCompression::None => Ok((
            CompressionAlgorithm::None,
            compress(bytes, CompressionAlgorithm::None, &options.limits)?,
        )),
        FileTokenCompression::Zstd => Ok((
            CompressionAlgorithm::Zstd,
            compress(bytes, CompressionAlgorithm::Zstd, &options.limits)?,
        )),
        FileTokenCompression::Auto => {
            match compress(bytes, CompressionAlgorithm::Zstd, &options.limits) {
                Ok(compressed) if compressed.len() < bytes.len() => {
                    Ok((CompressionAlgorithm::Zstd, compressed))
                }
                Ok(_) | Err(CompressionError::UnsupportedEncoder) => Ok((
                    CompressionAlgorithm::None,
                    compress(bytes, CompressionAlgorithm::None, &options.limits)?,
                )),
                Err(error) => Err(error.into()),
            }
        }
    }
}

const fn enforce_file_size(actual: u64, limits: &SecurityLimits) -> Result<(), FileTokenError> {
    if actual > limits.max_single_file_bytes {
        Err(FileTokenError::FileTooLarge {
            max: limits.max_single_file_bytes,
            actual,
        })
    } else {
        Ok(())
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FileTokenError> {
    let end = offset
        .checked_add(8)
        .ok_or(FileTokenError::LengthOverflow)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(FileTokenError::UnexpectedEof)?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(slice);
    Ok(u64::from_be_bytes(value))
}

fn usize_to_u64(value: usize) -> Result<u64, FileTokenError> {
    u64::try_from(value).map_err(|_| FileTokenError::LengthOverflow)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use proptest::prelude::*;
    use rebyte_format::{CompressionAlgorithm, SecurityLimits};

    use super::{
        FILE_TOKEN_HEADER_SIZE, FILE_TOKEN_PREFIX, FileTokenCompression, FileTokenError,
        FileTokenOptions, decode_file_token, encode_file_token,
    };

    #[test]
    fn empty_and_binary_files_round_trip() -> Result<(), FileTokenError> {
        for bytes in [Vec::new(), vec![0, 1, 0xff, 0, 10]] {
            let encoded = encode_file_token(&bytes, &FileTokenOptions::default())?;
            let decoded = decode_file_token(encoded.token(), &SecurityLimits::V1)?;
            assert_eq!(decoded.bytes(), bytes);
        }
        Ok(())
    }

    #[test]
    fn large_text_becomes_a_much_shorter_token() -> Result<(), FileTokenError> {
        let mut text = String::new();
        for index in 0..20_000 {
            use std::fmt::Write as _;

            writeln!(
                text,
                "Registro {index:05}: Rebyte reconstrói cada byte com limites, digest e validação."
            )
            .map_err(|_| FileTokenError::LengthOverflow)?;
        }
        let encoded = encode_file_token(text.as_bytes(), &FileTokenOptions::default())?;
        assert_eq!(encoded.compression(), CompressionAlgorithm::Zstd);
        assert!(encoded.token().len() < text.len() / 4);
        let decoded = decode_file_token(encoded.token(), &SecurityLimits::V1)?;
        assert_eq!(decoded.bytes(), text.as_bytes());
        Ok(())
    }

    #[test]
    fn extremely_repetitive_text_does_not_fall_back_to_verbatim() -> Result<(), FileTokenError> {
        let bytes = vec![b'R'; 8 * 1_024 * 1_024];
        let encoded = encode_file_token(&bytes, &FileTokenOptions::default())?;
        assert_eq!(encoded.compression(), CompressionAlgorithm::Zstd);
        assert!(encoded.stored_size() < encoded.original_size() / 200);
        assert_eq!(
            decode_file_token(encoded.token(), &SecurityLimits::SIMPLE_ARTIFACT)?.bytes(),
            bytes
        );
        Ok(())
    }

    #[test]
    fn auto_is_deterministic_and_avoids_expansion() -> Result<(), FileTokenError> {
        let first = encode_file_token(b"small", &FileTokenOptions::default())?;
        let second = encode_file_token(b"small", &FileTokenOptions::default())?;
        assert_eq!(first, second);
        assert_eq!(first.compression(), CompressionAlgorithm::None);
        assert_eq!(first.stored_size(), first.original_size());
        Ok(())
    }

    #[test]
    fn uncompressed_vector_is_immutable() -> Result<(), FileTokenError> {
        let options = FileTokenOptions {
            compression: FileTokenCompression::None,
            ..FileTokenOptions::default()
        };
        let encoded = encode_file_token(b"Rebyte", &options)?;
        assert_eq!(
            encoded.token(),
            "rf1_UkJGVAEAAAAAAAAAAAAABgAAAAAAAAAGELq0ltLAXFF-dIZTKN_Sfl_nGEqHDZAKUuFpxKbGy2BSZWJ5dGU"
        );
        Ok(())
    }

    #[test]
    fn explicit_algorithms_round_trip() -> Result<(), FileTokenError> {
        let bytes = b"some text some text some text some text";
        for compression in [FileTokenCompression::None, FileTokenCompression::Zstd] {
            let options = FileTokenOptions {
                compression,
                ..FileTokenOptions::default()
            };
            let encoded = encode_file_token(bytes, &options)?;
            assert_eq!(
                decode_file_token(encoded.token(), &SecurityLimits::V1)?.bytes(),
                bytes
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_text_and_unknown_header_values() -> Result<(), FileTokenError> {
        assert_eq!(
            decode_file_token("rb1_YQ", &SecurityLimits::V1),
            Err(FileTokenError::InvalidPrefix)
        );
        assert_eq!(
            decode_file_token("rf1_YQ==", &SecurityLimits::V1),
            Err(FileTokenError::InvalidAlphabet)
        );
        assert_eq!(
            decode_file_token("rf1_Y Q", &SecurityLimits::V1),
            Err(FileTokenError::InvalidAlphabet)
        );

        let encoded = encode_file_token(b"header checks", &FileTokenOptions::default())?;
        let binary = decode_binary(encoded.token())?;
        assert_header_mutation(&binary, 0, b'X', FileTokenError::InvalidMagic);
        assert_header_mutation(&binary, 4, 2, FileTokenError::UnsupportedVersion(2));
        assert_header_mutation(&binary, 5, 9, FileTokenError::UnsupportedCompression(9));
        assert_header_mutation(&binary, 6, 1, FileTokenError::NonZeroReserved);
        Ok(())
    }

    #[test]
    fn rejects_payload_mutation_and_trailing_bytes() -> Result<(), FileTokenError> {
        let options = FileTokenOptions {
            compression: FileTokenCompression::None,
            ..FileTokenOptions::default()
        };
        let encoded = encode_file_token(b"mutation target", &options)?;
        let mut binary = decode_binary(encoded.token())?;
        let payload = binary
            .get_mut(FILE_TOKEN_HEADER_SIZE)
            .ok_or(FileTokenError::UnexpectedEof)?;
        *payload ^= 1;
        assert_eq!(
            decode_file_token(&encode_binary(&binary), &SecurityLimits::V1),
            Err(FileTokenError::DigestMismatch)
        );
        binary.push(0);
        assert_eq!(
            decode_file_token(&encode_binary(&binary), &SecurityLimits::V1),
            Err(FileTokenError::PayloadLengthMismatch)
        );
        Ok(())
    }

    #[test]
    fn enforces_file_and_token_limits() -> Result<(), FileTokenError> {
        let mut limits = SecurityLimits::V1;
        limits.max_single_file_bytes = 3;
        let options = FileTokenOptions {
            limits,
            ..FileTokenOptions::default()
        };
        assert_eq!(
            encode_file_token(b"four", &options),
            Err(FileTokenError::FileTooLarge { max: 3, actual: 4 })
        );

        let encoded = encode_file_token(b"ok", &FileTokenOptions::default())?;
        limits = SecurityLimits::V1;
        limits.max_token_bytes = 4;
        assert!(matches!(
            decode_file_token(encoded.token(), &limits),
            Err(FileTokenError::TokenTooLarge { .. })
        ));
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..16_384)) {
            let encoded = encode_file_token(&bytes, &FileTokenOptions::default())?;
            let decoded = decode_file_token(encoded.token(), &SecurityLimits::V1)?;
            prop_assert_eq!(decoded.bytes(), bytes);
        }
    }

    fn decode_binary(token: &str) -> Result<Vec<u8>, FileTokenError> {
        let payload = token
            .strip_prefix(FILE_TOKEN_PREFIX)
            .ok_or(FileTokenError::InvalidPrefix)?;
        URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| FileTokenError::InvalidBase64)
    }

    fn encode_binary(binary: &[u8]) -> String {
        format!("{FILE_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(binary))
    }

    fn assert_header_mutation(binary: &[u8], offset: usize, value: u8, expected: FileTokenError) {
        let mut mutated = binary.to_vec();
        if let Some(byte) = mutated.get_mut(offset) {
            *byte = value;
        }
        assert_eq!(
            decode_file_token(&encode_binary(&mutated), &SecurityLimits::V1),
            Err(expected)
        );
    }
}
