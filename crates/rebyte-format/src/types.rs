//! RAP v1 enums and bounded data structures.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::{
    HEADER_SIZE_V1, MAX_CAPSULE_NAME_BYTES, MAX_DESCRIPTION_BYTES, MAX_PRODUCER_NAME_BYTES,
    MAX_PRODUCER_VERSION_BYTES, RelativeArtifactPath, SecurityLimits,
};

/// A supported RAP protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// RAP version 1.
    pub const V1: Self = Self(1);

    /// Returns the numeric wire value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(FormatError::UnsupportedProtocolVersion(value)),
        }
    }
}

/// Compression algorithm selected by a capsule.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CompressionAlgorithm {
    /// Payload bytes are stored verbatim.
    None = 0,
    /// Payload bytes are one bounded Zstandard frame.
    Zstd = 1,
}

impl TryFrom<u8> for CompressionAlgorithm {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Zstd),
            _ => Err(FormatError::UnsupportedCompression(value)),
        }
    }
}

/// Signature algorithm selected by a capsule.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// Ed25519 signature.
    Ed25519 = 1,
}

impl TryFrom<u8> for SignatureAlgorithm {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ed25519),
            _ => Err(FormatError::UnsupportedSignature(value)),
        }
    }
}

/// Closed set of filesystem operations in RAP v1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FileOperation {
    /// Create a missing file or replace an existing regular file.
    CreateOrReplace = 0,
}

impl TryFrom<u8> for FileOperation {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CreateOrReplace),
            _ => Err(FormatError::UnsupportedFileOperation(value)),
        }
    }
}

/// Informational classification of file bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ContentKind {
    /// Arbitrary bytes.
    Binary = 0,
    /// Valid UTF-8 bytes.
    TextUtf8 = 1,
}

impl TryFrom<u8> for ContentKind {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Binary),
            1 => Ok(Self::TextUtf8),
            _ => Err(FormatError::UnsupportedContentKind(value)),
        }
    }
}

/// A fixed 32-byte BLAKE3 digest.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Digest32(pub [u8; 32]);

impl Digest32 {
    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Fingerprint identifying a publisher public key.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    /// Returns the fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A non-empty UTF-8 string bounded by a compile-time byte limit.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedString<const MAX: usize>(String);

impl<const MAX: usize> BoundedString<MAX> {
    /// Validates and owns a string.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::EmptyString`] or
    /// [`FormatError::StringTooLong`] when the value is not canonical.
    pub fn new(value: &str, field: &'static str) -> Result<Self, FormatError> {
        if value.is_empty() {
            return Err(FormatError::EmptyString(field));
        }
        if value.len() > MAX {
            return Err(FormatError::StringTooLong {
                field,
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the UTF-8 value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> AsRef<str> for BoundedString<MAX> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Metadata identifying the software that produced the artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerMetadata {
    /// Producer display name.
    pub name: BoundedString<MAX_PRODUCER_NAME_BYTES>,
    /// Optional producer version.
    pub version: Option<BoundedString<MAX_PRODUCER_VERSION_BYTES>>,
}

/// Fixed RAP v1 envelope header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleHeaderV1 {
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
    /// Fixed header byte length.
    pub header_size: u16,
    /// Extension flags; zero in RAP v1.
    pub flags: u32,
    /// Payload compression.
    pub compression: CompressionAlgorithm,
    /// Signature algorithm.
    pub signature: SignatureAlgorithm,
    /// Canonical manifest length.
    pub manifest_size: u64,
    /// Compressed payload length.
    pub compressed_payload_size: u64,
    /// Reconstructed payload length.
    pub uncompressed_payload_size: u64,
    /// Number of manifest file entries.
    pub file_count: u32,
    /// Publisher public-key fingerprint.
    pub publisher_key_id: KeyId,
}

impl CapsuleHeaderV1 {
    /// Validates fixed fields and configured resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError`] when a fixed RAP v1 field is invalid or a
    /// declared resource exceeds `limits`.
    pub fn validate(&self, limits: &SecurityLimits) -> Result<(), FormatError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(FormatError::UnsupportedProtocolVersion(
                self.protocol_version.get(),
            ));
        }
        if self.header_size != HEADER_SIZE_V1 {
            return Err(FormatError::InvalidHeaderSize(self.header_size));
        }
        if self.flags != 0 {
            return Err(FormatError::UnsupportedFlags(self.flags));
        }
        bounded_u64("manifest", self.manifest_size, limits.max_manifest_bytes)?;
        bounded_u64(
            "compressed payload",
            self.compressed_payload_size,
            limits.max_compressed_payload_bytes,
        )?;
        bounded_u64(
            "uncompressed payload",
            self.uncompressed_payload_size,
            limits.max_uncompressed_payload_bytes,
        )?;
        if self.file_count > limits.max_file_count {
            return Err(FormatError::FileCountTooLarge {
                max: limits.max_file_count,
                actual: self.file_count,
            });
        }
        Ok(())
    }
}

/// Canonical RAP v1 manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleManifestV1 {
    /// Optional human-readable capsule name.
    pub capsule_name: Option<BoundedString<MAX_CAPSULE_NAME_BYTES>>,
    /// Optional human-readable description.
    pub description: Option<BoundedString<MAX_DESCRIPTION_BYTES>>,
    /// Producer metadata.
    pub producer: ProducerMetadata,
    /// Canonically ordered file entries.
    pub files: Vec<FileEntryV1>,
}

/// One file described by a RAP v1 manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEntryV1 {
    /// Portable relative target path.
    pub path: RelativeArtifactPath,
    /// Closed operation kind.
    pub operation: FileOperation,
    /// Informational content classification.
    pub content_kind: ContentKind,
    /// Portable executable permission flag.
    pub executable: bool,
    /// Offset in the reconstructed payload.
    pub offset: u64,
    /// Reconstructed file byte length.
    pub size: u64,
    /// Domain-separated digest of file bytes.
    pub digest: Digest32,
}

/// Validation error for a RAP value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FormatError {
    /// Protocol version is not supported.
    UnsupportedProtocolVersion(u16),
    /// Compression enum value is not supported.
    UnsupportedCompression(u8),
    /// Signature enum value is not supported.
    UnsupportedSignature(u8),
    /// File operation enum value is not supported.
    UnsupportedFileOperation(u8),
    /// Content kind enum value is not supported.
    UnsupportedContentKind(u8),
    /// Header byte length was not the RAP v1 fixed value.
    InvalidHeaderSize(u16),
    /// A non-zero or unknown flag was supplied.
    UnsupportedFlags(u32),
    /// A required string was empty.
    EmptyString(&'static str),
    /// A string exceeded its field limit.
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Maximum byte length.
        max: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// A length exceeded local policy.
    SizeTooLarge {
        /// Resource name.
        field: &'static str,
        /// Maximum byte length.
        max: u64,
        /// Observed byte length.
        actual: u64,
    },
    /// File count exceeded local policy.
    FileCountTooLarge {
        /// Maximum number of files.
        max: u32,
        /// Observed number of files.
        actual: u32,
    },
}

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocolVersion(value) => {
                write!(formatter, "unsupported protocol version {value}")
            }
            Self::UnsupportedCompression(value) => {
                write!(formatter, "unsupported compression algorithm {value}")
            }
            Self::UnsupportedSignature(value) => {
                write!(formatter, "unsupported signature algorithm {value}")
            }
            Self::UnsupportedFileOperation(value) => {
                write!(formatter, "unsupported file operation {value}")
            }
            Self::UnsupportedContentKind(value) => {
                write!(formatter, "unsupported content kind {value}")
            }
            Self::InvalidHeaderSize(value) => write!(formatter, "invalid header size {value}"),
            Self::UnsupportedFlags(value) => write!(formatter, "unsupported flags {value:#x}"),
            Self::EmptyString(field) => write!(formatter, "{field} cannot be empty"),
            Self::StringTooLong { field, max, actual } => {
                write!(formatter, "{field} has {actual} bytes; maximum is {max}")
            }
            Self::SizeTooLarge { field, max, actual } => {
                write!(formatter, "{field} has {actual} bytes; maximum is {max}")
            }
            Self::FileCountTooLarge { max, actual } => {
                write!(formatter, "capsule has {actual} files; maximum is {max}")
            }
        }
    }
}

impl core::error::Error for FormatError {}

const fn bounded_u64(field: &'static str, actual: u64, max: u64) -> Result<(), FormatError> {
    if actual > max {
        Err(FormatError::SizeTooLarge { field, max, actual })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedString, CapsuleHeaderV1, CompressionAlgorithm, FormatError, KeyId, ProtocolVersion,
        SignatureAlgorithm,
    };
    use crate::{HEADER_SIZE_V1, SecurityLimits};

    #[test]
    fn bounded_string_rejects_empty_and_oversized_values() {
        assert_eq!(
            BoundedString::<4>::new("", "name"),
            Err(FormatError::EmptyString("name"))
        );
        assert_eq!(
            BoundedString::<4>::new("12345", "name"),
            Err(FormatError::StringTooLong {
                field: "name",
                max: 4,
                actual: 5,
            })
        );
        assert!(BoundedString::<4>::new("ação", "name").is_err());
        assert!(BoundedString::<6>::new("ação", "name").is_ok());
    }

    #[test]
    fn algorithm_values_are_closed() {
        assert_eq!(
            CompressionAlgorithm::try_from(0),
            Ok(CompressionAlgorithm::None)
        );
        assert_eq!(
            CompressionAlgorithm::try_from(2),
            Err(FormatError::UnsupportedCompression(2))
        );
        assert_eq!(
            SignatureAlgorithm::try_from(0),
            Err(FormatError::UnsupportedSignature(0))
        );
    }

    #[test]
    fn header_enforces_limits_and_flags() {
        let mut header = CapsuleHeaderV1 {
            protocol_version: ProtocolVersion::V1,
            header_size: HEADER_SIZE_V1,
            flags: 0,
            compression: CompressionAlgorithm::None,
            signature: SignatureAlgorithm::Ed25519,
            manifest_size: 10,
            compressed_payload_size: 20,
            uncompressed_payload_size: 20,
            file_count: 1,
            publisher_key_id: KeyId::default(),
        };
        assert_eq!(header.validate(&SecurityLimits::V1), Ok(()));

        header.flags = 1;
        assert_eq!(
            header.validate(&SecurityLimits::V1),
            Err(FormatError::UnsupportedFlags(1))
        );
    }
}
