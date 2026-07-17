//! Typed failures for unsigned artifact encoding and verification.

use core::fmt;

use rebyte_compression::CompressionError;
use rebyte_format::PathError;

/// Failure to encode, parse or verify an unsigned artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArtifactTokenError {
    /// A portable artifact path or suggested destination was invalid.
    Path(PathError),
    /// The optional suggested basename was invalid.
    InvalidName(PathError),
    /// A file artifact did not contain exactly one pathless file.
    InvalidFileShape,
    /// A directory artifact contained an entry without a path.
    InvalidDirectoryShape,
    /// Two directory entries used the same path.
    DuplicatePath,
    /// A regular file was used as an ancestor of another entry.
    PathTypeConflict,
    /// Canonical entries were not ordered by UTF-8 path bytes.
    NonCanonicalOrder,
    /// A directory entry declared file-only fields.
    InvalidDirectoryEntry,
    /// An executable bit was declared for a directory.
    ExecutableDirectory,
    /// The entry count exceeded local policy.
    TooManyEntries {
        /// Maximum permitted entries.
        max: u32,
        /// Observed or declared entries.
        actual: u32,
    },
    /// One reconstructed file exceeded local policy.
    FileTooLarge {
        /// Maximum permitted bytes.
        max: u64,
        /// Observed or declared bytes.
        actual: u64,
    },
    /// The aggregate reconstructed payload exceeded local policy.
    PayloadTooLarge {
        /// Maximum permitted bytes.
        max: u64,
        /// Observed or declared bytes.
        actual: u64,
    },
    /// The canonical manifest exceeded local policy.
    ManifestTooLarge {
        /// Maximum permitted bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// The binary envelope exceeded local policy.
    BinaryTooLarge {
        /// Maximum permitted bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// The textual token exceeded local policy.
    TokenTooLarge {
        /// Maximum permitted bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// The token prefix was not `ra1_`.
    InvalidPrefix,
    /// The token contained whitespace, padding or a foreign alphabet byte.
    InvalidAlphabet,
    /// The token was not canonical Base64URL without padding.
    InvalidBase64,
    /// The envelope ended before a complete field.
    UnexpectedEof,
    /// The envelope magic was not `RBAT`.
    InvalidMagic,
    /// The artifact version is unsupported.
    UnsupportedVersion(u8),
    /// The artifact kind is unsupported.
    UnsupportedKind(u8),
    /// The compression algorithm is unsupported.
    UnsupportedCompression(u8),
    /// The compression profile is unsupported.
    UnsupportedProfile(u8),
    /// Header flags contained unsupported bits.
    UnsupportedFlags(u16),
    /// A reserved field was nonzero.
    NonZeroReserved,
    /// Declared and encoded metadata flags differed.
    MetadataFlagMismatch,
    /// An embedded dictionary was empty, oversized or used with another algorithm.
    InvalidDictionary,
    /// A UTF-8 manifest field was malformed.
    InvalidUtf8,
    /// A checked conversion or arithmetic operation overflowed.
    LengthOverflow,
    /// Manifest and header entry counts differed.
    EntryCountMismatch,
    /// File payload ranges were not contiguous and canonical.
    InvalidPayloadRange,
    /// Declared envelope lengths did not consume the exact input.
    EnvelopeLengthMismatch,
    /// Compressed bytes or envelope metadata were mutated.
    EnvelopeDigestMismatch,
    /// The decoded content identity differed from the canonical manifest.
    ContentDigestMismatch,
    /// One reconstructed file differed from its digest.
    FileDigestMismatch,
    /// Compression or bounded decompression failed.
    Compression(CompressionError),
}

impl fmt::Display for ArtifactTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => write!(formatter, "invalid artifact path: {error}"),
            Self::InvalidName(error) => write!(formatter, "invalid suggested name: {error}"),
            Self::InvalidFileShape => {
                formatter.write_str("file artifact must contain one pathless file")
            }
            Self::InvalidDirectoryShape => {
                formatter.write_str("directory artifact entries require portable paths")
            }
            Self::DuplicatePath => formatter.write_str("duplicate artifact path"),
            Self::PathTypeConflict => {
                formatter.write_str("artifact file path is an ancestor of another entry")
            }
            Self::NonCanonicalOrder => formatter.write_str("artifact entries are not canonical"),
            Self::InvalidDirectoryEntry => {
                formatter.write_str("directory entry contains file-only fields")
            }
            Self::ExecutableDirectory => {
                formatter.write_str("directory entry cannot be executable")
            }
            Self::TooManyEntries { max, actual } => {
                write!(formatter, "artifact has {actual} entries; maximum is {max}")
            }
            Self::FileTooLarge { max, actual } => {
                write!(
                    formatter,
                    "artifact file has {actual} bytes; maximum is {max}"
                )
            }
            Self::PayloadTooLarge { max, actual } => {
                write!(
                    formatter,
                    "artifact payload has {actual} bytes; maximum is {max}"
                )
            }
            Self::ManifestTooLarge { max, actual } => {
                write!(
                    formatter,
                    "artifact manifest has {actual} bytes; maximum is {max}"
                )
            }
            Self::BinaryTooLarge { max, actual } => {
                write!(
                    formatter,
                    "artifact envelope has {actual} bytes; maximum is {max}"
                )
            }
            Self::TokenTooLarge { max, actual } => {
                write!(
                    formatter,
                    "artifact token has {actual} bytes; maximum is {max}"
                )
            }
            Self::InvalidPrefix => formatter.write_str("invalid artifact-token prefix"),
            Self::InvalidAlphabet => formatter.write_str("invalid artifact-token alphabet"),
            Self::InvalidBase64 => formatter.write_str("invalid artifact-token Base64URL"),
            Self::UnexpectedEof => formatter.write_str("artifact envelope is truncated"),
            Self::InvalidMagic => formatter.write_str("invalid artifact envelope magic"),
            Self::UnsupportedVersion(value) => {
                write!(formatter, "unsupported artifact version {value}")
            }
            Self::UnsupportedKind(value) => write!(formatter, "unsupported artifact kind {value}"),
            Self::UnsupportedCompression(value) => {
                write!(formatter, "unsupported artifact compression {value}")
            }
            Self::UnsupportedProfile(value) => {
                write!(formatter, "unsupported artifact profile {value}")
            }
            Self::UnsupportedFlags(value) => {
                write!(formatter, "unsupported artifact flags 0x{value:04x}")
            }
            Self::NonZeroReserved => formatter.write_str("artifact reserved field is nonzero"),
            Self::MetadataFlagMismatch => {
                formatter.write_str("artifact metadata flags do not match its manifest")
            }
            Self::InvalidDictionary => {
                formatter.write_str("artifact dictionary metadata is invalid")
            }
            Self::InvalidUtf8 => formatter.write_str("artifact manifest is not valid UTF-8"),
            Self::LengthOverflow => formatter.write_str("artifact length overflow"),
            Self::EntryCountMismatch => {
                formatter.write_str("artifact entry count does not match its header")
            }
            Self::InvalidPayloadRange => {
                formatter.write_str("artifact payload ranges are not canonical")
            }
            Self::EnvelopeLengthMismatch => {
                formatter.write_str("artifact envelope length mismatch")
            }
            Self::EnvelopeDigestMismatch => {
                formatter.write_str("artifact envelope digest mismatch")
            }
            Self::ContentDigestMismatch => formatter.write_str("artifact content digest mismatch"),
            Self::FileDigestMismatch => formatter.write_str("artifact file digest mismatch"),
            Self::Compression(error) => write!(formatter, "artifact compression failed: {error}"),
        }
    }
}

impl std::error::Error for ArtifactTokenError {}

impl From<CompressionError> for ArtifactTokenError {
    fn from(value: CompressionError) -> Self {
        Self::Compression(value)
    }
}

impl From<PathError> for ArtifactTokenError {
    fn from(value: PathError) -> Self {
        Self::Path(value)
    }
}
