//! Codec errors that do not echo untrusted content.

use core::fmt;
use rebyte_format::{FormatError, PathError};

/// Failure to encode or decode a canonical RAP value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CodecError {
    /// Input exceeded a configured byte limit.
    InputTooLarge {
        /// Maximum permitted length.
        max: u64,
        /// Observed length.
        actual: u64,
    },
    /// Checked length arithmetic overflowed.
    LengthOverflow,
    /// Input ended before a declared field was complete.
    UnexpectedEof,
    /// Bytes remained after the canonical representation ended.
    TrailingBytes,
    /// Envelope magic did not match `RBAP`.
    InvalidMagic,
    /// A reserved field was non-zero.
    NonZeroReserved,
    /// Manifest version was not supported.
    InvalidManifestVersion(u16),
    /// Optional-field tag was not zero or one.
    InvalidOptionalTag(u8),
    /// Boolean field was not zero or one.
    InvalidBoolean(u8),
    /// String bytes were not valid UTF-8.
    InvalidUtf8,
    /// Manifest paths were not strictly increasing.
    NonCanonicalPathOrder,
    /// A file range had a gap, overlap or overflow.
    NonContiguousPayload,
    /// Header file count and manifest entry count differed.
    FileCountMismatch,
    /// Header output size and manifest file ranges differed.
    PayloadSizeMismatch,
    /// Text content metadata was structurally inconsistent.
    InvalidTextContent,
    /// Token prefix was missing or unsupported.
    InvalidTokenPrefix,
    /// Token contained padding, whitespace or a non-Base64URL character.
    InvalidTokenAlphabet,
    /// Base64URL decoding failed.
    InvalidBase64,
    /// A bounded protocol value was invalid.
    Format(FormatError),
    /// A portable path was invalid.
    Path(PathError),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { max, actual } => {
                write!(formatter, "input has {actual} bytes; maximum is {max}")
            }
            Self::LengthOverflow => formatter.write_str("capsule length overflow"),
            Self::UnexpectedEof => formatter.write_str("capsule is truncated"),
            Self::TrailingBytes => formatter.write_str("capsule has trailing bytes"),
            Self::InvalidMagic => formatter.write_str("invalid capsule magic"),
            Self::NonZeroReserved => formatter.write_str("reserved field is non-zero"),
            Self::InvalidManifestVersion(value) => {
                write!(formatter, "unsupported manifest version {value}")
            }
            Self::InvalidOptionalTag(value) => write!(formatter, "invalid optional tag {value}"),
            Self::InvalidBoolean(value) => write!(formatter, "invalid boolean value {value}"),
            Self::InvalidUtf8 => formatter.write_str("invalid UTF-8 string"),
            Self::NonCanonicalPathOrder => {
                formatter.write_str("manifest paths are not strictly ordered")
            }
            Self::NonContiguousPayload => {
                formatter.write_str("manifest payload ranges are not contiguous")
            }
            Self::FileCountMismatch => formatter.write_str("manifest file count mismatch"),
            Self::PayloadSizeMismatch => formatter.write_str("manifest payload size mismatch"),
            Self::InvalidTextContent => formatter.write_str("text content is not valid UTF-8"),
            Self::InvalidTokenPrefix => formatter.write_str("invalid token prefix"),
            Self::InvalidTokenAlphabet => formatter.write_str("invalid token alphabet"),
            Self::InvalidBase64 => formatter.write_str("invalid Base64URL payload"),
            Self::Format(error) => write!(formatter, "invalid format: {error}"),
            Self::Path(error) => write!(formatter, "invalid path: {error}"),
        }
    }
}

impl core::error::Error for CodecError {}

impl From<FormatError> for CodecError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

impl From<PathError> for CodecError {
    fn from(value: PathError) -> Self {
        Self::Path(value)
    }
}
