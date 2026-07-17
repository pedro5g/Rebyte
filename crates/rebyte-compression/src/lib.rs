//! Bounded compression and decompression for RAP v1.

#![forbid(unsafe_code)]

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::io::Write as _;

use rebyte_format::{CompressionAlgorithm, SecurityLimits};

/// Fixed native Zstandard compression level used by RAP v1.
pub const ZSTD_LEVEL_V1: i32 = 3;

const BUFFER_SIZE: usize = 64 * 1_024;
const ZSTD_LEVEL_FAST: i32 = 1;
const ZSTD_LEVEL_MAXIMUM: i32 = 19;
const MAXIMUM_WINDOW_LOG: u32 = 27;

/// Reproducible speed-versus-size policy for native Zstandard encoding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompressionProfile {
    /// Prefer encoding speed and low working memory.
    Fast,
    /// Use the stable RAP v1 level and balanced resource usage.
    #[default]
    Balanced,
    /// Spend substantially more CPU and enable bounded long-distance matching.
    Maximum,
}

impl CompressionProfile {
    const fn level(self) -> i32 {
        match self {
            Self::Fast => ZSTD_LEVEL_FAST,
            Self::Balanced => ZSTD_LEVEL_V1,
            Self::Maximum => ZSTD_LEVEL_MAXIMUM,
        }
    }
}

/// Compression or bounded decompression failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompressionError {
    /// Compressed input exceeded local policy.
    CompressedInputTooLarge {
        /// Maximum permitted bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Uncompressed input or output exceeded local policy.
    OutputTooLarge {
        /// Maximum permitted bytes.
        max: u64,
        /// Observed or declared bytes.
        actual: u64,
    },
    /// Declared expansion exceeded local policy.
    CompressionRatioExceeded {
        /// Maximum permitted ratio.
        max: u64,
    },
    /// Reconstructed output differed from the signed declared size.
    SizeMismatch {
        /// Signed declared byte count.
        expected: u64,
        /// Reconstructed byte count.
        actual: u64,
    },
    /// The Zstandard stream was malformed, truncated or unsupported.
    InvalidStream,
    /// Native compression failed.
    CompressionFailed,
    /// Zstandard encoding is deliberately unavailable in WebAssembly.
    UnsupportedEncoder,
    /// A platform length conversion overflowed.
    LengthOverflow,
}

impl fmt::Display for CompressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompressedInputTooLarge { max, actual } => {
                write!(
                    formatter,
                    "compressed input has {actual} bytes; maximum is {max}"
                )
            }
            Self::OutputTooLarge { max, actual } => {
                write!(formatter, "output has {actual} bytes; maximum is {max}")
            }
            Self::CompressionRatioExceeded { max } => {
                write!(formatter, "declared compression ratio exceeds {max}:1")
            }
            Self::SizeMismatch { expected, actual } => {
                write!(formatter, "output has {actual} bytes; expected {expected}")
            }
            Self::InvalidStream => formatter.write_str("invalid or truncated compression stream"),
            Self::CompressionFailed => formatter.write_str("compression failed"),
            Self::UnsupportedEncoder => {
                formatter.write_str("Zstandard encoding is unavailable on this target")
            }
            Self::LengthOverflow => formatter.write_str("compression length overflow"),
        }
    }
}

impl std::error::Error for CompressionError {}

/// Compresses payload bytes using the selected RAP algorithm.
///
/// # Errors
///
/// Returns [`CompressionError`] when input or output exceeds `limits`, native
/// compression fails, or Zstandard encoding is requested in WebAssembly.
///
/// Compression-ratio policy is intentionally enforced only while decoding.
/// Rejecting a locally produced frame because it compresses extremely well
/// would force the encoder to retain a much larger verbatim representation.
pub fn compress(
    input: &[u8],
    algorithm: CompressionAlgorithm,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    compress_with_profile(input, algorithm, CompressionProfile::Balanced, limits)
}

/// Compresses bytes with an explicit deterministic resource profile.
///
/// The selected profile affects only encoder effort. Every resulting frame is
/// decoded by the same bounded Zstandard path.
///
/// # Errors
///
/// Returns [`CompressionError`] under the same conditions as [`compress`].
pub fn compress_with_profile(
    input: &[u8],
    algorithm: CompressionAlgorithm,
    profile: CompressionProfile,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    let input_len = usize_to_u64(input.len())?;
    enforce_output_limit(input_len, limits)?;
    let output = match algorithm {
        CompressionAlgorithm::None => input.to_vec(),
        CompressionAlgorithm::Zstd => compress_zstd(input, profile)?,
    };
    let output_len = usize_to_u64(output.len())?;
    enforce_compressed_limit(output_len, limits)?;
    Ok(output)
}

/// Decompresses payload bytes while enforcing all limits during streaming.
///
/// # Errors
///
/// Returns [`CompressionError`] before decompression when signed lengths
/// violate policy, or during streaming when data is malformed, truncated,
/// oversized or differs from `declared_output_size`.
pub fn decompress(
    input: &[u8],
    algorithm: CompressionAlgorithm,
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    let compressed_size = usize_to_u64(input.len())?;
    enforce_compressed_limit(compressed_size, limits)?;
    enforce_output_limit(declared_output_size, limits)?;
    enforce_ratio(compressed_size, declared_output_size, limits)?;

    let output = match algorithm {
        CompressionAlgorithm::None => input.to_vec(),
        CompressionAlgorithm::Zstd => decompress_zstd(input, declared_output_size, limits)?,
    };
    let actual = usize_to_u64(output.len())?;
    if actual != declared_output_size {
        return Err(CompressionError::SizeMismatch {
            expected: declared_output_size,
            actual,
        });
    }
    Ok(output)
}

#[cfg(not(target_arch = "wasm32"))]
fn compress_zstd(input: &[u8], profile: CompressionProfile) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), profile.level())
        .map_err(|_| CompressionError::CompressionFailed)?;
    encoder
        .include_checksum(false)
        .map_err(|_| CompressionError::CompressionFailed)?;
    encoder
        .include_contentsize(true)
        .map_err(|_| CompressionError::CompressionFailed)?;
    encoder
        .set_pledged_src_size(Some(usize_to_u64(input.len())?))
        .map_err(|_| CompressionError::CompressionFailed)?;
    if profile == CompressionProfile::Maximum {
        encoder
            .long_distance_matching(true)
            .map_err(|_| CompressionError::CompressionFailed)?;
        encoder
            .window_log(MAXIMUM_WINDOW_LOG)
            .map_err(|_| CompressionError::CompressionFailed)?;
    }
    encoder
        .write_all(input)
        .map_err(|_| CompressionError::CompressionFailed)?;
    encoder
        .finish()
        .map_err(|_| CompressionError::CompressionFailed)
}

#[cfg(target_arch = "wasm32")]
fn compress_zstd(_input: &[u8], _profile: CompressionProfile) -> Result<Vec<u8>, CompressionError> {
    Err(CompressionError::UnsupportedEncoder)
}

#[cfg(not(target_arch = "wasm32"))]
fn decompress_zstd(
    input: &[u8],
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    let mut decoder =
        zstd::stream::read::Decoder::new(input).map_err(|_| CompressionError::InvalidStream)?;
    read_bounded(&mut decoder, declared_output_size, limits)
}

#[cfg(target_arch = "wasm32")]
fn decompress_zstd(
    input: &[u8],
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(input)
        .map_err(|_| CompressionError::InvalidStream)?;
    read_bounded(&mut decoder, declared_output_size, limits)
}

fn read_bounded(
    reader: &mut impl std::io::Read,
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    let initial_capacity =
        usize::try_from(declared_output_size).map_err(|_| CompressionError::LengthOverflow)?;
    let mut output = Vec::with_capacity(initial_capacity.min(BUFFER_SIZE));
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| CompressionError::InvalidStream)?;
        if read == 0 {
            break;
        }
        let next_len = output
            .len()
            .checked_add(read)
            .ok_or(CompressionError::LengthOverflow)?;
        let next_len_u64 = usize_to_u64(next_len)?;
        if next_len_u64 > declared_output_size {
            return Err(CompressionError::SizeMismatch {
                expected: declared_output_size,
                actual: next_len_u64,
            });
        }
        enforce_output_limit(next_len_u64, limits)?;
        output.extend_from_slice(buffer.get(..read).ok_or(CompressionError::LengthOverflow)?);
    }
    Ok(output)
}

const fn enforce_compressed_limit(
    actual: u64,
    limits: &SecurityLimits,
) -> Result<(), CompressionError> {
    if actual > limits.max_compressed_payload_bytes {
        Err(CompressionError::CompressedInputTooLarge {
            max: limits.max_compressed_payload_bytes,
            actual,
        })
    } else {
        Ok(())
    }
}

const fn enforce_output_limit(
    actual: u64,
    limits: &SecurityLimits,
) -> Result<(), CompressionError> {
    if actual > limits.max_uncompressed_payload_bytes {
        Err(CompressionError::OutputTooLarge {
            max: limits.max_uncompressed_payload_bytes,
            actual,
        })
    } else {
        Ok(())
    }
}

const fn enforce_ratio(
    compressed: u64,
    uncompressed: u64,
    limits: &SecurityLimits,
) -> Result<(), CompressionError> {
    if uncompressed == 0 {
        return Ok(());
    }
    if compressed == 0 || uncompressed > compressed.saturating_mul(limits.max_compression_ratio) {
        Err(CompressionError::CompressionRatioExceeded {
            max: limits.max_compression_ratio,
        })
    } else {
        Ok(())
    }
}

fn usize_to_u64(value: usize) -> Result<u64, CompressionError> {
    u64::try_from(value).map_err(|_| CompressionError::LengthOverflow)
}

#[cfg(test)]
mod tests {
    use super::{
        CompressionError, CompressionProfile, compress, compress_with_profile, decompress,
    };
    use rebyte_format::{CompressionAlgorithm, SecurityLimits};

    #[test]
    fn none_round_trip_is_exact() -> Result<(), CompressionError> {
        let bytes = b"exact\0bytes\n";
        let compressed = compress(bytes, CompressionAlgorithm::None, &SecurityLimits::V1)?;
        assert_eq!(
            decompress(
                &compressed,
                CompressionAlgorithm::None,
                u64::try_from(bytes.len()).map_err(|_| CompressionError::LengthOverflow)?,
                &SecurityLimits::V1,
            )?,
            bytes
        );
        Ok(())
    }

    #[test]
    fn zstd_round_trip_is_exact() -> Result<(), CompressionError> {
        let bytes = b"rebyte payload rebyte payload rebyte payload";
        let compressed = compress(bytes, CompressionAlgorithm::Zstd, &SecurityLimits::V1)?;
        assert_eq!(
            decompress(
                &compressed,
                CompressionAlgorithm::Zstd,
                u64::try_from(bytes.len()).map_err(|_| CompressionError::LengthOverflow)?,
                &SecurityLimits::V1,
            )?,
            bytes
        );
        Ok(())
    }

    #[test]
    fn encoding_does_not_reject_extreme_compression_ratio() -> Result<(), CompressionError> {
        let bytes = vec![b'x'; 2 * 1_024 * 1_024];
        let compressed = compress(&bytes, CompressionAlgorithm::Zstd, &SecurityLimits::V1)?;
        assert!(compressed.len() < bytes.len() / 200);
        assert!(matches!(
            decompress(
                &compressed,
                CompressionAlgorithm::Zstd,
                u64::try_from(bytes.len()).map_err(|_| CompressionError::LengthOverflow)?,
                &SecurityLimits::V1,
            ),
            Err(CompressionError::CompressionRatioExceeded { .. })
        ));
        assert_eq!(
            decompress(
                &compressed,
                CompressionAlgorithm::Zstd,
                u64::try_from(bytes.len()).map_err(|_| CompressionError::LengthOverflow)?,
                &SecurityLimits::SIMPLE_ARTIFACT,
            )?,
            bytes
        );
        Ok(())
    }

    #[test]
    fn every_profile_is_deterministic_and_decodable() -> Result<(), CompressionError> {
        let input = b"header:value\n".repeat(10_000);
        for profile in [
            CompressionProfile::Fast,
            CompressionProfile::Balanced,
            CompressionProfile::Maximum,
        ] {
            let first = compress_with_profile(
                &input,
                CompressionAlgorithm::Zstd,
                profile,
                &SecurityLimits::SIMPLE_ARTIFACT,
            )?;
            let second = compress_with_profile(
                &input,
                CompressionAlgorithm::Zstd,
                profile,
                &SecurityLimits::SIMPLE_ARTIFACT,
            )?;
            assert_eq!(first, second);
            assert_eq!(
                decompress(
                    &first,
                    CompressionAlgorithm::Zstd,
                    u64::try_from(input.len()).map_err(|_| CompressionError::LengthOverflow)?,
                    &SecurityLimits::SIMPLE_ARTIFACT,
                )?,
                input
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_wrong_declared_size() {
        assert_eq!(
            decompress(b"abc", CompressionAlgorithm::None, 2, &SecurityLimits::V1),
            Err(CompressionError::SizeMismatch {
                expected: 2,
                actual: 3,
            })
        );
    }

    #[test]
    fn rejects_declared_bomb_before_decoding() {
        let mut limits = SecurityLimits::V1;
        limits.max_compression_ratio = 2;
        assert_eq!(
            decompress(&[1], CompressionAlgorithm::Zstd, 3, &limits),
            Err(CompressionError::CompressionRatioExceeded { max: 2 })
        );
    }

    #[test]
    fn rejects_truncated_zstd_stream() -> Result<(), CompressionError> {
        let bytes = b"a bounded payload";
        let mut compressed = compress(bytes, CompressionAlgorithm::Zstd, &SecurityLimits::V1)?;
        let new_len = compressed.len().saturating_sub(2);
        compressed.truncate(new_len);
        assert!(
            decompress(
                &compressed,
                CompressionAlgorithm::Zstd,
                u64::try_from(bytes.len()).map_err(|_| CompressionError::LengthOverflow)?,
                &SecurityLimits::V1,
            )
            .is_err()
        );
        Ok(())
    }
}
