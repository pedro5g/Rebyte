//! Bounded compression and decompression for Rebyte formats.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;

use rebyte_format::{CompressionAlgorithm, SecurityLimits};

/// Fixed native Zstandard compression level used by RAP v1.
pub const ZSTD_LEVEL_V1: i32 = 3;

const BUFFER_SIZE: usize = 64 * 1_024;
const ZSTD_LEVEL_FAST: i32 = 1;
const ZSTD_LEVEL_MAXIMUM: i32 = 19;
const MAXIMUM_WINDOW_LOG: u32 = 27;

/// Reproducible speed-versus-size policy for native Zstandard encoding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
    /// A stream differed from its declared exact size.
    SizeMismatch {
        /// Declared byte count.
        expected: u64,
        /// Observed byte count.
        actual: u64,
    },
    /// The Zstandard stream was malformed, truncated or unsupported.
    InvalidStream,
    /// Native compression failed.
    CompressionFailed,
    /// A source stream could not be read.
    InputReadFailed,
    /// A destination stream could not be written.
    OutputWriteFailed,
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
                write!(formatter, "stream has {actual} bytes; expected {expected}")
            }
            Self::InvalidStream => formatter.write_str("invalid or truncated compression stream"),
            Self::CompressionFailed => formatter.write_str("compression failed"),
            Self::InputReadFailed => formatter.write_str("cannot read compression input"),
            Self::OutputWriteFailed => formatter.write_str("cannot write compression output"),
            Self::UnsupportedEncoder => {
                formatter.write_str("Zstandard encoding is unavailable on this target")
            }
            Self::LengthOverflow => formatter.write_str("compression length overflow"),
        }
    }
}

impl std::error::Error for CompressionError {}

/// Byte counts produced by a bounded streaming operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressionStats {
    /// Exact bytes consumed from the source.
    pub input_bytes: u64,
    /// Exact bytes written to the destination.
    pub output_bytes: u64,
}

/// Compresses payload bytes using the balanced RAP encoder profile.
///
/// # Errors
///
/// Returns [`CompressionError`] when input or output exceeds `limits`, native
/// compression fails, or Zstandard encoding is requested in WebAssembly.
pub fn compress(
    input: &[u8],
    algorithm: CompressionAlgorithm,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    compress_with_profile(input, algorithm, CompressionProfile::Balanced, limits)
}

/// Compresses bytes with an explicit deterministic resource profile.
///
/// Compression-ratio policy is intentionally enforced only while decoding.
/// Rejecting a locally produced frame because it compresses extremely well
/// would force the encoder to retain a much larger verbatim representation.
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
    enforce_compressed_limit(usize_to_u64(output.len())?, limits)?;
    Ok(output)
}

/// Compresses exactly `declared_input_size` bytes without materializing them.
///
/// The destination is bounded by `limits.max_compressed_payload_bytes`.
/// Input shorter or longer than declared is rejected.
///
/// # Errors
///
/// Returns [`CompressionError`] for size or resource-limit violations, I/O
/// failures, native encoder failures or unavailable target support.
pub fn compress_stream(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    algorithm: CompressionAlgorithm,
    profile: CompressionProfile,
    declared_input_size: u64,
    limits: &SecurityLimits,
) -> Result<CompressionStats, CompressionError> {
    enforce_output_limit(declared_input_size, limits)?;
    let mut bounded = BoundedWriter::new(output, limits.max_compressed_payload_bytes);
    let operation = match algorithm {
        CompressionAlgorithm::None => copy_declared(input, &mut bounded, declared_input_size),
        CompressionAlgorithm::Zstd => {
            compress_zstd_stream(input, &mut bounded, profile, declared_input_size)
        }
    };
    if bounded.exceeded {
        return Err(CompressionError::CompressedInputTooLarge {
            max: limits.max_compressed_payload_bytes,
            actual: bounded.attempted,
        });
    }
    operation?;
    Ok(CompressionStats {
        input_bytes: declared_input_size,
        output_bytes: bounded.written,
    })
}

/// Decompresses payload bytes while enforcing all limits during streaming.
///
/// # Errors
///
/// Returns [`CompressionError`] before decompression when declared lengths
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

/// Decompresses one exact bounded stream into a caller-selected destination.
///
/// # Errors
///
/// Returns [`CompressionError`] before or during decoding when declared
/// lengths violate policy, the stream is malformed, I/O fails or exact output
/// size is not reproduced.
pub fn decompress_stream(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    algorithm: CompressionAlgorithm,
    declared_compressed_size: u64,
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<CompressionStats, CompressionError> {
    enforce_compressed_limit(declared_compressed_size, limits)?;
    enforce_output_limit(declared_output_size, limits)?;
    enforce_ratio(declared_compressed_size, declared_output_size, limits)?;
    let mut limited = LimitedReader::new(input, declared_compressed_size);
    let output_bytes = match algorithm {
        CompressionAlgorithm::None => {
            if declared_compressed_size != declared_output_size {
                return Err(CompressionError::SizeMismatch {
                    expected: declared_output_size,
                    actual: declared_compressed_size,
                });
            }
            copy_declared(&mut limited, output, declared_output_size)?;
            declared_output_size
        }
        CompressionAlgorithm::Zstd => {
            decompress_zstd_stream(&mut limited, output, declared_output_size, limits)?
        }
    };
    if limited.remaining != 0 {
        return Err(CompressionError::InvalidStream);
    }
    Ok(CompressionStats {
        input_bytes: declared_compressed_size,
        output_bytes,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn compress_zstd(input: &[u8], profile: CompressionProfile) -> Result<Vec<u8>, CompressionError> {
    let mut output = Vec::new();
    let mut source = input;
    compress_zstd_stream(
        &mut source,
        &mut output,
        profile,
        usize_to_u64(input.len())?,
    )?;
    Ok(output)
}

#[cfg(target_arch = "wasm32")]
fn compress_zstd(_input: &[u8], _profile: CompressionProfile) -> Result<Vec<u8>, CompressionError> {
    Err(CompressionError::UnsupportedEncoder)
}

#[cfg(not(target_arch = "wasm32"))]
fn compress_zstd_stream(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    profile: CompressionProfile,
    declared_input_size: u64,
) -> Result<(), CompressionError> {
    let mut encoder = zstd::stream::write::Encoder::new(output, profile.level())
        .map_err(|_| CompressionError::CompressionFailed)?;
    encoder
        .include_checksum(false)
        .map_err(|_| CompressionError::CompressionFailed)?;
    encoder
        .include_contentsize(true)
        .map_err(|_| CompressionError::CompressionFailed)?;
    encoder
        .set_pledged_src_size(Some(declared_input_size))
        .map_err(|_| CompressionError::CompressionFailed)?;
    if profile == CompressionProfile::Maximum {
        encoder
            .long_distance_matching(true)
            .map_err(|_| CompressionError::CompressionFailed)?;
        encoder
            .window_log(MAXIMUM_WINDOW_LOG)
            .map_err(|_| CompressionError::CompressionFailed)?;
    }
    let copied = copy_declared(input, &mut encoder, declared_input_size);
    let finished = encoder
        .finish()
        .map_err(|_| CompressionError::CompressionFailed)
        .map(|_| ());
    copied.and(finished)
}

#[cfg(target_arch = "wasm32")]
fn compress_zstd_stream(
    _input: &mut impl io::Read,
    _output: &mut impl io::Write,
    _profile: CompressionProfile,
    _declared_input_size: u64,
) -> Result<(), CompressionError> {
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

#[cfg(not(target_arch = "wasm32"))]
fn decompress_zstd_stream(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<u64, CompressionError> {
    let mut decoder =
        zstd::stream::read::Decoder::new(input).map_err(|_| CompressionError::InvalidStream)?;
    copy_decoded(&mut decoder, output, declared_output_size, limits)
}

#[cfg(target_arch = "wasm32")]
fn decompress_zstd_stream(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<u64, CompressionError> {
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(input)
        .map_err(|_| CompressionError::InvalidStream)?;
    copy_decoded(&mut decoder, output, declared_output_size, limits)
}

fn read_bounded(
    reader: &mut impl io::Read,
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<Vec<u8>, CompressionError> {
    let initial_capacity =
        usize::try_from(declared_output_size).map_err(|_| CompressionError::LengthOverflow)?;
    let mut output = Vec::with_capacity(initial_capacity.min(BUFFER_SIZE));
    copy_decoded(reader, &mut output, declared_output_size, limits)?;
    Ok(output)
}

fn copy_decoded(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    declared_output_size: u64,
    limits: &SecurityLimits,
) -> Result<u64, CompressionError> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut written = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|_| CompressionError::InvalidStream)?;
        if read == 0 {
            break;
        }
        let next = written
            .checked_add(usize_to_u64(read)?)
            .ok_or(CompressionError::LengthOverflow)?;
        if next > declared_output_size {
            return Err(CompressionError::SizeMismatch {
                expected: declared_output_size,
                actual: next,
            });
        }
        enforce_output_limit(next, limits)?;
        output
            .write_all(buffer.get(..read).ok_or(CompressionError::LengthOverflow)?)
            .map_err(|_| CompressionError::OutputWriteFailed)?;
        written = next;
    }
    if written != declared_output_size {
        return Err(CompressionError::SizeMismatch {
            expected: declared_output_size,
            actual: written,
        });
    }
    Ok(written)
}

fn copy_declared(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    expected: u64,
) -> Result<(), CompressionError> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut consumed = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|_| CompressionError::InputReadFailed)?;
        if read == 0 {
            break;
        }
        let next = consumed
            .checked_add(usize_to_u64(read)?)
            .ok_or(CompressionError::LengthOverflow)?;
        if next > expected {
            return Err(CompressionError::SizeMismatch {
                expected,
                actual: next,
            });
        }
        output
            .write_all(buffer.get(..read).ok_or(CompressionError::LengthOverflow)?)
            .map_err(|_| CompressionError::OutputWriteFailed)?;
        consumed = next;
    }
    if consumed != expected {
        return Err(CompressionError::SizeMismatch {
            expected,
            actual: consumed,
        });
    }
    Ok(())
}

struct BoundedWriter<'a, W> {
    inner: &'a mut W,
    maximum: u64,
    written: u64,
    attempted: u64,
    exceeded: bool,
}

impl<'a, W> BoundedWriter<'a, W> {
    const fn new(inner: &'a mut W, maximum: u64) -> Self {
        Self {
            inner,
            maximum,
            written: 0,
            attempted: 0,
            exceeded: false,
        }
    }
}

impl<W: io::Write> io::Write for BoundedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("compression length overflow"))?;
        let next = self
            .written
            .checked_add(length)
            .ok_or_else(|| io::Error::other("compression length overflow"))?;
        self.attempted = next;
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("compressed output limit exceeded"));
        }
        let written = self.inner.write(bytes)?;
        let written_u64 =
            u64::try_from(written).map_err(|_| io::Error::other("compression length overflow"))?;
        self.written = self
            .written
            .checked_add(written_u64)
            .ok_or_else(|| io::Error::other("compression length overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct LimitedReader<'a, R> {
    inner: &'a mut R,
    remaining: u64,
}

impl<'a, R> LimitedReader<'a, R> {
    const fn new(inner: &'a mut R, remaining: u64) -> Self {
        Self { inner, remaining }
    }
}

impl<R: io::Read> io::Read for LimitedReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let maximum = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(output.len());
        let read = self.inner.read(
            output
                .get_mut(..maximum)
                .ok_or_else(|| io::Error::other("compression length overflow"))?,
        )?;
        let read_u64 =
            u64::try_from(read).map_err(|_| io::Error::other("compression length overflow"))?;
        self.remaining = self
            .remaining
            .checked_sub(read_u64)
            .ok_or_else(|| io::Error::other("compression length overflow"))?;
        Ok(read)
    }
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
    use std::io::Cursor;

    use rebyte_format::{CompressionAlgorithm, SecurityLimits};

    use super::{
        CompressionError, CompressionProfile, compress, compress_stream, compress_with_profile,
        decompress, decompress_stream,
    };

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
    fn streaming_round_trip_is_exact_and_bounded() -> Result<(), CompressionError> {
        let input = b"streaming rebyte\n".repeat(100_000);
        let length = u64::try_from(input.len()).map_err(|_| CompressionError::LengthOverflow)?;
        let mut source = Cursor::new(&input);
        let mut compressed = Vec::new();
        let encoded = compress_stream(
            &mut source,
            &mut compressed,
            CompressionAlgorithm::Zstd,
            CompressionProfile::Balanced,
            length,
            &SecurityLimits::SIMPLE_ARTIFACT,
        )?;
        assert_eq!(encoded.input_bytes, length);
        assert_eq!(
            encoded.output_bytes,
            u64::try_from(compressed.len()).map_err(|_| CompressionError::LengthOverflow)?
        );
        let mut compressed_source = Cursor::new(&compressed);
        let mut output = Vec::new();
        let decoded = decompress_stream(
            &mut compressed_source,
            &mut output,
            CompressionAlgorithm::Zstd,
            encoded.output_bytes,
            length,
            &SecurityLimits::SIMPLE_ARTIFACT,
        )?;
        assert_eq!(decoded.output_bytes, length);
        assert_eq!(output, input);
        Ok(())
    }

    #[test]
    fn streaming_rejects_wrong_input_length() {
        let mut source = Cursor::new(b"short");
        let mut output = Vec::new();
        assert_eq!(
            compress_stream(
                &mut source,
                &mut output,
                CompressionAlgorithm::None,
                CompressionProfile::Balanced,
                10,
                &SecurityLimits::SIMPLE_ARTIFACT,
            ),
            Err(CompressionError::SizeMismatch {
                expected: 10,
                actual: 5,
            })
        );
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
