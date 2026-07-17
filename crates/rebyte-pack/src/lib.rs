//! Deterministic construction of unsigned RAP v1 capsule material.

#![forbid(unsafe_code)]

use std::fmt;

use rebyte_codec::{CodecError, encode_manifest};
use rebyte_compression::{CompressionError, compress};
use rebyte_format::{
    BoundedString, CapsuleManifestV1, CompressionAlgorithm, ContentKind, FileEntryV1,
    FileOperation, FormatError, MAX_CAPSULE_NAME_BYTES, MAX_DESCRIPTION_BYTES,
    MAX_PRODUCER_VERSION_BYTES, PathError, ProducerMetadata, RelativeArtifactPath, SecurityLimits,
};
use rebyte_integrity::file_digest;

/// Final file bytes supplied by a producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactFile {
    /// Portable target path.
    pub relative_path: RelativeArtifactPath,
    /// Exact bytes to reconstruct.
    pub bytes: Vec<u8>,
    /// Portable executable flag.
    pub executable: bool,
}

impl ArtifactFile {
    /// Validates `relative_path` and copies the artifact bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::Path`] when the path is not portable RAP v1 data.
    pub fn new(relative_path: &str, bytes: impl Into<Vec<u8>>) -> Result<Self, PackError> {
        Ok(Self {
            relative_path: RelativeArtifactPath::new(relative_path)?,
            bytes: bytes.into(),
            executable: false,
        })
    }

    /// Sets the portable executable flag.
    #[must_use]
    pub const fn with_executable(mut self, executable: bool) -> Self {
        self.executable = executable;
        self
    }
}

/// Deterministic producer and compression options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackOptions {
    /// Signed optional capsule name.
    pub capsule_name: Option<BoundedString<MAX_CAPSULE_NAME_BYTES>>,
    /// Signed optional capsule description.
    pub description: Option<BoundedString<MAX_DESCRIPTION_BYTES>>,
    /// Signed producer metadata.
    pub producer: ProducerMetadata,
    /// Payload compression algorithm.
    pub compression: CompressionAlgorithm,
    /// Local defensive limits.
    pub limits: SecurityLimits,
}

impl PackOptions {
    /// Creates options with Zstandard and RAP v1 limits.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::Format`] when `producer_name` is empty or exceeds
    /// the RAP v1 producer-name limit.
    pub fn new(producer_name: &str) -> Result<Self, PackError> {
        Ok(Self {
            capsule_name: None,
            description: None,
            producer: ProducerMetadata {
                name: BoundedString::new(producer_name, "producer name")?,
                version: None,
            },
            compression: CompressionAlgorithm::Zstd,
            limits: SecurityLimits::V1,
        })
    }

    /// Sets an optional producer version.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::Format`] when `version` is empty or oversized.
    pub fn with_producer_version(mut self, version: &str) -> Result<Self, PackError> {
        self.producer.version = Some(BoundedString::<MAX_PRODUCER_VERSION_BYTES>::new(
            version,
            "producer version",
        )?);
        Ok(self)
    }

    /// Sets an optional capsule name.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::Format`] when `name` is empty or oversized.
    pub fn with_capsule_name(mut self, name: &str) -> Result<Self, PackError> {
        self.capsule_name = Some(BoundedString::new(name, "capsule name")?);
        Ok(self)
    }

    /// Sets an optional capsule description.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::Format`] when `description` is empty or oversized.
    pub fn with_description(mut self, description: &str) -> Result<Self, PackError> {
        self.description = Some(BoundedString::new(description, "description")?);
        Ok(self)
    }
}

/// Canonical material awaiting a publisher key and signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedCapsule {
    /// Canonical manifest.
    pub manifest: CapsuleManifestV1,
    /// Canonical compressed payload.
    pub compressed_payload: Vec<u8>,
    /// Signed reconstructed payload byte count.
    pub uncompressed_payload_size: u64,
    /// Selected compression algorithm.
    pub compression: CompressionAlgorithm,
}

/// Deterministically packs final artifact bytes without signing them.
///
/// # Errors
///
/// Returns [`PackError`] for duplicate paths, count/size limits, arithmetic
/// overflow, non-canonical metadata or compression failure.
pub fn pack(
    artifacts: &[ArtifactFile],
    options: &PackOptions,
) -> Result<UnsignedCapsule, PackError> {
    let file_count = u32::try_from(artifacts.len()).map_err(|_| PackError::LengthOverflow)?;
    if file_count > options.limits.max_file_count {
        return Err(PackError::TooManyFiles {
            max: options.limits.max_file_count,
            actual: file_count,
        });
    }

    let mut ordered: Vec<&ArtifactFile> = artifacts.iter().collect();
    ordered.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
    reject_duplicates(&ordered)?;

    let total_size = total_size(&ordered, &options.limits)?;
    let capacity = usize::try_from(total_size).map_err(|_| PackError::LengthOverflow)?;
    let mut payload = Vec::with_capacity(capacity);
    let mut entries = Vec::with_capacity(ordered.len());
    let mut offset = 0_u64;
    for artifact in ordered {
        let size = u64::try_from(artifact.bytes.len()).map_err(|_| PackError::LengthOverflow)?;
        let content_kind = if core::str::from_utf8(&artifact.bytes).is_ok() {
            ContentKind::TextUtf8
        } else {
            ContentKind::Binary
        };
        entries.push(FileEntryV1 {
            path: artifact.relative_path.clone(),
            operation: FileOperation::CreateOrReplace,
            content_kind,
            executable: artifact.executable,
            offset,
            size,
            digest: file_digest(&artifact.bytes),
        });
        payload.extend_from_slice(&artifact.bytes);
        offset = offset.checked_add(size).ok_or(PackError::LengthOverflow)?;
    }

    let manifest = CapsuleManifestV1 {
        capsule_name: options.capsule_name.clone(),
        description: options.description.clone(),
        producer: options.producer.clone(),
        files: entries,
    };
    let manifest_size =
        u64::try_from(encode_manifest(&manifest)?.len()).map_err(|_| PackError::LengthOverflow)?;
    if manifest_size > options.limits.max_manifest_bytes {
        return Err(PackError::ManifestTooLarge {
            max: options.limits.max_manifest_bytes,
            actual: manifest_size,
        });
    }
    let compressed_payload = compress(&payload, options.compression, &options.limits)?;
    Ok(UnsignedCapsule {
        manifest,
        compressed_payload,
        uncompressed_payload_size: total_size,
        compression: options.compression,
    })
}

/// Failure to construct deterministic unsigned capsule material.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PackError {
    /// Artifact path was unsafe or non-portable.
    Path(PathError),
    /// Metadata was not a bounded RAP value.
    Format(FormatError),
    /// Canonical manifest encoding failed.
    Codec(CodecError),
    /// Compression failed or violated local limits.
    Compression(CompressionError),
    /// Two artifacts targeted the same canonical path.
    DuplicatePath,
    /// File count exceeded local policy.
    TooManyFiles {
        /// Maximum count.
        max: u32,
        /// Observed count.
        actual: u32,
    },
    /// A file exceeded local policy.
    FileTooLarge {
        /// Maximum bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Total output exceeded local policy.
    OutputTooLarge {
        /// Maximum bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Canonical manifest exceeded local policy.
    ManifestTooLarge {
        /// Maximum bytes.
        max: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Platform or protocol arithmetic overflowed.
    LengthOverflow,
}

impl fmt::Display for PackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => write!(formatter, "invalid artifact path: {error}"),
            Self::Format(error) => write!(formatter, "invalid artifact metadata: {error}"),
            Self::Codec(error) => write!(formatter, "cannot encode manifest: {error}"),
            Self::Compression(error) => write!(formatter, "cannot compress payload: {error}"),
            Self::DuplicatePath => formatter.write_str("duplicate artifact path"),
            Self::TooManyFiles { max, actual } => {
                write!(
                    formatter,
                    "artifact set has {actual} files; maximum is {max}"
                )
            }
            Self::FileTooLarge { max, actual } => {
                write!(formatter, "artifact has {actual} bytes; maximum is {max}")
            }
            Self::OutputTooLarge { max, actual } => {
                write!(
                    formatter,
                    "artifact set has {actual} bytes; maximum is {max}"
                )
            }
            Self::ManifestTooLarge { max, actual } => {
                write!(formatter, "manifest has {actual} bytes; maximum is {max}")
            }
            Self::LengthOverflow => formatter.write_str("artifact length overflow"),
        }
    }
}

impl std::error::Error for PackError {}

impl From<PathError> for PackError {
    fn from(value: PathError) -> Self {
        Self::Path(value)
    }
}

impl From<FormatError> for PackError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

impl From<CodecError> for PackError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<CompressionError> for PackError {
    fn from(value: CompressionError) -> Self {
        Self::Compression(value)
    }
}

fn reject_duplicates(artifacts: &[&ArtifactFile]) -> Result<(), PackError> {
    if artifacts
        .windows(2)
        .any(|pair| pair[0].relative_path == pair[1].relative_path)
    {
        Err(PackError::DuplicatePath)
    } else {
        Ok(())
    }
}

fn total_size(artifacts: &[&ArtifactFile], limits: &SecurityLimits) -> Result<u64, PackError> {
    let mut total = 0_u64;
    for artifact in artifacts {
        let size = u64::try_from(artifact.bytes.len()).map_err(|_| PackError::LengthOverflow)?;
        if size > limits.max_single_file_bytes {
            return Err(PackError::FileTooLarge {
                max: limits.max_single_file_bytes,
                actual: size,
            });
        }
        total = total.checked_add(size).ok_or(PackError::LengthOverflow)?;
        if total > limits.max_uncompressed_payload_bytes {
            return Err(PackError::OutputTooLarge {
                max: limits.max_uncompressed_payload_bytes,
                actual: total,
            });
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use rebyte_compression::decompress;
    use rebyte_format::{CompressionAlgorithm, ContentKind};

    use super::{ArtifactFile, PackError, PackOptions, pack};

    fn options() -> Result<PackOptions, PackError> {
        let mut options = PackOptions::new("tests")?;
        options.compression = CompressionAlgorithm::None;
        Ok(options)
    }

    #[test]
    fn output_is_deterministic_and_path_sorted() -> Result<(), PackError> {
        let a = ArtifactFile::new("a.txt", b"a".to_vec())?;
        let b = ArtifactFile::new("b.bin", vec![0xff])?;
        let first = pack(&[b.clone(), a.clone()], &options()?)?;
        let second = pack(&[a, b], &options()?)?;
        assert_eq!(first, second);
        assert_eq!(first.manifest.files[0].path.as_str(), "a.txt");
        assert_eq!(first.manifest.files[1].content_kind, ContentKind::Binary);
        Ok(())
    }

    #[test]
    fn payload_reconstructs_exact_input_bytes() -> Result<(), PackError> {
        let artifacts = [
            ArtifactFile::new("a", b"first\n".to_vec())?,
            ArtifactFile::new("b", vec![0, 1, 2])?,
        ];
        let options = options()?;
        let unsigned = pack(&artifacts, &options)?;
        let payload = decompress(
            &unsigned.compressed_payload,
            unsigned.compression,
            unsigned.uncompressed_payload_size,
            &options.limits,
        )?;
        assert_eq!(payload, b"first\n\0\x01\x02");
        Ok(())
    }

    #[test]
    fn duplicate_path_is_rejected() -> Result<(), PackError> {
        let artifacts = [
            ArtifactFile::new("same", Vec::new())?,
            ArtifactFile::new("same", Vec::new())?,
        ];
        assert_eq!(pack(&artifacts, &options()?), Err(PackError::DuplicatePath));
        Ok(())
    }

    #[test]
    fn file_limit_is_enforced_before_allocation() -> Result<(), PackError> {
        let artifacts = [ArtifactFile::new("large", vec![1, 2])?];
        let mut options = options()?;
        options.limits.max_single_file_bytes = 1;
        assert_eq!(
            pack(&artifacts, &options),
            Err(PackError::FileTooLarge { max: 1, actual: 2 })
        );
        Ok(())
    }
}
