//! Public model for canonical unsigned artifacts.

use rebyte_compression::CompressionProfile;
use rebyte_format::{
    CompressionAlgorithm, Digest32, PathError, RelativeArtifactPath, SecurityLimits,
};

use crate::ArtifactTokenError;

/// Closed artifact shape represented by an `ra1_` envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// Exactly one file whose suggested basename is optional.
    File,
    /// A portable tree of regular files and directories.
    Directory,
}

impl ArtifactKind {
    pub(crate) const fn wire(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Directory => 1,
        }
    }

    pub(crate) const fn from_wire(value: u8) -> Result<Self, ArtifactTokenError> {
        match value {
            0 => Ok(Self::File),
            1 => Ok(Self::Directory),
            _ => Err(ArtifactTokenError::UnsupportedKind(value)),
        }
    }
}

/// Entry shape inside a directory artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactEntryKind {
    /// A regular file with byte-exact content.
    File,
    /// A directory, including an otherwise empty directory.
    Directory,
}

impl ArtifactEntryKind {
    pub(crate) const fn wire(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Directory => 1,
        }
    }

    pub(crate) const fn from_wire(value: u8) -> Result<Self, ArtifactTokenError> {
        match value {
            0 => Ok(Self::File),
            1 => Ok(Self::Directory),
            _ => Err(ArtifactTokenError::InvalidDirectoryEntry),
        }
    }
}

/// One regular file or explicit directory in an unsigned artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactEntry {
    pub(crate) kind: ArtifactEntryKind,
    pub(crate) path: Option<RelativeArtifactPath>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) executable: bool,
}

impl ArtifactEntry {
    /// Creates the pathless content entry required by a file artifact.
    #[must_use]
    pub const fn unnamed_file(bytes: Vec<u8>, executable: bool) -> Self {
        Self {
            kind: ArtifactEntryKind::File,
            path: None,
            bytes,
            executable,
        }
    }

    /// Creates a named regular-file entry for a directory artifact.
    #[must_use]
    pub const fn file(path: RelativeArtifactPath, bytes: Vec<u8>, executable: bool) -> Self {
        Self {
            kind: ArtifactEntryKind::File,
            path: Some(path),
            bytes,
            executable,
        }
    }

    /// Creates an explicit directory entry.
    #[must_use]
    pub const fn directory(path: RelativeArtifactPath) -> Self {
        Self {
            kind: ArtifactEntryKind::Directory,
            path: Some(path),
            bytes: Vec::new(),
            executable: false,
        }
    }

    /// Returns whether this entry is a file or directory.
    #[must_use]
    pub const fn kind(&self) -> ArtifactEntryKind {
        self.kind
    }

    /// Returns the portable path, or `None` for a single-file artifact.
    #[must_use]
    pub const fn path(&self) -> Option<&RelativeArtifactPath> {
        self.path.as_ref()
    }

    /// Returns exact file bytes; directories return an empty slice.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the portable executable bit.
    #[must_use]
    pub const fn executable(&self) -> bool {
        self.executable
    }
}

/// Complete in-memory artifact before or after canonical encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    pub(crate) kind: ArtifactKind,
    pub(crate) suggested_name: Option<String>,
    pub(crate) suggested_path: Option<RelativeArtifactPath>,
    pub(crate) entries: Vec<ArtifactEntry>,
}

impl Artifact {
    /// Creates a single-file artifact without destination metadata.
    #[must_use]
    pub fn file(bytes: Vec<u8>, executable: bool) -> Self {
        Self {
            kind: ArtifactKind::File,
            suggested_name: None,
            suggested_path: None,
            entries: vec![ArtifactEntry::unnamed_file(bytes, executable)],
        }
    }

    /// Creates a directory artifact. Entries are canonicalized while encoding.
    #[must_use]
    pub const fn directory(entries: Vec<ArtifactEntry>) -> Self {
        Self {
            kind: ArtifactKind::Directory,
            suggested_name: None,
            suggested_path: None,
            entries,
        }
    }

    /// Adds a portable suggested basename.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactTokenError::InvalidName`] for a path, traversal,
    /// reserved device name or other non-portable component.
    pub fn with_suggested_name(mut self, value: &str) -> Result<Self, ArtifactTokenError> {
        self.suggested_name = Some(validate_name(value)?);
        Ok(self)
    }

    /// Adds a portable relative destination suggestion.
    #[must_use]
    pub fn with_suggested_path(mut self, value: RelativeArtifactPath) -> Self {
        self.suggested_path = Some(value);
        self
    }

    /// Returns the artifact shape.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Returns the optional, untrusted suggested basename.
    #[must_use]
    pub fn suggested_name(&self) -> Option<&str> {
        self.suggested_name.as_deref()
    }

    /// Returns the optional, untrusted relative destination.
    #[must_use]
    pub const fn suggested_path(&self) -> Option<&RelativeArtifactPath> {
        self.suggested_path.as_ref()
    }

    /// Returns canonical entries after decoding, or caller order before encoding.
    #[must_use]
    pub fn entries(&self) -> &[ArtifactEntry] {
        &self.entries
    }
}

/// Encoder choice for an unsigned artifact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArtifactCompression {
    /// Keep Zstandard only when the complete stored payload is smaller.
    #[default]
    Auto,
    /// Always emit one Zstandard frame.
    Zstd,
    /// Store the aggregate payload verbatim.
    None,
}

/// Encoding and verification policy for one unsigned artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ArtifactOptions {
    /// Compression selection policy.
    pub compression: ArtifactCompression,
    /// Native encoder effort.
    pub profile: CompressionProfile,
    /// Resource limits applied during encoding and self-verification.
    pub limits: SecurityLimits,
}

impl ArtifactOptions {
    /// Selects automatic, forced Zstandard or verbatim storage.
    #[must_use]
    pub const fn with_compression(mut self, value: ArtifactCompression) -> Self {
        self.compression = value;
        self
    }

    /// Selects the Zstandard resource profile.
    #[must_use]
    pub const fn with_profile(mut self, value: CompressionProfile) -> Self {
        self.profile = value;
        self
    }

    /// Replaces all defensive limits.
    #[must_use]
    pub const fn with_limits(mut self, value: SecurityLimits) -> Self {
        self.limits = value;
        self
    }
}

impl Default for ArtifactOptions {
    fn default() -> Self {
        Self {
            compression: ArtifactCompression::Auto,
            profile: CompressionProfile::Balanced,
            limits: SecurityLimits::SIMPLE_ARTIFACT,
        }
    }
}

/// Canonical binary envelope and verified encoding metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedArtifact {
    pub(crate) binary: Vec<u8>,
    pub(crate) kind: ArtifactKind,
    pub(crate) compression: CompressionAlgorithm,
    pub(crate) profile: CompressionProfile,
    pub(crate) content_digest: Digest32,
    pub(crate) envelope_digest: Digest32,
    pub(crate) original_size: u64,
    pub(crate) stored_size: u64,
    pub(crate) entry_count: u32,
}

impl EncodedArtifact {
    /// Returns canonical `.rba` bytes.
    #[must_use]
    pub fn binary(&self) -> &[u8] {
        &self.binary
    }

    /// Consumes this report and returns canonical `.rba` bytes.
    #[must_use]
    pub fn into_binary(self) -> Vec<u8> {
        self.binary
    }

    /// Returns whether this contains one file or a directory.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Returns the selected storage algorithm.
    #[must_use]
    pub const fn compression(&self) -> CompressionAlgorithm {
        self.compression
    }

    /// Returns the encoder effort recorded by the envelope.
    #[must_use]
    pub const fn profile(&self) -> CompressionProfile {
        self.profile
    }

    /// Returns the identity derived from canonical content, excluding suggestions.
    #[must_use]
    pub const fn content_digest(&self) -> Digest32 {
        self.content_digest
    }

    /// Returns the digest of the complete metadata and stored representation.
    #[must_use]
    pub const fn envelope_digest(&self) -> Digest32 {
        self.envelope_digest
    }

    /// Returns aggregate reconstructed file bytes.
    #[must_use]
    pub const fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Returns compressed or verbatim payload bytes.
    #[must_use]
    pub const fn stored_size(&self) -> u64 {
        self.stored_size
    }

    /// Returns the number of explicit file and directory entries.
    #[must_use]
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }
}

/// Fully parsed, decompressed and digest-verified unsigned artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedArtifact {
    pub(crate) artifact: Artifact,
    pub(crate) compression: CompressionAlgorithm,
    pub(crate) profile: CompressionProfile,
    pub(crate) content_digest: Digest32,
    pub(crate) envelope_digest: Digest32,
    pub(crate) original_size: u64,
    pub(crate) stored_size: u64,
}

impl DecodedArtifact {
    /// Returns the reconstructed artifact.
    #[must_use]
    pub const fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    /// Consumes the report and returns the reconstructed artifact.
    #[must_use]
    pub fn into_artifact(self) -> Artifact {
        self.artifact
    }

    /// Returns the verified compression algorithm.
    #[must_use]
    pub const fn compression(&self) -> CompressionAlgorithm {
        self.compression
    }

    /// Returns the recorded encoder profile.
    #[must_use]
    pub const fn profile(&self) -> CompressionProfile {
        self.profile
    }

    /// Returns the verified content identity.
    #[must_use]
    pub const fn content_digest(&self) -> Digest32 {
        self.content_digest
    }

    /// Returns the verified envelope digest.
    #[must_use]
    pub const fn envelope_digest(&self) -> Digest32 {
        self.envelope_digest
    }

    /// Returns aggregate reconstructed file bytes.
    #[must_use]
    pub const fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Returns compressed or verbatim payload bytes.
    #[must_use]
    pub const fn stored_size(&self) -> u64 {
        self.stored_size
    }
}

fn validate_name(value: &str) -> Result<String, ArtifactTokenError> {
    let path = RelativeArtifactPath::new(value).map_err(ArtifactTokenError::InvalidName)?;
    if value.contains('/') {
        return Err(ArtifactTokenError::InvalidName(PathError::EmptyComponent));
    }
    Ok(path.into_string())
}
