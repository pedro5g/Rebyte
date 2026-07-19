// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Filesystem-backed streaming artifact encoding and reconstruction.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

use rebyte_compression::{
    CompressionMethod, CompressionProfile, compress_stream_with_dictionary,
    decompress_stream_with_dictionary, train_dictionary,
};
use rebyte_format::{
    CompressionAlgorithm, Digest32, PathError, RelativeArtifactPath, SecurityLimits,
};
use rebyte_integrity::{DomainHasher, digest_matches};

use super::{
    ARTIFACT_HEADER_SIZE, Artifact, ArtifactCompression, ArtifactDictionary, ArtifactEntryKind,
    ArtifactKind, ArtifactOptions, ArtifactTokenError, CanonicalEntry, Header,
    MAX_DICTIONARY_SAMPLE_SIZE, MAX_DICTIONARY_SIZE, MAX_DICTIONARY_TRAINING_BYTES,
    MIN_DICTIONARY_SAMPLES, content_digest, decode_header, decode_manifest, encode_header,
    encode_manifest, enforce_binary_size, enforce_entry_count, enforce_file_size,
    enforce_header_limits, enforce_payload_size, envelope_hasher, metadata_flags,
    validate_metadata, validate_tree,
};

const BUFFER_SIZE: usize = 64 * 1_024;

/// Failure during filesystem-backed artifact streaming.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactIoError {
    /// Canonical format, limit, compression or integrity validation failed.
    Format(ArtifactTokenError),
    /// A filesystem operation failed.
    Io(io::Error),
    /// Source bytes changed between hashing and compression.
    SourceChanged,
    /// A source path was a symbolic link.
    SymbolicLink,
    /// A source entry was neither a regular file nor a directory.
    UnsupportedFileType,
    /// A source path was not portable UTF-8.
    NonPortablePath,
    /// The selected output already exists.
    OutputExists,
}

impl fmt::Display for ArtifactIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "artifact filesystem operation failed: {error}"),
            Self::SourceChanged => {
                formatter.write_str("artifact source changed while it was being encoded")
            }
            Self::SymbolicLink => formatter.write_str("symbolic links are forbidden in artifacts"),
            Self::UnsupportedFileType => {
                formatter.write_str("artifact source contains an unsupported filesystem entry")
            }
            Self::NonPortablePath => {
                formatter.write_str("artifact source contains a non-portable path")
            }
            Self::OutputExists => formatter.write_str("artifact output already exists"),
        }
    }
}

impl std::error::Error for ArtifactIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ArtifactTokenError> for ArtifactIoError {
    fn from(value: ArtifactTokenError) -> Self {
        Self::Format(value)
    }
}

impl From<io::Error> for ArtifactIoError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Optional untrusted metadata embedded by a filesystem encoder.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArtifactPathMetadata {
    suggested_name: Option<String>,
    suggested_path: Option<RelativeArtifactPath>,
}

impl ArtifactPathMetadata {
    /// Creates metadata without name or destination hints.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            suggested_name: None,
            suggested_path: None,
        }
    }

    /// Adds one portable basename.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactTokenError::InvalidName`] for a path or non-portable
    /// component.
    pub fn with_suggested_name(mut self, value: &str) -> Result<Self, ArtifactTokenError> {
        if value.contains('/') || value.contains('\\') {
            return Err(ArtifactTokenError::InvalidName(PathError::EmptyComponent));
        }
        let validated =
            RelativeArtifactPath::new(value).map_err(ArtifactTokenError::InvalidName)?;
        self.suggested_name = Some(validated.into_string());
        Ok(self)
    }

    /// Adds one validated relative destination.
    #[must_use]
    pub fn with_suggested_path(mut self, value: RelativeArtifactPath) -> Self {
        self.suggested_path = Some(value);
        self
    }

    /// Returns the optional suggested basename.
    #[must_use]
    pub fn suggested_name(&self) -> Option<&str> {
        self.suggested_name.as_deref()
    }

    /// Returns the optional suggested destination.
    #[must_use]
    pub const fn suggested_path(&self) -> Option<&RelativeArtifactPath> {
        self.suggested_path.as_ref()
    }
}

/// Verified metadata from a streaming artifact operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamArtifactReport {
    kind: ArtifactKind,
    compression: CompressionAlgorithm,
    profile: CompressionProfile,
    content_digest: Digest32,
    envelope_digest: Digest32,
    original_size: u64,
    stored_size: u64,
    dictionary_size: u32,
    entry_count: u32,
    suggested_name: Option<String>,
    suggested_path: Option<RelativeArtifactPath>,
}

impl StreamArtifactReport {
    /// Returns whether the artifact is one file or a directory.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Returns the verified storage algorithm.
    #[must_use]
    pub const fn compression(&self) -> CompressionAlgorithm {
        self.compression
    }

    /// Returns the recorded encoder effort.
    #[must_use]
    pub const fn profile(&self) -> CompressionProfile {
        self.profile
    }

    /// Returns the destination-independent content identity.
    #[must_use]
    pub const fn content_digest(&self) -> Digest32 {
        self.content_digest
    }

    /// Returns the digest covering the complete stored envelope.
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

    /// Returns verified embedded adaptive-dictionary bytes, or zero.
    #[must_use]
    pub const fn dictionary_size(&self) -> u32 {
        self.dictionary_size
    }

    /// Returns explicit file and directory entries.
    #[must_use]
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
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
}

struct ScannedEntry {
    canonical: CanonicalEntry,
    source: Option<PathBuf>,
}

struct ScannedArtifact {
    kind: ArtifactKind,
    entries: Vec<ScannedEntry>,
    original_size: u64,
}

struct LoadedEnvelope {
    source: File,
    header: Header,
    manifest: Vec<u8>,
    decoded_manifest: super::DecodedManifest,
}

/// Encodes a regular file or directory directly into a new `.rba` file.
///
/// Source files are hashed first and verified again while streaming. The
/// complete output is self-verified in staging before a no-clobber commit.
///
/// # Errors
///
/// Returns [`ArtifactIoError`] for unsafe inputs, source mutation, resource
/// limits, compression/integrity failures or filesystem errors.
pub fn encode_artifact_path(
    source: &Path,
    output: &Path,
    metadata: &ArtifactPathMetadata,
    options: &ArtifactOptions,
) -> Result<StreamArtifactReport, ArtifactIoError> {
    ensure_absent(output)?;
    let scanned = scan_source(source, &options.limits)?;
    let artifact = metadata_artifact(scanned.kind, metadata);
    validate_metadata(&artifact, &options.limits)?;
    let canonical: Vec<_> = scanned
        .entries
        .iter()
        .map(|entry| entry.canonical.clone())
        .collect();
    let content = content_digest(scanned.kind, &canonical);

    create_parent(output)?;
    let parent = parent_or_current(output);
    let mut stored = tempfile::Builder::new()
        .prefix(".rebyte-stored-")
        .tempfile_in(parent)?;
    let (compression, dictionary, stored_size) =
        spool_payload(&scanned, stored.as_file_mut(), options)?;
    stored.as_file_mut().seek(io::SeekFrom::Start(0))?;
    let manifest = encode_manifest(&artifact, &dictionary, &canonical, &options.limits)?;

    let entry_count = usize_to_u32(canonical.len())?;
    let mut header = Header {
        kind: scanned.kind,
        compression,
        profile: options.profile,
        flags: metadata_flags(&artifact, &dictionary),
        entry_count,
        manifest_size: usize_to_u64(manifest.len())?,
        original_size: scanned.original_size,
        stored_size,
        content_digest: content,
        envelope_digest: Digest32([0; 32]),
    };
    header.envelope_digest = hash_stored(&header, &manifest, stored.as_file_mut())?;
    stored.as_file_mut().seek(io::SeekFrom::Start(0))?;
    let binary_size = u64::try_from(ARTIFACT_HEADER_SIZE)
        .map_err(|_| ArtifactTokenError::LengthOverflow)?
        .checked_add(header.manifest_size)
        .and_then(|value| value.checked_add(stored_size))
        .ok_or(ArtifactTokenError::LengthOverflow)?;
    enforce_binary_size(binary_size, &options.limits)?;

    let mut staged = tempfile::Builder::new()
        .prefix(".rebyte-envelope-")
        .tempfile_in(parent)?;
    staged.write_all(&encode_header(&header))?;
    staged.write_all(&manifest)?;
    copy_exact(stored.as_file_mut(), &mut staged, stored_size)?;
    staged.as_file().sync_all()?;

    let verified = decode_artifact_file(staged.path(), None, &options.limits)?;
    if verified.content_digest != header.content_digest
        || verified.envelope_digest != header.envelope_digest
    {
        return Err(ArtifactTokenError::ContentDigestMismatch.into());
    }
    staged
        .persist_noclobber(output)
        .map_err(|error| ArtifactIoError::Io(error.error))?;
    sync_parent(output)?;
    Ok(verified)
}

/// Fully verifies a binary `.rba` and optionally reconstructs it transactionally.
///
/// Passing `None` performs a read-only streaming verification. A supplied
/// output must not exist; reconstructed bytes remain staged until every digest
/// and exact length has passed.
///
/// # Errors
///
/// Returns [`ArtifactIoError`] for malformed input, mutation, unsafe output,
/// resource-limit violations or filesystem failures.
pub fn decode_artifact_file(
    input: &Path,
    output: Option<&Path>,
    limits: &SecurityLimits,
) -> Result<StreamArtifactReport, ArtifactIoError> {
    decode_artifact_file_inner(input, output, limits, None)
}

/// Reconstructs the exact envelope identity observed by an earlier preview.
///
/// This closes the preview-to-apply race when untrusted destination metadata
/// must be inspected before selecting an output.
///
/// # Errors
///
/// Returns [`ArtifactIoError::SourceChanged`] if the input no longer matches
/// `expected_envelope_digest`, plus errors documented by
/// [`decode_artifact_file`].
pub fn decode_artifact_file_expected(
    input: &Path,
    output: &Path,
    limits: &SecurityLimits,
    expected_envelope_digest: &Digest32,
) -> Result<StreamArtifactReport, ArtifactIoError> {
    decode_artifact_file_inner(input, Some(output), limits, Some(expected_envelope_digest))
}

fn decode_artifact_file_inner(
    input: &Path,
    output: Option<&Path>,
    limits: &SecurityLimits,
    expected_envelope_digest: Option<&Digest32>,
) -> Result<StreamArtifactReport, ArtifactIoError> {
    let LoadedEnvelope {
        mut source,
        header,
        manifest,
        decoded_manifest,
    } = load_envelope(input, limits)?;
    if expected_envelope_digest
        .is_some_and(|expected| !digest_matches(expected, &header.envelope_digest))
    {
        return Err(ArtifactIoError::SourceChanged);
    }
    let actual_content = content_digest(header.kind, &decoded_manifest.entries);
    if !digest_matches(&header.content_digest, &actual_content) {
        return Err(ArtifactTokenError::ContentDigestMismatch.into());
    }
    if let Some(target) = output {
        ensure_absent(target)?;
        create_parent(target)?;
    }
    let mut raw = output.map_or_else(
        || tempfile::Builder::new().prefix(".rebyte-raw-").tempfile(),
        |target| {
            tempfile::Builder::new()
                .prefix(".rebyte-raw-")
                .tempfile_in(parent_or_current(target))
        },
    )?;
    let hasher = envelope_hasher(&header, &manifest);
    let mut digesting = DigestReader::new(&mut source, hasher);
    let method = if decoded_manifest.dictionary.is_empty() {
        CompressionMethod::new(header.compression)
    } else {
        CompressionMethod::zstd_with_dictionary(&decoded_manifest.dictionary)
    };
    decompress_stream_with_dictionary(
        &mut digesting,
        raw.as_file_mut(),
        method,
        header.stored_size,
        header.original_size,
        limits,
    )
    .map_err(ArtifactTokenError::Compression)?;
    let actual_envelope = digesting.finalize();
    if !digest_matches(&header.envelope_digest, &actual_envelope) {
        return Err(ArtifactTokenError::EnvelopeDigestMismatch.into());
    }
    let mut trailing = [0_u8; 1];
    if source.read(&mut trailing)? != 0 {
        return Err(ArtifactTokenError::EnvelopeLengthMismatch.into());
    }
    raw.as_file().sync_all()?;
    verify_raw_payload(
        raw.as_file_mut(),
        &decoded_manifest.entries,
        header.original_size,
    )?;

    let report = StreamArtifactReport {
        kind: header.kind,
        compression: header.compression,
        profile: header.profile,
        content_digest: actual_content,
        envelope_digest: actual_envelope,
        original_size: header.original_size,
        stored_size: header.stored_size,
        dictionary_size: usize_to_u32(decoded_manifest.dictionary.len())?,
        entry_count: header.entry_count,
        suggested_name: decoded_manifest.suggested_name,
        suggested_path: decoded_manifest.suggested_path,
    };
    if let Some(target) = output {
        commit_raw(raw, target, header.kind, &decoded_manifest.entries)?;
    }
    Ok(report)
}

fn scan_source(source: &Path, limits: &SecurityLimits) -> Result<ScannedArtifact, ArtifactIoError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(ArtifactIoError::SymbolicLink);
    }
    if metadata.is_file() {
        let (size, digest) = hash_source_file(source, limits)?;
        return Ok(ScannedArtifact {
            kind: ArtifactKind::File,
            entries: vec![ScannedEntry {
                canonical: CanonicalEntry {
                    kind: ArtifactEntryKind::File,
                    path: None,
                    offset: 0,
                    size,
                    digest,
                    executable: is_executable(&metadata),
                },
                source: Some(source.to_path_buf()),
            }],
            original_size: size,
        });
    }
    if !metadata.is_dir() {
        return Err(ArtifactIoError::UnsupportedFileType);
    }
    let mut entries = Vec::new();
    scan_directory(source, source, &mut entries, limits)?;
    entries.sort_by(|left, right| {
        left.canonical
            .path
            .as_ref()
            .map(RelativeArtifactPath::as_str)
            .cmp(
                &right
                    .canonical
                    .path
                    .as_ref()
                    .map(RelativeArtifactPath::as_str),
            )
    });
    let mut offset = 0_u64;
    for entry in &mut entries {
        if entry.canonical.kind == ArtifactEntryKind::File {
            entry.canonical.offset = offset;
            offset = offset
                .checked_add(entry.canonical.size)
                .ok_or(ArtifactTokenError::LengthOverflow)?;
            enforce_payload_size(offset, limits)?;
        }
    }
    let canonical: Vec<_> = entries
        .iter()
        .map(|entry| entry.canonical.clone())
        .collect();
    validate_tree(&canonical)?;
    enforce_entry_count(usize_to_u32(entries.len())?, limits)?;
    Ok(ScannedArtifact {
        kind: ArtifactKind::Directory,
        entries,
        original_size: offset,
    })
}

fn scan_directory(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<ScannedEntry>,
    limits: &SecurityLimits,
) -> Result<(), ArtifactIoError> {
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(fs::DirEntry::file_name);
    for child in children {
        let source = child.path();
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.file_type().is_symlink() {
            return Err(ArtifactIoError::SymbolicLink);
        }
        let path = portable_relative(root, &source, limits)?;
        if metadata.is_dir() {
            entries.push(ScannedEntry {
                canonical: CanonicalEntry {
                    kind: ArtifactEntryKind::Directory,
                    path: Some(path),
                    offset: 0,
                    size: 0,
                    digest: Digest32([0; 32]),
                    executable: false,
                },
                source: None,
            });
            enforce_entry_count(usize_to_u32(entries.len())?, limits)?;
            scan_directory(root, &source, entries, limits)?;
        } else if metadata.is_file() {
            let (size, digest) = hash_source_file(&source, limits)?;
            entries.push(ScannedEntry {
                canonical: CanonicalEntry {
                    kind: ArtifactEntryKind::File,
                    path: Some(path),
                    offset: 0,
                    size,
                    digest,
                    executable: is_executable(&metadata),
                },
                source: Some(source),
            });
            enforce_entry_count(usize_to_u32(entries.len())?, limits)?;
        } else {
            return Err(ArtifactIoError::UnsupportedFileType);
        }
    }
    Ok(())
}

fn hash_source_file(
    path: &Path,
    limits: &SecurityLimits,
) -> Result<(u64, Digest32), ArtifactIoError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() {
        return Err(ArtifactIoError::SymbolicLink);
    }
    enforce_file_size(before.len(), limits)?;
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err(ArtifactIoError::SourceChanged);
    }
    let mut hasher = DomainHasher::file();
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(usize_to_u64(read)?)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        enforce_file_size(size, limits)?;
        hasher.update(
            buffer
                .get(..read)
                .ok_or(ArtifactTokenError::LengthOverflow)?,
        );
    }
    if size != before.len() || file.metadata()?.len() != before.len() {
        return Err(ArtifactIoError::SourceChanged);
    }
    Ok((size, hasher.finalize()))
}

fn spool_payload(
    scanned: &ScannedArtifact,
    output: &mut File,
    options: &ArtifactOptions,
) -> Result<(CompressionAlgorithm, Vec<u8>, u64), ArtifactIoError> {
    match options.compression {
        ArtifactCompression::None => spool_with_method(
            scanned,
            output,
            CompressionMethod::new(CompressionAlgorithm::None),
            options.profile,
            &options.limits,
        )
        .map(|size| (CompressionAlgorithm::None, Vec::new(), size)),
        ArtifactCompression::Zstd => {
            let ordinary = spool_with_method(
                scanned,
                output,
                CompressionMethod::new(CompressionAlgorithm::Zstd),
                options.profile,
                &options.limits,
            )?;
            let (dictionary, size) = best_stream_dictionary(scanned, output, ordinary, options)?;
            Ok((CompressionAlgorithm::Zstd, dictionary, size))
        }
        ArtifactCompression::Auto => {
            let ordinary = spool_with_method(
                scanned,
                output,
                CompressionMethod::new(CompressionAlgorithm::Zstd),
                options.profile,
                &options.limits,
            )?;
            let (dictionary, compressed) =
                best_stream_dictionary(scanned, output, ordinary, options)?;
            let dictionary_cost = usize_to_u64(dictionary.len())?
                .saturating_add(u64::from(!dictionary.is_empty()) * 4);
            if compressed.saturating_add(dictionary_cost) < scanned.original_size {
                Ok((CompressionAlgorithm::Zstd, dictionary, compressed))
            } else {
                let size = spool_with_method(
                    scanned,
                    output,
                    CompressionMethod::new(CompressionAlgorithm::None),
                    options.profile,
                    &options.limits,
                )?;
                Ok((CompressionAlgorithm::None, Vec::new(), size))
            }
        }
    }
}

fn best_stream_dictionary(
    scanned: &ScannedArtifact,
    output: &mut File,
    ordinary_size: u64,
    options: &ArtifactOptions,
) -> Result<(Vec<u8>, u64), ArtifactIoError> {
    let Some(dictionary) = train_stream_dictionary(scanned, options)? else {
        return Ok((Vec::new(), ordinary_size));
    };
    let mut candidate = tempfile::tempfile()?;
    let candidate_size = spool_with_method(
        scanned,
        &mut candidate,
        CompressionMethod::zstd_with_dictionary(&dictionary),
        options.profile,
        &options.limits,
    )?;
    let dictionary_cost = usize_to_u64(dictionary.len())?.saturating_add(4);
    if candidate_size.saturating_add(dictionary_cost) >= ordinary_size {
        return Ok((Vec::new(), ordinary_size));
    }
    output.set_len(0)?;
    output.seek(io::SeekFrom::Start(0))?;
    candidate.seek(io::SeekFrom::Start(0))?;
    copy_exact(&mut candidate, output, candidate_size)?;
    output.flush()?;
    output.sync_all()?;
    Ok((dictionary, candidate_size))
}

fn train_stream_dictionary(
    scanned: &ScannedArtifact,
    options: &ArtifactOptions,
) -> Result<Option<Vec<u8>>, ArtifactIoError> {
    if options.dictionary == ArtifactDictionary::None {
        return Ok(None);
    }
    let mut training_samples = Vec::new();
    let mut sampled_bytes = 0_usize;
    for entry in &scanned.entries {
        let Some(path) = &entry.source else {
            continue;
        };
        if sampled_bytes >= MAX_DICTIONARY_TRAINING_BYTES {
            break;
        }
        let available = MAX_DICTIONARY_TRAINING_BYTES.saturating_sub(sampled_bytes);
        let declared = usize::try_from(entry.canonical.size)
            .map_err(|_| ArtifactTokenError::LengthOverflow)?;
        let length = declared.min(MAX_DICTIONARY_SAMPLE_SIZE).min(available);
        if length < 8 {
            continue;
        }
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(ArtifactIoError::SymbolicLink);
        }
        if !metadata.is_file() || metadata.len() != entry.canonical.size {
            return Err(ArtifactIoError::SourceChanged);
        }
        let mut source = File::open(path)?;
        let mut sample = Vec::with_capacity(length);
        std::io::Read::take(&mut source, usize_to_u64(length)?).read_to_end(&mut sample)?;
        if sample.len() != length || source.metadata()?.len() != entry.canonical.size {
            return Err(ArtifactIoError::SourceChanged);
        }
        sampled_bytes = sampled_bytes
            .checked_add(length)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        training_samples.push(sample);
    }
    if training_samples.len() < MIN_DICTIONARY_SAMPLES {
        return Ok(None);
    }
    let maximum = (sampled_bytes / 20).clamp(256, MAX_DICTIONARY_SIZE);
    Ok(train_dictionary(&training_samples, maximum).ok())
}

fn spool_with_method(
    scanned: &ScannedArtifact,
    output: &mut File,
    method: CompressionMethod<'_>,
    profile: CompressionProfile,
    limits: &SecurityLimits,
) -> Result<u64, ArtifactIoError> {
    output.set_len(0)?;
    output.seek(io::SeekFrom::Start(0))?;
    let mut reader = ArtifactReader::new(&scanned.entries);
    let result = compress_stream_with_dictionary(
        &mut reader,
        output,
        method,
        profile,
        scanned.original_size,
        limits,
    );
    if let Some(failure) = reader.failure {
        return Err(failure.into_error());
    }
    let stats = result.map_err(ArtifactTokenError::Compression)?;
    output.flush()?;
    output.sync_all()?;
    Ok(stats.output_bytes)
}

fn load_envelope(input: &Path, limits: &SecurityLimits) -> Result<LoadedEnvelope, ArtifactIoError> {
    let metadata = fs::symlink_metadata(input)?;
    if metadata.file_type().is_symlink() {
        return Err(ArtifactIoError::SymbolicLink);
    }
    if !metadata.is_file() {
        return Err(ArtifactIoError::UnsupportedFileType);
    }
    enforce_binary_size(metadata.len(), limits)?;
    let mut file = File::open(input)?;
    let mut header_bytes = [0_u8; ARTIFACT_HEADER_SIZE];
    file.read_exact(&mut header_bytes)
        .map_err(|_| ArtifactTokenError::UnexpectedEof)?;
    let header = decode_header(&header_bytes)?;
    enforce_header_limits(&header, limits)?;
    let expected = u64::try_from(ARTIFACT_HEADER_SIZE)
        .map_err(|_| ArtifactTokenError::LengthOverflow)?
        .checked_add(header.manifest_size)
        .and_then(|value| value.checked_add(header.stored_size))
        .ok_or(ArtifactTokenError::LengthOverflow)?;
    if metadata.len() != expected {
        return Err(ArtifactTokenError::EnvelopeLengthMismatch.into());
    }
    let manifest_size =
        usize::try_from(header.manifest_size).map_err(|_| ArtifactTokenError::LengthOverflow)?;
    let mut manifest = vec![0_u8; manifest_size];
    file.read_exact(&mut manifest)
        .map_err(|_| ArtifactTokenError::UnexpectedEof)?;
    let decoded = decode_manifest(&manifest, &header, limits)?;
    Ok(LoadedEnvelope {
        source: file,
        header,
        manifest,
        decoded_manifest: decoded,
    })
}

fn verify_raw_payload(
    raw: &mut File,
    entries: &[CanonicalEntry],
    expected_size: u64,
) -> Result<(), ArtifactIoError> {
    raw.seek(io::SeekFrom::Start(0))?;
    let mut total = 0_u64;
    for entry in entries {
        if entry.kind != ArtifactEntryKind::File {
            continue;
        }
        let digest = hash_exact(raw, entry.size)?;
        if !digest_matches(&entry.digest, &digest) {
            return Err(ArtifactTokenError::FileDigestMismatch.into());
        }
        total = total
            .checked_add(entry.size)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
    }
    if total != expected_size {
        return Err(ArtifactTokenError::InvalidPayloadRange.into());
    }
    let mut trailing = [0_u8; 1];
    if raw.read(&mut trailing)? != 0 {
        return Err(ArtifactTokenError::InvalidPayloadRange.into());
    }
    Ok(())
}

fn hash_exact(reader: &mut impl io::Read, size: u64) -> Result<Digest32, ArtifactIoError> {
    let mut hasher = DomainHasher::file();
    let mut remaining = size;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    while remaining != 0 {
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = reader.read(
            buffer
                .get_mut(..maximum)
                .ok_or(ArtifactTokenError::LengthOverflow)?,
        )?;
        if read == 0 {
            return Err(ArtifactTokenError::UnexpectedEof.into());
        }
        hasher.update(
            buffer
                .get(..read)
                .ok_or(ArtifactTokenError::LengthOverflow)?,
        );
        remaining = remaining
            .checked_sub(usize_to_u64(read)?)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
    }
    Ok(hasher.finalize())
}

fn commit_raw(
    mut raw: tempfile::NamedTempFile,
    target: &Path,
    kind: ArtifactKind,
    entries: &[CanonicalEntry],
) -> Result<(), ArtifactIoError> {
    match kind {
        ArtifactKind::File => {
            let executable = entries
                .first()
                .ok_or(ArtifactTokenError::InvalidFileShape)?
                .executable;
            set_file_permissions(raw.path(), executable)?;
            raw.as_file().sync_all()?;
            raw.persist_noclobber(target)
                .map_err(|error| ArtifactIoError::Io(error.error))?;
        }
        ArtifactKind::Directory => {
            let parent = parent_or_current(target);
            let staging = tempfile::Builder::new()
                .prefix(".rebyte-tree-")
                .tempdir_in(parent)?;
            raw.as_file_mut().seek(io::SeekFrom::Start(0))?;
            materialize_tree(raw.as_file_mut(), staging.path(), entries)?;
            let staging_path = staging.keep();
            if let Err(error) = fs::rename(&staging_path, target) {
                let _cleanup_result = fs::remove_dir_all(&staging_path);
                return Err(ArtifactIoError::Io(error));
            }
        }
    }
    sync_parent(target)?;
    Ok(())
}

fn materialize_tree(
    raw: &mut File,
    root: &Path,
    entries: &[CanonicalEntry],
) -> Result<(), ArtifactIoError> {
    for entry in entries {
        let path = entry
            .path
            .as_ref()
            .ok_or(ArtifactTokenError::InvalidDirectoryShape)?;
        let destination = root.join(portable_path(path.as_str()));
        match entry.kind {
            ArtifactEntryKind::Directory => {
                fs::create_dir_all(&destination)?;
                set_directory_permissions(&destination)?;
            }
            ArtifactEntryKind::File => {
                create_parent(&destination)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)?;
                copy_exact(raw, &mut file, entry.size)?;
                file.sync_all()?;
                set_file_permissions(&destination, entry.executable)?;
            }
        }
    }
    set_directory_permissions(root)?;
    Ok(())
}

fn hash_stored(
    header: &Header,
    manifest: &[u8],
    stored: &mut File,
) -> Result<Digest32, ArtifactIoError> {
    let mut hasher = envelope_hasher(header, manifest);
    let mut remaining = header.stored_size;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    while remaining != 0 {
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = stored.read(
            buffer
                .get_mut(..maximum)
                .ok_or(ArtifactTokenError::LengthOverflow)?,
        )?;
        if read == 0 {
            return Err(ArtifactTokenError::UnexpectedEof.into());
        }
        hasher.update(
            buffer
                .get(..read)
                .ok_or(ArtifactTokenError::LengthOverflow)?,
        );
        remaining = remaining
            .checked_sub(usize_to_u64(read)?)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
    }
    Ok(hasher.finalize())
}

fn copy_exact(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    size: u64,
) -> Result<(), ArtifactIoError> {
    let mut remaining = size;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    while remaining != 0 {
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = input.read(
            buffer
                .get_mut(..maximum)
                .ok_or(ArtifactTokenError::LengthOverflow)?,
        )?;
        if read == 0 {
            return Err(ArtifactTokenError::UnexpectedEof.into());
        }
        output.write_all(
            buffer
                .get(..read)
                .ok_or(ArtifactTokenError::LengthOverflow)?,
        )?;
        remaining = remaining
            .checked_sub(usize_to_u64(read)?)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
    }
    Ok(())
}

fn metadata_artifact(kind: ArtifactKind, metadata: &ArtifactPathMetadata) -> Artifact {
    Artifact {
        kind,
        suggested_name: metadata.suggested_name.clone(),
        suggested_path: metadata.suggested_path.clone(),
        entries: Vec::new(),
    }
}

fn portable_relative(
    root: &Path,
    path: &Path,
    limits: &SecurityLimits,
) -> Result<RelativeArtifactPath, ArtifactIoError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ArtifactIoError::NonPortablePath)?;
    let text = relative.to_str().ok_or(ArtifactIoError::NonPortablePath)?;
    let portable = text.replace(std::path::MAIN_SEPARATOR, "/");
    RelativeArtifactPath::with_max_bytes(&portable, limits.max_path_bytes)
        .map_err(ArtifactTokenError::Path)
        .map_err(Into::into)
}

fn portable_path(value: &str) -> PathBuf {
    value.split('/').collect()
}

fn ensure_absent(path: &Path) -> Result<(), ArtifactIoError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ArtifactIoError::OutputExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_parent(path: &Path) -> Result<(), ArtifactIoError> {
    fs::create_dir_all(parent_or_current(path)).map_err(Into::into)
}

fn parent_or_current(path: &Path) -> &Path {
    path.parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_file_permissions(path: &Path, executable: bool) -> Result<(), ArtifactIoError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path, _executable: bool) -> Result<(), ArtifactIoError> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), ArtifactIoError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(Into::into)
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), ArtifactIoError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), ArtifactIoError> {
    File::open(parent_or_current(path))?
        .sync_all()
        .map_err(Into::into)
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), ArtifactIoError> {
    Ok(())
}

fn usize_to_u32(value: usize) -> Result<u32, ArtifactIoError> {
    u32::try_from(value)
        .map_err(|_| ArtifactTokenError::LengthOverflow)
        .map_err(Into::into)
}

fn usize_to_u64(value: usize) -> Result<u64, ArtifactIoError> {
    u64::try_from(value)
        .map_err(|_| ArtifactTokenError::LengthOverflow)
        .map_err(Into::into)
}

#[derive(Clone, Copy)]
enum StreamFailure {
    Io,
    SourceChanged,
}

impl StreamFailure {
    fn into_error(self) -> ArtifactIoError {
        match self {
            Self::Io => ArtifactIoError::Io(io::Error::other("cannot read artifact source")),
            Self::SourceChanged => ArtifactIoError::SourceChanged,
        }
    }
}

struct CurrentFile {
    file: File,
    remaining: u64,
    expected_digest: Digest32,
    hasher: DomainHasher,
}

struct ArtifactReader<'a> {
    entries: &'a [ScannedEntry],
    next_index: usize,
    current: Option<CurrentFile>,
    failure: Option<StreamFailure>,
}

impl<'a> ArtifactReader<'a> {
    const fn new(entries: &'a [ScannedEntry]) -> Self {
        Self {
            entries,
            next_index: 0,
            current: None,
            failure: None,
        }
    }

    fn open_next(&mut self) -> io::Result<bool> {
        while let Some(entry) = self.entries.get(self.next_index) {
            self.next_index = self
                .next_index
                .checked_add(1)
                .ok_or_else(|| io::Error::other("artifact entry overflow"))?;
            let Some(path) = &entry.source else {
                continue;
            };
            let metadata = fs::symlink_metadata(path).map_err(|error| self.io_failure(error))?;
            if metadata.file_type().is_symlink() || metadata.len() != entry.canonical.size {
                return Err(self.changed_failure());
            }
            let file = File::open(path).map_err(|error| self.io_failure(error))?;
            let opened = file.metadata().map_err(|error| self.io_failure(error))?;
            if !opened.is_file() || opened.len() != entry.canonical.size {
                return Err(self.changed_failure());
            }
            self.current = Some(CurrentFile {
                file,
                remaining: entry.canonical.size,
                expected_digest: entry.canonical.digest,
                hasher: DomainHasher::file(),
            });
            return Ok(true);
        }
        Ok(false)
    }

    fn finish_current(&mut self) -> io::Result<()> {
        let Some(mut current) = self.current.take() else {
            return Ok(());
        };
        if current.remaining != 0 {
            return Err(self.changed_failure());
        }
        let mut extra = [0_u8; 1];
        if current
            .file
            .read(&mut extra)
            .map_err(|error| self.io_failure(error))?
            != 0
        {
            return Err(self.changed_failure());
        }
        if !digest_matches(&current.expected_digest, &current.hasher.finalize()) {
            return Err(self.changed_failure());
        }
        Ok(())
    }

    fn io_failure(&mut self, _error: io::Error) -> io::Error {
        self.failure = Some(StreamFailure::Io);
        io::Error::other("artifact source read failed")
    }

    fn changed_failure(&mut self) -> io::Error {
        self.failure = Some(StreamFailure::SourceChanged);
        io::Error::other("artifact source changed")
    }
}

impl io::Read for ArtifactReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.current.is_none() && !self.open_next()? {
                return Ok(0);
            }
            let remaining = self.current.as_ref().map_or(0, |item| item.remaining);
            if remaining == 0 {
                self.finish_current()?;
                continue;
            }
            let maximum = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(output.len());
            let read_result = self
                .current
                .as_mut()
                .ok_or_else(|| io::Error::other("artifact reader state"))?
                .file
                .read(
                    output
                        .get_mut(..maximum)
                        .ok_or_else(|| io::Error::other("artifact length overflow"))?,
                );
            let read = match read_result {
                Ok(value) => value,
                Err(error) => return Err(self.io_failure(error)),
            };
            if read == 0 {
                return Err(self.changed_failure());
            }
            let bytes = output
                .get(..read)
                .ok_or_else(|| io::Error::other("artifact length overflow"))?;
            let current = self
                .current
                .as_mut()
                .ok_or_else(|| io::Error::other("artifact reader state"))?;
            current.hasher.update(bytes);
            let read_u64 =
                u64::try_from(read).map_err(|_| io::Error::other("artifact length overflow"))?;
            current.remaining = current
                .remaining
                .checked_sub(read_u64)
                .ok_or_else(|| io::Error::other("artifact length overflow"))?;
            return Ok(read);
        }
    }
}

struct DigestReader<'a> {
    inner: &'a mut File,
    hasher: DomainHasher,
}

impl<'a> DigestReader<'a> {
    const fn new(inner: &'a mut File, hasher: DomainHasher) -> Self {
        Self { inner, hasher }
    }

    fn finalize(self) -> Digest32 {
        self.hasher.finalize()
    }
}

impl io::Read for DigestReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(output)?;
        if let Some(bytes) = output.get(..read) {
            self.hasher.update(bytes);
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{ArtifactPathMetadata, decode_artifact_file, encode_artifact_path};
    use crate::{ArtifactKind, ArtifactOptions, ArtifactTokenError};
    use rebyte_format::{RelativeArtifactPath, SecurityLimits};

    #[test]
    fn conflicting_outputs_and_symlinks_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = directory.path().join("plain.txt");
        fs::write(&source, b"streaming source\n")?;
        let taken = directory.path().join("taken.rba");
        fs::write(&taken, b"already here")?;
        let metadata = ArtifactPathMetadata::new();
        assert!(matches!(
            encode_artifact_path(&source, &taken, &metadata, &ArtifactOptions::default()),
            Err(super::ArtifactIoError::OutputExists)
        ));

        let encoded = directory.path().join("plain.rba");
        encode_artifact_path(&source, &encoded, &metadata, &ArtifactOptions::default())?;
        assert!(matches!(
            decode_artifact_file(&encoded, Some(&source), &SecurityLimits::SIMPLE_ARTIFACT),
            Err(super::ArtifactIoError::OutputExists)
        ));

        #[cfg(unix)]
        {
            let tree = directory.path().join("tree");
            fs::create_dir_all(&tree)?;
            fs::write(tree.join("real.txt"), b"real\n")?;
            std::os::unix::fs::symlink(tree.join("real.txt"), tree.join("link.txt"))?;
            let output = directory.path().join("tree.rba");
            assert!(matches!(
                encode_artifact_path(&tree, &output, &metadata, &ArtifactOptions::default()),
                Err(super::ArtifactIoError::SymbolicLink)
            ));
        }
        Ok(())
    }

    #[test]
    fn expected_envelope_digest_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = directory.path().join("pinned.txt");
        fs::write(&source, b"digest pinned bytes\n")?;
        let encoded = directory.path().join("pinned.rba");
        let report = encode_artifact_path(
            &source,
            &encoded,
            &ArtifactPathMetadata::new(),
            &ArtifactOptions::default(),
        )?;
        let restored = directory.path().join("pinned.out");
        let decoded = super::decode_artifact_file_expected(
            &encoded,
            &restored,
            &SecurityLimits::SIMPLE_ARTIFACT,
            &report.envelope_digest(),
        )?;
        assert_eq!(decoded.compression(), report.compression());
        assert_eq!(decoded.profile(), report.profile());
        assert_eq!(decoded.entry_count(), report.entry_count());

        let wrong = rebyte_format::Digest32([0x5A; 32]);
        let elsewhere = directory.path().join("pinned.other");
        assert!(
            super::decode_artifact_file_expected(
                &encoded,
                &elsewhere,
                &SecurityLimits::SIMPLE_ARTIFACT,
                &wrong,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn similar_small_files_can_train_a_dictionary() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = directory.path().join("configs");
        fs::create_dir_all(&source)?;
        for index in 0..24 {
            let body = format!(
                "[service]\nname = \"service-{index}\"\nport = 80{index:02}\nregion = \"sao-paulo\"\nretries = 3\ntimeout_ms = 2500\n"
            )
            .repeat(6);
            fs::write(source.join(format!("service-{index}.toml")), body)?;
        }
        let encoded = directory.path().join("configs.rba");
        let report = encode_artifact_path(
            &source,
            &encoded,
            &ArtifactPathMetadata::new(),
            &ArtifactOptions::default(),
        )?;
        let restored = directory.path().join("configs.out");
        decode_artifact_file(&encoded, Some(&restored), &SecurityLimits::SIMPLE_ARTIFACT)?;
        for index in 0..24 {
            assert_eq!(
                fs::read(source.join(format!("service-{index}.toml")))?,
                fs::read(restored.join(format!("service-{index}.toml")))?
            );
        }
        assert_eq!(report.kind(), ArtifactKind::Directory);
        Ok(())
    }

    #[test]
    fn every_streaming_error_renders_a_message() {
        use std::error::Error as _;

        let errors = [
            super::ArtifactIoError::Format(ArtifactTokenError::InvalidFileShape),
            super::ArtifactIoError::Io(std::io::Error::from(std::io::ErrorKind::NotFound)),
            super::ArtifactIoError::SourceChanged,
            super::ArtifactIoError::SymbolicLink,
            super::ArtifactIoError::UnsupportedFileType,
            super::ArtifactIoError::NonPortablePath,
            super::ArtifactIoError::OutputExists,
        ];
        let mut messages = Vec::new();
        for error in &errors {
            let message = error.to_string();
            assert!(!message.is_empty());
            messages.push(message);
        }
        messages.sort();
        messages.dedup();
        assert_eq!(messages.len(), 7);
        assert!(errors[0].source().is_some());
        assert!(errors[1].source().is_some());
        assert!(errors[2].source().is_none());
    }

    #[test]
    fn large_file_streams_to_binary_and_back() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = directory.path().join("large.txt");
        let encoded = directory.path().join("large.rba");
        let restored = directory.path().join("restored.txt");
        let bytes = b"Rebyte streaming payload\n".repeat(500_000);
        fs::write(&source, &bytes)?;
        let metadata = ArtifactPathMetadata::new().with_suggested_name("large.txt")?;
        let report =
            encode_artifact_path(&source, &encoded, &metadata, &ArtifactOptions::default())?;
        assert_eq!(report.kind(), ArtifactKind::File);
        assert!(report.stored_size() < report.original_size());
        let decoded =
            decode_artifact_file(&encoded, Some(&restored), &SecurityLimits::SIMPLE_ARTIFACT)?;
        assert_eq!(decoded.content_digest(), report.content_digest());
        assert_eq!(fs::read(&restored)?, bytes);
        Ok(())
    }

    #[test]
    fn directory_stream_preserves_empty_directories() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = directory.path().join("source");
        let encoded = directory.path().join("tree.rba");
        let restored = directory.path().join("restored");
        fs::create_dir_all(source.join("empty/nested"))?;
        fs::create_dir_all(source.join("src"))?;
        fs::write(source.join("src/main.rs"), b"fn main() {}\n")?;
        let metadata = ArtifactPathMetadata::new()
            .with_suggested_path(RelativeArtifactPath::new("backup/source")?);
        encode_artifact_path(&source, &encoded, &metadata, &ArtifactOptions::default())?;
        let preview = decode_artifact_file(&encoded, None, &SecurityLimits::SIMPLE_ARTIFACT)?;
        assert_eq!(
            preview.suggested_path().map(RelativeArtifactPath::as_str),
            Some("backup/source")
        );
        decode_artifact_file(&encoded, Some(&restored), &SecurityLimits::SIMPLE_ARTIFACT)?;
        assert!(restored.join("empty/nested").is_dir());
        assert_eq!(fs::read(restored.join("src/main.rs"))?, b"fn main() {}\n");
        Ok(())
    }

    #[test]
    fn corrupted_stream_never_commits_output() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = directory.path().join("source.bin");
        let encoded = directory.path().join("source.rba");
        let restored = directory.path().join("restored.bin");
        fs::write(&source, b"integrity target")?;
        encode_artifact_path(
            &source,
            &encoded,
            &ArtifactPathMetadata::new(),
            &ArtifactOptions::default(),
        )?;
        let mut bytes = fs::read(&encoded)?;
        let last = bytes.last_mut().ok_or(ArtifactTokenError::UnexpectedEof)?;
        *last ^= 1;
        fs::write(&encoded, bytes)?;
        assert!(
            decode_artifact_file(&encoded, Some(&restored), &SecurityLimits::SIMPLE_ARTIFACT,)
                .is_err()
        );
        assert!(!restored.exists());
        Ok(())
    }
}
