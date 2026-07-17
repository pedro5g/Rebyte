// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Manual canonical artifact codec and integrity pipeline.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rebyte_compression::{CompressionError, CompressionProfile, compress_with_profile, decompress};
use rebyte_format::{CompressionAlgorithm, Digest32, RelativeArtifactPath, SecurityLimits};
use rebyte_integrity::{DomainHasher, digest_matches, file_digest};
use std::collections::HashSet;

use crate::error::ArtifactTokenError;
use crate::model::{
    Artifact, ArtifactCompression, ArtifactEntry, ArtifactEntryKind, ArtifactKind, ArtifactOptions,
    DecodedArtifact, EncodedArtifact,
};

/// Text prefix for a Base64URL Artifact Token v1.
pub const ARTIFACT_TOKEN_PREFIX: &str = "ra1_";
/// Fixed byte length of an Artifact Token v1 binary header.
pub const ARTIFACT_HEADER_SIZE: usize = 104;

const MAGIC: [u8; 4] = *b"RBAT";
const VERSION: u8 = 1;
const FLAG_NAME: u16 = 1;
const FLAG_PATH: u16 = 1 << 1;
const SUPPORTED_FLAGS: u16 = FLAG_NAME | FLAG_PATH;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalEntry {
    kind: ArtifactEntryKind,
    path: Option<RelativeArtifactPath>,
    offset: u64,
    size: u64,
    digest: Digest32,
    executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    kind: ArtifactKind,
    compression: CompressionAlgorithm,
    profile: CompressionProfile,
    flags: u16,
    entry_count: u32,
    manifest_size: u64,
    original_size: u64,
    stored_size: u64,
    content_digest: Digest32,
    envelope_digest: Digest32,
}

struct DecodedManifest {
    suggested_name: Option<String>,
    suggested_path: Option<RelativeArtifactPath>,
    entries: Vec<CanonicalEntry>,
}

/// Encodes one artifact into canonical `.rba` bytes.
///
/// # Errors
///
/// Returns [`ArtifactTokenError`] for an invalid artifact shape, duplicate or
/// unsafe paths, resource-limit violations, compression failures or failed
/// self-verification.
pub fn encode_artifact(
    artifact: &Artifact,
    options: &ArtifactOptions,
) -> Result<EncodedArtifact, ArtifactTokenError> {
    let (entries, payload) = canonicalize(artifact, &options.limits)?;
    let manifest = encode_manifest(artifact, &entries, &options.limits)?;
    let content_digest = content_digest(artifact.kind, &entries);
    let (compression, stored) = select_payload(&payload, options)?;
    let entry_count = usize_to_u32(entries.len())?;
    let original_size = usize_to_u64(payload.len())?;
    let stored_size = usize_to_u64(stored.len())?;
    let flags = metadata_flags(artifact);
    let mut header = Header {
        kind: artifact.kind,
        compression,
        profile: options.profile,
        flags,
        entry_count,
        manifest_size: usize_to_u64(manifest.len())?,
        original_size,
        stored_size,
        content_digest,
        envelope_digest: Digest32([0; 32]),
    };
    header.envelope_digest = envelope_digest(&header, &manifest, &stored);
    let header_bytes = encode_header(&header);
    let binary_size = ARTIFACT_HEADER_SIZE
        .checked_add(manifest.len())
        .and_then(|value| value.checked_add(stored.len()))
        .ok_or(ArtifactTokenError::LengthOverflow)?;
    enforce_binary_size(usize_to_u64(binary_size)?, &options.limits)?;
    let mut binary = Vec::with_capacity(binary_size);
    binary.extend_from_slice(&header_bytes);
    binary.extend_from_slice(&manifest);
    binary.extend_from_slice(&stored);

    let decoded = decode_artifact(&binary, &options.limits)?;
    if decoded.artifact != canonical_artifact(artifact, &entries, &payload)? {
        return Err(ArtifactTokenError::ContentDigestMismatch);
    }
    Ok(EncodedArtifact {
        binary,
        kind: artifact.kind,
        compression,
        profile: options.profile,
        content_digest,
        envelope_digest: header.envelope_digest,
        original_size,
        stored_size,
        entry_count,
    })
}

/// Encodes an artifact as canonical Base64URL with the `ra1_` prefix.
///
/// # Errors
///
/// Returns [`ArtifactTokenError`] under the same conditions as
/// [`encode_artifact`], or when textual expansion exceeds policy.
pub fn encode_artifact_token(
    artifact: &Artifact,
    options: &ArtifactOptions,
) -> Result<String, ArtifactTokenError> {
    let encoded = encode_artifact(artifact, options)?;
    encode_artifact_binary_token(encoded.binary(), &options.limits)
}

/// Represents existing `.rba` bytes as `ra1_` Base64URL text.
///
/// This operation changes only the outer representation. Use
/// [`decode_artifact`] when the source bytes have not already been verified.
///
/// # Errors
///
/// Returns [`ArtifactTokenError::TokenTooLarge`] when textual expansion
/// exceeds local policy.
pub fn encode_artifact_binary_token(
    binary: &[u8],
    limits: &SecurityLimits,
) -> Result<String, ArtifactTokenError> {
    let token = format!("{ARTIFACT_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(binary));
    enforce_token_size(usize_to_u64(token.len())?, limits)?;
    Ok(token)
}

/// Decodes and fully verifies canonical `.rba` envelope bytes.
///
/// # Errors
///
/// Returns [`ArtifactTokenError`] before releasing content when parsing,
/// bounds, canonicalization, decompression or any digest check fails.
pub fn decode_artifact(
    binary: &[u8],
    limits: &SecurityLimits,
) -> Result<DecodedArtifact, ArtifactTokenError> {
    enforce_binary_size(usize_to_u64(binary.len())?, limits)?;
    let header = decode_header(binary)?;
    enforce_header_limits(&header, limits)?;
    let manifest_size =
        usize::try_from(header.manifest_size).map_err(|_| ArtifactTokenError::LengthOverflow)?;
    let stored_size =
        usize::try_from(header.stored_size).map_err(|_| ArtifactTokenError::LengthOverflow)?;
    let manifest_end = ARTIFACT_HEADER_SIZE
        .checked_add(manifest_size)
        .ok_or(ArtifactTokenError::LengthOverflow)?;
    let expected_end = manifest_end
        .checked_add(stored_size)
        .ok_or(ArtifactTokenError::LengthOverflow)?;
    if binary.len() != expected_end {
        return Err(ArtifactTokenError::EnvelopeLengthMismatch);
    }
    let manifest = binary
        .get(ARTIFACT_HEADER_SIZE..manifest_end)
        .ok_or(ArtifactTokenError::UnexpectedEof)?;
    let stored = binary
        .get(manifest_end..expected_end)
        .ok_or(ArtifactTokenError::UnexpectedEof)?;
    let actual_envelope_digest = envelope_digest(&header, manifest, stored);
    if !digest_matches(&header.envelope_digest, &actual_envelope_digest) {
        return Err(ArtifactTokenError::EnvelopeDigestMismatch);
    }
    let decoded_manifest = decode_manifest(manifest, &header, limits)?;
    let actual_content_digest = content_digest(header.kind, &decoded_manifest.entries);
    if !digest_matches(&header.content_digest, &actual_content_digest) {
        return Err(ArtifactTokenError::ContentDigestMismatch);
    }
    let payload = decompress(stored, header.compression, header.original_size, limits)?;
    let artifact = reconstruct(
        header.kind,
        decoded_manifest.suggested_name,
        decoded_manifest.suggested_path,
        &decoded_manifest.entries,
        &payload,
    )?;
    Ok(DecodedArtifact {
        artifact,
        compression: header.compression,
        profile: header.profile,
        content_digest: actual_content_digest,
        envelope_digest: actual_envelope_digest,
        original_size: header.original_size,
        stored_size: header.stored_size,
    })
}

/// Decodes canonical `ra1_` text and fully verifies the embedded artifact.
///
/// # Errors
///
/// Returns [`ArtifactTokenError`] for outer text errors or any binary
/// verification failure.
pub fn decode_artifact_token(
    token: &str,
    limits: &SecurityLimits,
) -> Result<DecodedArtifact, ArtifactTokenError> {
    enforce_token_size(usize_to_u64(token.len())?, limits)?;
    let payload = token
        .strip_prefix(ARTIFACT_TOKEN_PREFIX)
        .ok_or(ArtifactTokenError::InvalidPrefix)?;
    if payload.is_empty()
        || payload
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(ArtifactTokenError::InvalidAlphabet);
    }
    let binary = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| ArtifactTokenError::InvalidBase64)?;
    if URL_SAFE_NO_PAD.encode(&binary) != payload {
        return Err(ArtifactTokenError::InvalidBase64);
    }
    decode_artifact(&binary, limits)
}

fn canonicalize(
    artifact: &Artifact,
    limits: &SecurityLimits,
) -> Result<(Vec<CanonicalEntry>, Vec<u8>), ArtifactTokenError> {
    enforce_entry_count(usize_to_u32(artifact.entries.len())?, limits)?;
    validate_metadata(artifact, limits)?;
    let mut source = artifact.entries.clone();
    match artifact.kind {
        ArtifactKind::File => {
            if source.len() != 1
                || source.first().is_none_or(|entry| {
                    entry.kind != ArtifactEntryKind::File || entry.path.is_some()
                })
            {
                return Err(ArtifactTokenError::InvalidFileShape);
            }
        }
        ArtifactKind::Directory => {
            if source.iter().any(|entry| entry.path.is_none()) {
                return Err(ArtifactTokenError::InvalidDirectoryShape);
            }
            source.sort_by(|left, right| {
                left.path
                    .as_ref()
                    .map(RelativeArtifactPath::as_str)
                    .cmp(&right.path.as_ref().map(RelativeArtifactPath::as_str))
            });
            let mut previous: Option<&str> = None;
            for entry in &source {
                let path = entry
                    .path
                    .as_ref()
                    .ok_or(ArtifactTokenError::InvalidDirectoryShape)?
                    .as_str();
                if previous == Some(path) {
                    return Err(ArtifactTokenError::DuplicatePath);
                }
                previous = Some(path);
            }
        }
    }

    let mut payload = Vec::new();
    let mut entries = Vec::with_capacity(source.len());
    for entry in source {
        let offset = usize_to_u64(payload.len())?;
        match entry.kind {
            ArtifactEntryKind::File => {
                let size = usize_to_u64(entry.bytes.len())?;
                enforce_file_size(size, limits)?;
                let next = offset
                    .checked_add(size)
                    .ok_or(ArtifactTokenError::LengthOverflow)?;
                enforce_payload_size(next, limits)?;
                let digest = file_digest(&entry.bytes);
                payload.extend_from_slice(&entry.bytes);
                entries.push(CanonicalEntry {
                    kind: entry.kind,
                    path: entry.path,
                    offset,
                    size,
                    digest,
                    executable: entry.executable,
                });
            }
            ArtifactEntryKind::Directory => {
                if !entry.bytes.is_empty() {
                    return Err(ArtifactTokenError::InvalidDirectoryEntry);
                }
                if entry.executable {
                    return Err(ArtifactTokenError::ExecutableDirectory);
                }
                entries.push(CanonicalEntry {
                    kind: entry.kind,
                    path: entry.path,
                    offset: 0,
                    size: 0,
                    digest: Digest32([0; 32]),
                    executable: false,
                });
            }
        }
    }
    validate_tree(&entries)?;
    Ok((entries, payload))
}

fn canonical_artifact(
    source: &Artifact,
    entries: &[CanonicalEntry],
    payload: &[u8],
) -> Result<Artifact, ArtifactTokenError> {
    reconstruct(
        source.kind,
        source.suggested_name.clone(),
        source.suggested_path.clone(),
        entries,
        payload,
    )
}

fn reconstruct(
    kind: ArtifactKind,
    suggested_name: Option<String>,
    suggested_path: Option<RelativeArtifactPath>,
    entries: &[CanonicalEntry],
    payload: &[u8],
) -> Result<Artifact, ArtifactTokenError> {
    let mut reconstructed = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry.kind {
            ArtifactEntryKind::File => {
                let start = usize::try_from(entry.offset)
                    .map_err(|_| ArtifactTokenError::LengthOverflow)?;
                let size =
                    usize::try_from(entry.size).map_err(|_| ArtifactTokenError::LengthOverflow)?;
                let end = start
                    .checked_add(size)
                    .ok_or(ArtifactTokenError::LengthOverflow)?;
                let bytes = payload
                    .get(start..end)
                    .ok_or(ArtifactTokenError::InvalidPayloadRange)?;
                let digest = file_digest(bytes);
                if !digest_matches(&entry.digest, &digest) {
                    return Err(ArtifactTokenError::FileDigestMismatch);
                }
                reconstructed.push(entry.path.as_ref().map_or_else(
                    || ArtifactEntry::unnamed_file(bytes.to_vec(), entry.executable),
                    |path| ArtifactEntry::file(path.clone(), bytes.to_vec(), entry.executable),
                ));
            }
            ArtifactEntryKind::Directory => {
                let path = entry
                    .path
                    .clone()
                    .ok_or(ArtifactTokenError::InvalidDirectoryShape)?;
                reconstructed.push(ArtifactEntry::directory(path));
            }
        }
    }
    Ok(Artifact {
        kind,
        suggested_name,
        suggested_path,
        entries: reconstructed,
    })
}

fn encode_manifest(
    artifact: &Artifact,
    entries: &[CanonicalEntry],
    limits: &SecurityLimits,
) -> Result<Vec<u8>, ArtifactTokenError> {
    let mut output = Vec::new();
    write_optional_string(&mut output, artifact.suggested_name.as_deref())?;
    write_optional_string(
        &mut output,
        artifact
            .suggested_path
            .as_ref()
            .map(RelativeArtifactPath::as_str),
    )?;
    output.extend_from_slice(&usize_to_u32(entries.len())?.to_be_bytes());
    for entry in entries {
        output.push(entry.kind.wire());
        output.push(u8::from(entry.executable));
        output.extend_from_slice(&[0; 2]);
        let path = entry.path.as_ref().map_or("", RelativeArtifactPath::as_str);
        output.extend_from_slice(&usize_to_u16(path.len())?.to_be_bytes());
        output.extend_from_slice(&[0; 2]);
        output.extend_from_slice(&entry.offset.to_be_bytes());
        output.extend_from_slice(&entry.size.to_be_bytes());
        output.extend_from_slice(entry.digest.as_bytes());
        output.extend_from_slice(path.as_bytes());
    }
    let actual = usize_to_u64(output.len())?;
    if actual > limits.max_manifest_bytes {
        return Err(ArtifactTokenError::ManifestTooLarge {
            max: limits.max_manifest_bytes,
            actual,
        });
    }
    Ok(output)
}

fn decode_manifest(
    bytes: &[u8],
    header: &Header,
    limits: &SecurityLimits,
) -> Result<DecodedManifest, ArtifactTokenError> {
    let mut cursor = Cursor::new(bytes);
    let suggested_name = cursor.read_optional_string()?;
    if let Some(name) = &suggested_name {
        validate_suggested_name(name, limits)?;
    }
    let suggested_path = cursor
        .read_optional_string()?
        .map(|value| {
            RelativeArtifactPath::with_max_bytes(&value, limits.max_path_bytes)
                .map_err(ArtifactTokenError::Path)
        })
        .transpose()?;
    let flags = (u16::from(suggested_name.is_some()) * FLAG_NAME)
        | (u16::from(suggested_path.is_some()) * FLAG_PATH);
    if flags != header.flags {
        return Err(ArtifactTokenError::MetadataFlagMismatch);
    }
    let count = cursor.read_u32()?;
    if count != header.entry_count {
        return Err(ArtifactTokenError::EntryCountMismatch);
    }
    enforce_entry_count(count, limits)?;
    let count_usize = usize::try_from(count).map_err(|_| ArtifactTokenError::LengthOverflow)?;
    let mut entries = Vec::with_capacity(count_usize);
    let mut expected_offset = 0_u64;
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let entry = decode_manifest_entry(&mut cursor, header, limits, &mut expected_offset)?;
        if let Some(path) = &entry.path {
            let value = path.as_str();
            if let Some(item) = previous.as_deref() {
                if item == value {
                    return Err(ArtifactTokenError::DuplicatePath);
                }
                if item > value {
                    return Err(ArtifactTokenError::NonCanonicalOrder);
                }
            }
            previous = Some(value.to_string());
        }
        entries.push(entry);
    }
    if !cursor.is_empty() {
        return Err(ArtifactTokenError::EnvelopeLengthMismatch);
    }
    if expected_offset != header.original_size {
        return Err(ArtifactTokenError::InvalidPayloadRange);
    }
    validate_tree(&entries)?;
    match header.kind {
        ArtifactKind::File
            if entries.len() != 1
                || entries
                    .first()
                    .is_none_or(|entry| entry.kind != ArtifactEntryKind::File) =>
        {
            Err(ArtifactTokenError::InvalidFileShape)
        }
        _ => Ok(DecodedManifest {
            suggested_name,
            suggested_path,
            entries,
        }),
    }
}

fn validate_tree(entries: &[CanonicalEntry]) -> Result<(), ArtifactTokenError> {
    let mut files = HashSet::new();
    for entry in entries {
        let Some(path) = entry.path.as_ref().map(RelativeArtifactPath::as_str) else {
            continue;
        };
        let mut ancestor = path;
        while let Some(index) = ancestor.rfind('/') {
            ancestor = ancestor
                .get(..index)
                .ok_or(ArtifactTokenError::LengthOverflow)?;
            if files.contains(ancestor) {
                return Err(ArtifactTokenError::PathTypeConflict);
            }
        }
        if entry.kind == ArtifactEntryKind::File {
            files.insert(path);
        }
    }
    Ok(())
}

fn decode_manifest_entry(
    cursor: &mut Cursor<'_>,
    header: &Header,
    limits: &SecurityLimits,
    expected_offset: &mut u64,
) -> Result<CanonicalEntry, ArtifactTokenError> {
    let kind = ArtifactEntryKind::from_wire(cursor.read_u8()?)?;
    let executable = match cursor.read_u8()? {
        0 => false,
        1 => true,
        _ => return Err(ArtifactTokenError::InvalidDirectoryEntry),
    };
    if cursor.read_u16()? != 0 {
        return Err(ArtifactTokenError::NonZeroReserved);
    }
    let path_len = usize::from(cursor.read_u16()?);
    if cursor.read_u16()? != 0 {
        return Err(ArtifactTokenError::NonZeroReserved);
    }
    let offset = cursor.read_u64()?;
    let size = cursor.read_u64()?;
    let digest = Digest32(cursor.read_array()?);
    let path = if path_len == 0 {
        None
    } else {
        let value = cursor.read_utf8(path_len)?;
        Some(
            RelativeArtifactPath::with_max_bytes(value, limits.max_path_bytes)
                .map_err(ArtifactTokenError::Path)?,
        )
    };
    match header.kind {
        ArtifactKind::File if path.is_some() => {
            return Err(ArtifactTokenError::InvalidFileShape);
        }
        ArtifactKind::Directory if path.is_none() => {
            return Err(ArtifactTokenError::InvalidDirectoryShape);
        }
        _ => {}
    }
    match kind {
        ArtifactEntryKind::File => {
            enforce_file_size(size, limits)?;
            if offset != *expected_offset {
                return Err(ArtifactTokenError::InvalidPayloadRange);
            }
            *expected_offset = expected_offset
                .checked_add(size)
                .ok_or(ArtifactTokenError::LengthOverflow)?;
        }
        ArtifactEntryKind::Directory => {
            if offset != 0 || size != 0 || digest != Digest32([0; 32]) {
                return Err(ArtifactTokenError::InvalidDirectoryEntry);
            }
            if executable {
                return Err(ArtifactTokenError::ExecutableDirectory);
            }
        }
    }
    Ok(CanonicalEntry {
        kind,
        path,
        offset,
        size,
        digest,
        executable,
    })
}

fn encode_header(header: &Header) -> [u8; ARTIFACT_HEADER_SIZE] {
    let mut output = [0_u8; ARTIFACT_HEADER_SIZE];
    output[0..4].copy_from_slice(&MAGIC);
    output[4] = VERSION;
    output[5] = header.kind.wire();
    output[6] = header.compression as u8;
    output[7] = profile_wire(header.profile);
    output[8..10].copy_from_slice(&header.flags.to_be_bytes());
    output[12..16].copy_from_slice(&header.entry_count.to_be_bytes());
    output[16..24].copy_from_slice(&header.manifest_size.to_be_bytes());
    output[24..32].copy_from_slice(&header.original_size.to_be_bytes());
    output[32..40].copy_from_slice(&header.stored_size.to_be_bytes());
    output[40..72].copy_from_slice(header.content_digest.as_bytes());
    output[72..104].copy_from_slice(header.envelope_digest.as_bytes());
    output
}

fn decode_header(bytes: &[u8]) -> Result<Header, ArtifactTokenError> {
    if bytes.len() < ARTIFACT_HEADER_SIZE {
        return Err(ArtifactTokenError::UnexpectedEof);
    }
    if bytes.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(ArtifactTokenError::InvalidMagic);
    }
    let version = read_byte(bytes, 4)?;
    if version != VERSION {
        return Err(ArtifactTokenError::UnsupportedVersion(version));
    }
    let kind = ArtifactKind::from_wire(read_byte(bytes, 5)?)?;
    let compression_value = read_byte(bytes, 6)?;
    let compression = match compression_value {
        0 => CompressionAlgorithm::None,
        1 => CompressionAlgorithm::Zstd,
        _ => {
            return Err(ArtifactTokenError::UnsupportedCompression(
                compression_value,
            ));
        }
    };
    let profile = profile_from_wire(read_byte(bytes, 7)?)?;
    let flags = read_u16_at(bytes, 8)?;
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err(ArtifactTokenError::UnsupportedFlags(flags));
    }
    if bytes.get(10..12) != Some([0, 0].as_slice()) {
        return Err(ArtifactTokenError::NonZeroReserved);
    }
    Ok(Header {
        kind,
        compression,
        profile,
        flags,
        entry_count: read_u32_at(bytes, 12)?,
        manifest_size: read_u64_at(bytes, 16)?,
        original_size: read_u64_at(bytes, 24)?,
        stored_size: read_u64_at(bytes, 32)?,
        content_digest: Digest32(read_array_at(bytes, 40)?),
        envelope_digest: Digest32(read_array_at(bytes, 72)?),
    })
}

fn content_digest(kind: ArtifactKind, entries: &[CanonicalEntry]) -> Digest32 {
    let mut hasher = DomainHasher::artifact_content();
    hasher.update(&[VERSION, kind.wire()]);
    hasher.update(
        &usize_to_u32(entries.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for entry in entries {
        hasher.update(&[entry.kind.wire(), u8::from(entry.executable)]);
        let path = entry.path.as_ref().map_or("", RelativeArtifactPath::as_str);
        hasher.update(&usize_to_u64(path.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update(&entry.size.to_be_bytes());
        hasher.update(entry.digest.as_bytes());
    }
    hasher.finalize()
}

fn envelope_digest(header: &Header, manifest: &[u8], stored: &[u8]) -> Digest32 {
    let mut hasher = DomainHasher::artifact_envelope();
    hasher.update(&[
        VERSION,
        header.kind.wire(),
        header.compression as u8,
        profile_wire(header.profile),
    ]);
    hasher.update(&header.flags.to_be_bytes());
    hasher.update(&header.entry_count.to_be_bytes());
    hasher.update(&header.manifest_size.to_be_bytes());
    hasher.update(&header.original_size.to_be_bytes());
    hasher.update(&header.stored_size.to_be_bytes());
    hasher.update(header.content_digest.as_bytes());
    hasher.update(manifest);
    hasher.update(stored);
    hasher.finalize()
}

const fn profile_wire(value: CompressionProfile) -> u8 {
    match value {
        CompressionProfile::Fast => 0,
        CompressionProfile::Balanced => 1,
        CompressionProfile::Maximum => 2,
    }
}

const fn profile_from_wire(value: u8) -> Result<CompressionProfile, ArtifactTokenError> {
    match value {
        0 => Ok(CompressionProfile::Fast),
        1 => Ok(CompressionProfile::Balanced),
        2 => Ok(CompressionProfile::Maximum),
        _ => Err(ArtifactTokenError::UnsupportedProfile(value)),
    }
}

fn select_payload(
    payload: &[u8],
    options: &ArtifactOptions,
) -> Result<(CompressionAlgorithm, Vec<u8>), ArtifactTokenError> {
    match options.compression {
        ArtifactCompression::None => Ok((
            CompressionAlgorithm::None,
            compress_with_profile(
                payload,
                CompressionAlgorithm::None,
                options.profile,
                &options.limits,
            )?,
        )),
        ArtifactCompression::Zstd => Ok((
            CompressionAlgorithm::Zstd,
            compress_with_profile(
                payload,
                CompressionAlgorithm::Zstd,
                options.profile,
                &options.limits,
            )?,
        )),
        ArtifactCompression::Auto => {
            match compress_with_profile(
                payload,
                CompressionAlgorithm::Zstd,
                options.profile,
                &options.limits,
            ) {
                Ok(compressed) if compressed.len() < payload.len() => {
                    Ok((CompressionAlgorithm::Zstd, compressed))
                }
                Ok(_) | Err(CompressionError::UnsupportedEncoder) => Ok((
                    CompressionAlgorithm::None,
                    compress_with_profile(
                        payload,
                        CompressionAlgorithm::None,
                        options.profile,
                        &options.limits,
                    )?,
                )),
                Err(error) => Err(error.into()),
            }
        }
    }
}

fn metadata_flags(artifact: &Artifact) -> u16 {
    (u16::from(artifact.suggested_name.is_some()) * FLAG_NAME)
        | (u16::from(artifact.suggested_path.is_some()) * FLAG_PATH)
}

fn validate_metadata(
    artifact: &Artifact,
    limits: &SecurityLimits,
) -> Result<(), ArtifactTokenError> {
    if let Some(name) = &artifact.suggested_name {
        validate_suggested_name(name, limits)?;
    }
    if let Some(path) = &artifact.suggested_path {
        RelativeArtifactPath::with_max_bytes(path.as_str(), limits.max_path_bytes)
            .map_err(ArtifactTokenError::Path)?;
    }
    Ok(())
}

fn validate_suggested_name(value: &str, limits: &SecurityLimits) -> Result<(), ArtifactTokenError> {
    if value.contains('/') {
        return Err(ArtifactTokenError::InvalidName(
            rebyte_format::PathError::EmptyComponent,
        ));
    }
    RelativeArtifactPath::with_max_bytes(value, limits.max_path_bytes)
        .map(|_| ())
        .map_err(ArtifactTokenError::InvalidName)
}

fn enforce_header_limits(
    header: &Header,
    limits: &SecurityLimits,
) -> Result<(), ArtifactTokenError> {
    enforce_entry_count(header.entry_count, limits)?;
    if header.manifest_size > limits.max_manifest_bytes {
        return Err(ArtifactTokenError::ManifestTooLarge {
            max: limits.max_manifest_bytes,
            actual: header.manifest_size,
        });
    }
    if header.stored_size > limits.max_compressed_payload_bytes {
        return Err(ArtifactTokenError::BinaryTooLarge {
            max: limits.max_compressed_payload_bytes,
            actual: header.stored_size,
        });
    }
    enforce_payload_size(header.original_size, limits)
}

const fn enforce_entry_count(
    actual: u32,
    limits: &SecurityLimits,
) -> Result<(), ArtifactTokenError> {
    if actual > limits.max_file_count {
        Err(ArtifactTokenError::TooManyEntries {
            max: limits.max_file_count,
            actual,
        })
    } else {
        Ok(())
    }
}

const fn enforce_file_size(actual: u64, limits: &SecurityLimits) -> Result<(), ArtifactTokenError> {
    if actual > limits.max_single_file_bytes {
        Err(ArtifactTokenError::FileTooLarge {
            max: limits.max_single_file_bytes,
            actual,
        })
    } else {
        Ok(())
    }
}

const fn enforce_payload_size(
    actual: u64,
    limits: &SecurityLimits,
) -> Result<(), ArtifactTokenError> {
    if actual > limits.max_uncompressed_payload_bytes {
        Err(ArtifactTokenError::PayloadTooLarge {
            max: limits.max_uncompressed_payload_bytes,
            actual,
        })
    } else {
        Ok(())
    }
}

const fn enforce_binary_size(
    actual: u64,
    limits: &SecurityLimits,
) -> Result<(), ArtifactTokenError> {
    if actual > limits.max_capsule_bytes {
        Err(ArtifactTokenError::BinaryTooLarge {
            max: limits.max_capsule_bytes,
            actual,
        })
    } else {
        Ok(())
    }
}

const fn enforce_token_size(
    actual: u64,
    limits: &SecurityLimits,
) -> Result<(), ArtifactTokenError> {
    if actual > limits.max_token_bytes {
        Err(ArtifactTokenError::TokenTooLarge {
            max: limits.max_token_bytes,
            actual,
        })
    } else {
        Ok(())
    }
}

fn write_optional_string(
    output: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), ArtifactTokenError> {
    let value = value.unwrap_or_default();
    output.extend_from_slice(&usize_to_u16(value.len())?.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_byte(bytes: &[u8], offset: usize) -> Result<u8, ArtifactTokenError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(ArtifactTokenError::UnexpectedEof)
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, ArtifactTokenError> {
    Ok(u16::from_be_bytes(read_array_at(bytes, offset)?))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, ArtifactTokenError> {
    Ok(u32::from_be_bytes(read_array_at(bytes, offset)?))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64, ArtifactTokenError> {
    Ok(u64::from_be_bytes(read_array_at(bytes, offset)?))
}

fn read_array_at<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ArtifactTokenError> {
    let end = offset
        .checked_add(N)
        .ok_or(ArtifactTokenError::LengthOverflow)?;
    bytes
        .get(offset..end)
        .ok_or(ArtifactTokenError::UnexpectedEof)?
        .try_into()
        .map_err(|_| ArtifactTokenError::UnexpectedEof)
}

fn usize_to_u16(value: usize) -> Result<u16, ArtifactTokenError> {
    u16::try_from(value).map_err(|_| ArtifactTokenError::LengthOverflow)
}

fn usize_to_u32(value: usize) -> Result<u32, ArtifactTokenError> {
    u32::try_from(value).map_err(|_| ArtifactTokenError::LengthOverflow)
}

fn usize_to_u64(value: usize) -> Result<u64, ArtifactTokenError> {
    u64::try_from(value).map_err(|_| ArtifactTokenError::LengthOverflow)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_u8(&mut self) -> Result<u8, ArtifactTokenError> {
        let value = read_byte(self.bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ArtifactTokenError> {
        let value = read_u16_at(self.bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(2)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, ArtifactTokenError> {
        let value = read_u32_at(self.bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(4)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, ArtifactTokenError> {
        let value = read_u64_at(self.bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(8)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ArtifactTokenError> {
        let value = read_array_at(self.bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(N)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        Ok(value)
    }

    fn read_utf8(&mut self, length: usize) -> Result<&'a str, ArtifactTokenError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ArtifactTokenError::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ArtifactTokenError::UnexpectedEof)?;
        self.offset = end;
        core::str::from_utf8(bytes).map_err(|_| ArtifactTokenError::InvalidUtf8)
    }

    fn read_optional_string(&mut self) -> Result<Option<String>, ArtifactTokenError> {
        let length = usize::from(self.read_u16()?);
        if length == 0 {
            Ok(None)
        } else {
            self.read_utf8(length).map(|value| Some(value.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rebyte_compression::CompressionProfile;
    use rebyte_format::{RelativeArtifactPath, SecurityLimits};

    use crate::DecodedArtifact;

    use super::{
        ARTIFACT_HEADER_SIZE, Artifact, ArtifactCompression, ArtifactEntry, ArtifactKind,
        ArtifactOptions, ArtifactTokenError, decode_artifact, decode_artifact_token,
        encode_artifact, encode_artifact_token,
    };

    fn path(value: &str) -> Result<RelativeArtifactPath, ArtifactTokenError> {
        RelativeArtifactPath::new(value).map_err(Into::into)
    }

    #[test]
    fn file_round_trip_preserves_name_extension_and_bytes() -> Result<(), ArtifactTokenError> {
        let artifact = Artifact::file(b"console.log('rebyte');\n".to_vec(), false)
            .with_suggested_name("app.min.js")?
            .with_suggested_path(path("releases/web")?);
        let token = encode_artifact_token(&artifact, &ArtifactOptions::default())?;
        let decoded = decode_artifact_token(&token, &SecurityLimits::SIMPLE_ARTIFACT)?;
        assert_eq!(decoded.artifact(), &artifact);
        assert_eq!(decoded.artifact().suggested_name(), Some("app.min.js"));
        Ok(())
    }

    #[test]
    fn directory_round_trip_is_sorted_and_preserves_empty_dirs() -> Result<(), ArtifactTokenError> {
        let artifact = Artifact::directory(vec![
            ArtifactEntry::file(path("src/main.rs")?, b"fn main() {}\n".to_vec(), false),
            ArtifactEntry::directory(path("empty")?),
            ArtifactEntry::file(path("Cargo.toml")?, b"[package]\n".to_vec(), false),
        ])
        .with_suggested_name("demo")?;
        let encoded = encode_artifact(&artifact, &ArtifactOptions::default())?;
        let decoded = decode_artifact(encoded.binary(), &SecurityLimits::SIMPLE_ARTIFACT)?;
        let paths: Vec<_> = decoded
            .artifact()
            .entries()
            .iter()
            .filter_map(|entry| entry.path().map(RelativeArtifactPath::as_str))
            .collect();
        assert_eq!(paths, ["Cargo.toml", "empty", "src/main.rs"]);
        assert_eq!(decoded.artifact().kind(), ArtifactKind::Directory);
        Ok(())
    }

    #[test]
    fn suggestions_do_not_change_content_identity() -> Result<(), ArtifactTokenError> {
        let first = Artifact::file(b"same".to_vec(), false).with_suggested_name("a.txt")?;
        let second = Artifact::file(b"same".to_vec(), false)
            .with_suggested_name("b.txt")?
            .with_suggested_path(path("elsewhere")?);
        let first = encode_artifact(&first, &ArtifactOptions::default())?;
        let second = encode_artifact(&second, &ArtifactOptions::default())?;
        assert_eq!(first.content_digest(), second.content_digest());
        assert_ne!(first.envelope_digest(), second.envelope_digest());
        Ok(())
    }

    #[test]
    fn extreme_compression_stays_compact() -> Result<(), ArtifactTokenError> {
        let artifact = Artifact::file(vec![b'x'; 8 * 1_024 * 1_024], false);
        let encoded = encode_artifact(&artifact, &ArtifactOptions::default())?;
        assert!(encoded.stored_size() < encoded.original_size() / 200);
        assert_eq!(
            decode_artifact(encoded.binary(), &SecurityLimits::SIMPLE_ARTIFACT)?
                .artifact()
                .entries()[0]
                .bytes(),
            artifact.entries()[0].bytes()
        );
        Ok(())
    }

    #[test]
    fn rejects_mutation_truncation_and_trailing_bytes() -> Result<(), ArtifactTokenError> {
        let artifact = Artifact::file(b"mutation".to_vec(), false);
        let encoded = encode_artifact(&artifact, &ArtifactOptions::default())?;
        let mut mutated = encoded.binary().to_vec();
        let payload = mutated
            .get_mut(ARTIFACT_HEADER_SIZE..)
            .and_then(|bytes| bytes.last_mut())
            .ok_or(ArtifactTokenError::UnexpectedEof)?;
        *payload ^= 1;
        assert_eq!(
            decode_artifact(&mutated, &SecurityLimits::SIMPLE_ARTIFACT),
            Err(ArtifactTokenError::EnvelopeDigestMismatch)
        );
        assert!(
            decode_artifact(
                &encoded.binary()[..encoded.binary().len() - 1],
                &SecurityLimits::SIMPLE_ARTIFACT
            )
            .is_err()
        );
        let mut trailing = encoded.binary().to_vec();
        trailing.push(0);
        assert_eq!(
            decode_artifact(&trailing, &SecurityLimits::SIMPLE_ARTIFACT),
            Err(ArtifactTokenError::EnvelopeLengthMismatch)
        );
        Ok(())
    }

    #[test]
    fn rejects_duplicate_paths_and_file_ancestors() -> Result<(), ArtifactTokenError> {
        let duplicate = Artifact::directory(vec![
            ArtifactEntry::directory(path("same")?),
            ArtifactEntry::file(path("same")?, Vec::new(), false),
        ]);
        assert_eq!(
            encode_artifact(&duplicate, &ArtifactOptions::default()),
            Err(ArtifactTokenError::DuplicatePath)
        );

        let conflict = Artifact::directory(vec![
            ArtifactEntry::file(path("parent")?, b"file".to_vec(), false),
            ArtifactEntry::file(path("parent/child.txt")?, b"child".to_vec(), false),
        ]);
        assert_eq!(
            encode_artifact(&conflict, &ArtifactOptions::default()),
            Err(ArtifactTokenError::PathTypeConflict)
        );
        Ok(())
    }

    #[test]
    fn every_profile_and_algorithm_round_trips() -> Result<(), ArtifactTokenError> {
        let artifact = Artifact::file(b"profile profile profile\n".repeat(10_000), false);
        for profile in [
            CompressionProfile::Fast,
            CompressionProfile::Balanced,
            CompressionProfile::Maximum,
        ] {
            for compression in [
                ArtifactCompression::Auto,
                ArtifactCompression::Zstd,
                ArtifactCompression::None,
            ] {
                let options = ArtifactOptions::default()
                    .with_profile(profile)
                    .with_compression(compression);
                let encoded = encode_artifact(&artifact, &options)?;
                assert_eq!(
                    decode_artifact(encoded.binary(), &SecurityLimits::SIMPLE_ARTIFACT)?.artifact(),
                    &artifact
                );
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_file_bytes_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..64_000)) {
            let artifact = Artifact::file(bytes, false);
            let encoded = encode_artifact(&artifact, &ArtifactOptions::default());
            prop_assert!(encoded.is_ok());
            if let Ok(encoded) = encoded {
                let decoded = decode_artifact(
                    encoded.binary(),
                    &SecurityLimits::SIMPLE_ARTIFACT,
                );
                prop_assert_eq!(decoded.map(DecodedArtifact::into_artifact), Ok(artifact));
            }
        }
    }
}
