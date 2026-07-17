//! Deterministic binary encoding.

use alloc::vec::Vec;
use rebyte_format::{
    BoundedString, CapsuleHeaderV1, CapsuleManifestV1, FileEntryV1, HEADER_SIZE_V1, MAGIC,
    SecurityLimits,
};

use crate::{CodecError, DecodedCapsule};

/// Encodes the fixed RAP v1 header.
///
/// # Errors
///
/// Returns [`CodecError`] when a fixed field or declared resource is invalid.
pub fn encode_header(header: &CapsuleHeaderV1) -> Result<Vec<u8>, CodecError> {
    header.validate(&SecurityLimits::V1)?;
    let mut output = Vec::with_capacity(usize::from(HEADER_SIZE_V1));
    output.extend_from_slice(&MAGIC);
    push_u16(&mut output, header.protocol_version.get());
    push_u16(&mut output, header.header_size);
    push_u32(&mut output, header.flags);
    output.push(header.compression as u8);
    output.push(header.signature as u8);
    push_u16(&mut output, 0);
    push_u64(&mut output, header.manifest_size);
    push_u64(&mut output, header.compressed_payload_size);
    push_u64(&mut output, header.uncompressed_payload_size);
    push_u32(&mut output, header.file_count);
    push_u32(&mut output, 0);
    output.extend_from_slice(header.publisher_key_id.as_bytes());
    debug_assert_eq!(output.len(), usize::from(HEADER_SIZE_V1));
    Ok(output)
}

/// Encodes a canonical RAP v1 manifest.
///
/// # Errors
///
/// Returns [`CodecError`] when file ordering, ranges or a bounded encoded
/// length is invalid.
pub fn encode_manifest(manifest: &CapsuleManifestV1) -> Result<Vec<u8>, CodecError> {
    validate_entries(&manifest.files)?;
    let mut output = Vec::new();
    push_u16(&mut output, 1);
    push_u16(&mut output, 0);
    push_optional_string(
        &mut output,
        manifest.capsule_name.as_ref().map(BoundedString::as_str),
    )?;
    push_optional_string(
        &mut output,
        manifest.description.as_ref().map(BoundedString::as_str),
    )?;
    push_string(&mut output, manifest.producer.name.as_str())?;
    push_optional_string(
        &mut output,
        manifest
            .producer
            .version
            .as_ref()
            .map(BoundedString::as_str),
    )?;
    for entry in &manifest.files {
        encode_entry(&mut output, entry)?;
    }
    Ok(output)
}

/// Encodes a complete signed RAP v1 envelope.
///
/// # Errors
///
/// Returns [`CodecError`] when semantic lengths do not match the header or a
/// value is not canonical.
pub fn encode_capsule(capsule: &DecodedCapsule) -> Result<Vec<u8>, CodecError> {
    let header = encode_header(&capsule.header)?;
    let manifest = encode_manifest(&capsule.manifest)?;
    ensure_declared_lengths(capsule, manifest.len())?;

    let capacity = header
        .len()
        .checked_add(manifest.len())
        .and_then(|value| value.checked_add(capsule.compressed_payload.len()))
        .and_then(|value| value.checked_add(32 + 64))
        .ok_or(CodecError::LengthOverflow)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&header);
    output.extend_from_slice(&manifest);
    output.extend_from_slice(&capsule.compressed_payload);
    output.extend_from_slice(capsule.capsule_digest.as_bytes());
    output.extend_from_slice(capsule.signature.as_bytes());
    Ok(output)
}

fn ensure_declared_lengths(
    capsule: &DecodedCapsule,
    manifest_len: usize,
) -> Result<(), CodecError> {
    let manifest_len = u64::try_from(manifest_len).map_err(|_| CodecError::LengthOverflow)?;
    let payload_len =
        u64::try_from(capsule.compressed_payload.len()).map_err(|_| CodecError::LengthOverflow)?;
    let file_count =
        u32::try_from(capsule.manifest.files.len()).map_err(|_| CodecError::LengthOverflow)?;
    if capsule.header.manifest_size != manifest_len
        || capsule.header.compressed_payload_size != payload_len
        || capsule.header.file_count != file_count
    {
        return Err(CodecError::FileCountMismatch);
    }
    if validate_entries(&capsule.manifest.files)? != capsule.header.uncompressed_payload_size {
        return Err(CodecError::PayloadSizeMismatch);
    }
    Ok(())
}

fn encode_entry(output: &mut Vec<u8>, entry: &FileEntryV1) -> Result<(), CodecError> {
    push_string(output, entry.path.as_str())?;
    output.push(entry.operation as u8);
    output.push(entry.content_kind as u8);
    output.push(u8::from(entry.executable));
    output.push(0);
    push_u64(output, entry.offset);
    push_u64(output, entry.size);
    output.extend_from_slice(entry.digest.as_bytes());
    Ok(())
}

fn validate_entries(entries: &[FileEntryV1]) -> Result<u64, CodecError> {
    let mut previous_path: Option<&str> = None;
    let mut expected_offset = 0_u64;
    for entry in entries {
        if previous_path.is_some_and(|previous| previous >= entry.path.as_str()) {
            return Err(CodecError::NonCanonicalPathOrder);
        }
        if entry.offset != expected_offset || entry.size > SecurityLimits::V1.max_single_file_bytes
        {
            return Err(CodecError::NonContiguousPayload);
        }
        expected_offset = expected_offset
            .checked_add(entry.size)
            .ok_or(CodecError::LengthOverflow)?;
        previous_path = Some(entry.path.as_str());
    }
    Ok(expected_offset)
}

fn push_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), CodecError> {
    if let Some(value) = value {
        output.push(1);
        push_string(output, value)
    } else {
        output.push(0);
        Ok(())
    }
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), CodecError> {
    let length = u32::try_from(value.len()).map_err(|_| CodecError::LengthOverflow)?;
    push_u32(output, length);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use rebyte_format::{
        BoundedString, CapsuleHeaderV1, CapsuleManifestV1, CompressionAlgorithm, ContentKind,
        Digest32, FileEntryV1, FileOperation, HEADER_SIZE_V1, KeyId, MAX_PRODUCER_NAME_BYTES,
        ProducerMetadata, ProtocolVersion, RelativeArtifactPath, SignatureAlgorithm,
    };

    use crate::{CodecError, DecodedCapsule, SignatureBytes, encode_capsule};

    fn capsule() -> Result<DecodedCapsule, CodecError> {
        let producer = BoundedString::<MAX_PRODUCER_NAME_BYTES>::new("test", "producer")?;
        let path = RelativeArtifactPath::new("a.txt")?;
        let manifest = CapsuleManifestV1 {
            capsule_name: None,
            description: None,
            producer: ProducerMetadata {
                name: producer,
                version: None,
            },
            files: vec![FileEntryV1 {
                path,
                operation: FileOperation::CreateOrReplace,
                content_kind: ContentKind::TextUtf8,
                executable: false,
                offset: 0,
                size: 1,
                digest: Digest32([7; 32]),
            }],
        };
        let manifest_size = super::encode_manifest(&manifest)?.len();
        Ok(DecodedCapsule {
            header: CapsuleHeaderV1 {
                protocol_version: ProtocolVersion::V1,
                header_size: HEADER_SIZE_V1,
                flags: 0,
                compression: CompressionAlgorithm::None,
                signature: SignatureAlgorithm::Ed25519,
                manifest_size: u64::try_from(manifest_size)
                    .map_err(|_| CodecError::LengthOverflow)?,
                compressed_payload_size: 1,
                uncompressed_payload_size: 1,
                file_count: 1,
                publisher_key_id: KeyId([8; 32]),
            },
            manifest,
            compressed_payload: vec![b'x'],
            capsule_digest: Digest32([9; 32]),
            signature: SignatureBytes([10; 64]),
        })
    }

    #[test]
    fn envelope_length_matches_wire_layout() -> Result<(), CodecError> {
        let capsule = capsule()?;
        let encoded = encode_capsule(&capsule)?;
        let expected = usize::from(HEADER_SIZE_V1)
            + usize::try_from(capsule.header.manifest_size)
                .map_err(|_| CodecError::LengthOverflow)?
            + 1
            + 32
            + 64;
        assert_eq!(encoded.len(), expected);
        Ok(())
    }

    #[test]
    fn rejects_unsorted_entries() -> Result<(), CodecError> {
        let mut capsule = capsule()?;
        let mut second = capsule.manifest.files[0].clone();
        second.path = RelativeArtifactPath::new("0.txt")?;
        second.offset = 1;
        capsule.manifest.files.push(second);
        assert_eq!(
            super::encode_manifest(&capsule.manifest),
            Err(CodecError::NonCanonicalPathOrder)
        );
        Ok(())
    }
}
