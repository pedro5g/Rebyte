//! Bounded cursor-based decoding.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::str;
use rebyte_format::{
    BoundedString, CapsuleHeaderV1, CapsuleManifestV1, CompressionAlgorithm, ContentKind, Digest32,
    FileEntryV1, FileOperation, HEADER_SIZE_V1, KeyId, MAGIC, MAX_CAPSULE_NAME_BYTES,
    MAX_DESCRIPTION_BYTES, MAX_PRODUCER_NAME_BYTES, MAX_PRODUCER_VERSION_BYTES, ProducerMetadata,
    ProtocolVersion, RelativeArtifactPath, SecurityLimits, SignatureAlgorithm,
};

use crate::{CodecError, DecodedCapsule, SignatureBytes};

/// Decodes and validates a fixed RAP v1 header.
///
/// # Errors
///
/// Returns [`CodecError`] for truncation, unknown fixed values, non-zero
/// reserved fields or declared resources outside `limits`.
pub fn decode_header(input: &[u8], limits: &SecurityLimits) -> Result<CapsuleHeaderV1, CodecError> {
    match input.len().cmp(&usize::from(HEADER_SIZE_V1)) {
        core::cmp::Ordering::Less => return Err(CodecError::UnexpectedEof),
        core::cmp::Ordering::Greater => return Err(CodecError::TrailingBytes),
        core::cmp::Ordering::Equal => {}
    }
    let mut cursor = Cursor::new(input);
    if cursor.read_array::<4>()? != MAGIC {
        return Err(CodecError::InvalidMagic);
    }
    let protocol_version = ProtocolVersion::try_from(cursor.read_u16()?)?;
    let header_size = cursor.read_u16()?;
    let flags = cursor.read_u32()?;
    let compression = CompressionAlgorithm::try_from(cursor.read_u8()?)?;
    let signature = SignatureAlgorithm::try_from(cursor.read_u8()?)?;
    if cursor.read_u16()? != 0 {
        return Err(CodecError::NonZeroReserved);
    }
    let manifest_size = cursor.read_u64()?;
    let compressed_payload_size = cursor.read_u64()?;
    let uncompressed_payload_size = cursor.read_u64()?;
    let file_count = cursor.read_u32()?;
    if cursor.read_u32()? != 0 {
        return Err(CodecError::NonZeroReserved);
    }
    let publisher_key_id = KeyId(cursor.read_array::<32>()?);
    if cursor.position() != usize::from(HEADER_SIZE_V1) {
        return Err(CodecError::TrailingBytes);
    }
    let header = CapsuleHeaderV1 {
        protocol_version,
        header_size,
        flags,
        compression,
        signature,
        manifest_size,
        compressed_payload_size,
        uncompressed_payload_size,
        file_count,
        publisher_key_id,
    };
    header.validate(limits)?;
    Ok(header)
}

/// Decodes a complete capsule without granting cryptographic trust.
///
/// # Errors
///
/// Returns [`CodecError`] when the input exceeds `limits`, is truncated,
/// contains invalid values or is not the unique canonical RAP v1 encoding.
pub fn decode_capsule(input: &[u8], limits: &SecurityLimits) -> Result<DecodedCapsule, CodecError> {
    enforce_input_limit(input.len(), limits.max_capsule_bytes)?;
    let header_bytes = input
        .get(..usize::from(HEADER_SIZE_V1))
        .ok_or(CodecError::UnexpectedEof)?;
    let header = decode_header(header_bytes, limits)?;
    let manifest_len = usize_from_u64(header.manifest_size)?;
    let payload_len = usize_from_u64(header.compressed_payload_size)?;
    let expected_len = usize::from(HEADER_SIZE_V1)
        .checked_add(manifest_len)
        .and_then(|value| value.checked_add(payload_len))
        .and_then(|value| value.checked_add(32 + 64))
        .ok_or(CodecError::LengthOverflow)?;
    match input.len().cmp(&expected_len) {
        core::cmp::Ordering::Less => return Err(CodecError::UnexpectedEof),
        core::cmp::Ordering::Greater => return Err(CodecError::TrailingBytes),
        core::cmp::Ordering::Equal => {}
    }

    let manifest_start = usize::from(HEADER_SIZE_V1);
    let manifest_end = manifest_start
        .checked_add(manifest_len)
        .ok_or(CodecError::LengthOverflow)?;
    let payload_end = manifest_end
        .checked_add(payload_len)
        .ok_or(CodecError::LengthOverflow)?;
    let digest_end = payload_end
        .checked_add(32)
        .ok_or(CodecError::LengthOverflow)?;

    let manifest_bytes = input
        .get(manifest_start..manifest_end)
        .ok_or(CodecError::UnexpectedEof)?;
    let manifest = decode_manifest(manifest_bytes, &header, limits)?;
    let compressed_payload = input
        .get(manifest_end..payload_end)
        .ok_or(CodecError::UnexpectedEof)?
        .to_vec();
    let capsule_digest = Digest32(read_array_from_range::<32>(input, payload_end, digest_end)?);
    let signature = SignatureBytes(read_array_from_range::<64>(
        input,
        digest_end,
        expected_len,
    )?);
    Ok(DecodedCapsule {
        header,
        manifest,
        compressed_payload,
        capsule_digest,
        signature,
    })
}

fn decode_manifest(
    input: &[u8],
    header: &CapsuleHeaderV1,
    limits: &SecurityLimits,
) -> Result<CapsuleManifestV1, CodecError> {
    let mut cursor = Cursor::new(input);
    let version = cursor.read_u16()?;
    if version != 1 {
        return Err(CodecError::InvalidManifestVersion(version));
    }
    if cursor.read_u16()? != 0 {
        return Err(CodecError::NonZeroReserved);
    }
    let capsule_name =
        read_optional_bounded::<MAX_CAPSULE_NAME_BYTES>(&mut cursor, "capsule name")?;
    let description = read_optional_bounded::<MAX_DESCRIPTION_BYTES>(&mut cursor, "description")?;
    let producer_name = read_bounded::<MAX_PRODUCER_NAME_BYTES>(&mut cursor, "producer name")?;
    let producer_version =
        read_optional_bounded::<MAX_PRODUCER_VERSION_BYTES>(&mut cursor, "producer version")?;
    let file_count = usize::try_from(header.file_count).map_err(|_| CodecError::LengthOverflow)?;
    let mut files = Vec::with_capacity(file_count);
    let mut expected_offset = 0_u64;
    for _ in 0..file_count {
        let entry = decode_entry(&mut cursor, limits)?;
        if files
            .last()
            .is_some_and(|previous: &FileEntryV1| previous.path >= entry.path)
        {
            return Err(CodecError::NonCanonicalPathOrder);
        }
        if entry.offset != expected_offset {
            return Err(CodecError::NonContiguousPayload);
        }
        expected_offset = expected_offset
            .checked_add(entry.size)
            .ok_or(CodecError::LengthOverflow)?;
        files.push(entry);
    }
    if cursor.remaining() != 0 {
        return Err(CodecError::TrailingBytes);
    }
    if files.len() != file_count {
        return Err(CodecError::FileCountMismatch);
    }
    if expected_offset != header.uncompressed_payload_size {
        return Err(CodecError::PayloadSizeMismatch);
    }
    Ok(CapsuleManifestV1 {
        capsule_name,
        description,
        producer: ProducerMetadata {
            name: producer_name,
            version: producer_version,
        },
        files,
    })
}

fn decode_entry(
    cursor: &mut Cursor<'_>,
    limits: &SecurityLimits,
) -> Result<FileEntryV1, CodecError> {
    let path = cursor.read_string(limits.max_path_bytes)?;
    let path = RelativeArtifactPath::with_max_bytes(&path, limits.max_path_bytes)?;
    let operation = FileOperation::try_from(cursor.read_u8()?)?;
    let content_kind = ContentKind::try_from(cursor.read_u8()?)?;
    let executable = match cursor.read_u8()? {
        0 => false,
        1 => true,
        value => return Err(CodecError::InvalidBoolean(value)),
    };
    if cursor.read_u8()? != 0 {
        return Err(CodecError::NonZeroReserved);
    }
    let offset = cursor.read_u64()?;
    let size = cursor.read_u64()?;
    if size > limits.max_single_file_bytes {
        return Err(CodecError::InputTooLarge {
            max: limits.max_single_file_bytes,
            actual: size,
        });
    }
    let digest = Digest32(cursor.read_array::<32>()?);
    Ok(FileEntryV1 {
        path,
        operation,
        content_kind,
        executable,
        offset,
        size,
        digest,
    })
}

fn read_bounded<const MAX: usize>(
    cursor: &mut Cursor<'_>,
    field: &'static str,
) -> Result<BoundedString<MAX>, CodecError> {
    let value = cursor.read_string(MAX)?;
    Ok(BoundedString::new(&value, field)?)
}

fn read_optional_bounded<const MAX: usize>(
    cursor: &mut Cursor<'_>,
    field: &'static str,
) -> Result<Option<BoundedString<MAX>>, CodecError> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => read_bounded(cursor, field).map(Some),
        value => Err(CodecError::InvalidOptionalTag(value)),
    }
}

fn read_array_from_range<const N: usize>(
    input: &[u8],
    start: usize,
    end: usize,
) -> Result<[u8; N], CodecError> {
    input
        .get(start..end)
        .ok_or(CodecError::UnexpectedEof)?
        .try_into()
        .map_err(|_| CodecError::UnexpectedEof)
}

fn enforce_input_limit(actual: usize, max: u64) -> Result<(), CodecError> {
    let actual = u64::try_from(actual).map_err(|_| CodecError::LengthOverflow)?;
    if actual > max {
        Err(CodecError::InputTooLarge { max, actual })
    } else {
        Ok(())
    }
}

fn usize_from_u64(value: u64) -> Result<usize, CodecError> {
    usize::try_from(value).map_err(|_| CodecError::LengthOverflow)
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(CodecError::LengthOverflow)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.position = end;
        bytes.try_into().map_err(|_| CodecError::UnexpectedEof)
    }

    fn read_string(&mut self, max: usize) -> Result<alloc::string::String, CodecError> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| CodecError::LengthOverflow)?;
        if length > max {
            return Err(CodecError::InputTooLarge {
                max: u64::try_from(max).map_err(|_| CodecError::LengthOverflow)?,
                actual: u64::try_from(length).map_err(|_| CodecError::LengthOverflow)?,
            });
        }
        let end = self
            .position
            .checked_add(length)
            .ok_or(CodecError::LengthOverflow)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.position = end;
        str::from_utf8(bytes)
            .map(ToString::to_string)
            .map_err(|_| CodecError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use rebyte_format::{
        BoundedString, CapsuleHeaderV1, CapsuleManifestV1, CompressionAlgorithm, ContentKind,
        Digest32, FileEntryV1, FileOperation, HEADER_SIZE_V1, KeyId, MAX_PRODUCER_NAME_BYTES,
        ProducerMetadata, ProtocolVersion, RelativeArtifactPath, SecurityLimits,
        SignatureAlgorithm,
    };

    use crate::{
        CodecError, DecodedCapsule, SignatureBytes, decode_capsule, encode_capsule, encode_manifest,
    };

    fn example() -> Result<DecodedCapsule, CodecError> {
        let manifest = CapsuleManifestV1 {
            capsule_name: None,
            description: None,
            producer: ProducerMetadata {
                name: BoundedString::<MAX_PRODUCER_NAME_BYTES>::new("tests", "producer")?,
                version: None,
            },
            files: vec![FileEntryV1 {
                path: RelativeArtifactPath::new("hello.txt")?,
                operation: FileOperation::CreateOrReplace,
                content_kind: ContentKind::TextUtf8,
                executable: false,
                offset: 0,
                size: 6,
                digest: Digest32([1; 32]),
            }],
        };
        let manifest_size = encode_manifest(&manifest)?.len();
        Ok(DecodedCapsule {
            header: CapsuleHeaderV1 {
                protocol_version: ProtocolVersion::V1,
                header_size: HEADER_SIZE_V1,
                flags: 0,
                compression: CompressionAlgorithm::None,
                signature: SignatureAlgorithm::Ed25519,
                manifest_size: u64::try_from(manifest_size)
                    .map_err(|_| CodecError::LengthOverflow)?,
                compressed_payload_size: 6,
                uncompressed_payload_size: 6,
                file_count: 1,
                publisher_key_id: KeyId([2; 32]),
            },
            manifest,
            compressed_payload: b"hello\n".to_vec(),
            capsule_digest: Digest32([3; 32]),
            signature: SignatureBytes([4; 64]),
        })
    }

    #[test]
    fn canonical_round_trip() -> Result<(), CodecError> {
        let capsule = example()?;
        let bytes = encode_capsule(&capsule)?;
        assert_eq!(decode_capsule(&bytes, &SecurityLimits::V1)?, capsule);
        assert_eq!(
            encode_capsule(&decode_capsule(&bytes, &SecurityLimits::V1)?)?,
            bytes
        );
        Ok(())
    }

    #[test]
    fn every_truncated_prefix_is_rejected() -> Result<(), CodecError> {
        let bytes = encode_capsule(&example()?)?;
        for length in 0..bytes.len() {
            assert!(decode_capsule(&bytes[..length], &SecurityLimits::V1).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_unknown_algorithm() -> Result<(), CodecError> {
        let mut bytes = encode_capsule(&example()?)?;
        bytes[12] = 255;
        assert!(matches!(
            decode_capsule(&bytes, &SecurityLimits::V1),
            Err(CodecError::Format(_))
        ));
        Ok(())
    }

    #[test]
    fn rejects_trailing_byte() -> Result<(), CodecError> {
        let mut bytes = encode_capsule(&example()?)?;
        bytes.push(0);
        assert_eq!(
            decode_capsule(&bytes, &SecurityLimits::V1),
            Err(CodecError::TrailingBytes)
        );
        Ok(())
    }
}
