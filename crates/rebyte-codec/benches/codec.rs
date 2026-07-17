//! Reproducible throughput baselines for the canonical RAP codec.

#![forbid(unsafe_code)]
#![allow(
    missing_docs,
    reason = "Criterion generates a public harness symbol which is not product API"
)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rebyte_codec::{CodecError, DecodedCapsule, SignatureBytes, decode_capsule, encode_capsule};
use rebyte_format::{
    BoundedString, CapsuleHeaderV1, CapsuleManifestV1, CompressionAlgorithm, ContentKind, Digest32,
    FileEntryV1, FileOperation, HEADER_SIZE_V1, KeyId, MAX_PRODUCER_NAME_BYTES, ProducerMetadata,
    ProtocolVersion, RelativeArtifactPath, SecurityLimits, SignatureAlgorithm,
};

fn canonical_codec(criterion: &mut Criterion) {
    let Ok(bytes) = fixture(1_048_576) else {
        return;
    };
    let mut group = criterion.benchmark_group("rap_v1_codec");
    group.throughput(Throughput::Bytes(1_048_576));
    group.bench_function("decode_1_mib", |bencher| {
        bencher.iter(|| decode_capsule(black_box(&bytes), black_box(&SecurityLimits::V1)));
    });
    group.finish();
}

fn fixture(payload_size: usize) -> Result<Vec<u8>, CodecError> {
    let payload_size = u64::try_from(payload_size).map_err(|_| CodecError::LengthOverflow)?;
    let manifest = CapsuleManifestV1 {
        capsule_name: None,
        description: None,
        producer: ProducerMetadata {
            name: BoundedString::<MAX_PRODUCER_NAME_BYTES>::new("benchmarks", "producer")?,
            version: None,
        },
        files: vec![FileEntryV1 {
            path: RelativeArtifactPath::new("payload.bin")?,
            operation: FileOperation::CreateOrReplace,
            content_kind: ContentKind::Binary,
            executable: false,
            offset: 0,
            size: payload_size,
            digest: Digest32([1; 32]),
        }],
    };
    let manifest_size = u64::try_from(rebyte_codec::encode_manifest(&manifest)?.len())
        .map_err(|_| CodecError::LengthOverflow)?;
    let payload_len = usize::try_from(payload_size).map_err(|_| CodecError::LengthOverflow)?;
    encode_capsule(&DecodedCapsule {
        header: CapsuleHeaderV1 {
            protocol_version: ProtocolVersion::V1,
            header_size: HEADER_SIZE_V1,
            flags: 0,
            compression: CompressionAlgorithm::None,
            signature: SignatureAlgorithm::Ed25519,
            manifest_size,
            compressed_payload_size: payload_size,
            uncompressed_payload_size: payload_size,
            file_count: 1,
            publisher_key_id: KeyId([2; 32]),
        },
        manifest,
        compressed_payload: vec![0x5a; payload_len],
        capsule_digest: Digest32([3; 32]),
        signature: SignatureBytes([4; 64]),
    })
}

criterion_group!(benches, canonical_codec);
criterion_main!(benches);
