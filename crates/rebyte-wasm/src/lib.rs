//! Browser-safe RAP v1 packing and structural inspection.

#![forbid(unsafe_code)]

use rebyte_codec::{DecodedCapsule, decode_capsule, decode_token, encode_manifest};
use rebyte_format::{CompressionAlgorithm, ContentKind, SecurityLimits};
use rebyte_pack::{ArtifactFile, PackOptions, UnsignedCapsule, pack};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Builds deterministic unsigned material without embedding any signing key.
///
/// `artifacts` is an array of `{ path, bytes, executable? }`; `options`
/// contains `producer` and optional `producerVersion`, `capsuleName` and
/// `description`. The returned object contains canonical manifest and payload
/// bytes for server-side revalidation and signing.
///
/// # Errors
///
/// Returns a `JavaScript` string error when inputs, paths, metadata or resource
/// limits are invalid.
#[wasm_bindgen]
pub fn pack_unsigned(artifacts: JsValue, options: JsValue) -> Result<JsValue, JsValue> {
    let artifacts: Vec<ArtifactInput> = from_js(artifacts)?;
    let options: PackInputOptions = from_js(options)?;
    let request = build_unsigned(artifacts, options).map_err(js_error)?;
    to_js(&request)
}

/// Returns bounded metadata from a canonical capsule without claiming trust.
///
/// Input is `{ kind: "binary", value: number[] }` or
/// `{ kind: "token", value: "rb1_..." }`.
///
/// # Errors
///
/// Returns a `JavaScript` string error for oversized, malformed or
/// non-canonical input.
#[wasm_bindgen]
pub fn inspect(input: JsValue) -> Result<JsValue, JsValue> {
    let input: CapsuleInput = from_js(input)?;
    let decoded = decode_input(input).map_err(js_error)?;
    to_js(&Inspection::from_decoded(&decoded))
}

/// Confirms bounded canonical RAP structure without signature or trust policy.
///
/// This export deliberately does not authenticate publishers or expose
/// filesystem behavior. Use native/server verification for trust decisions.
///
/// # Errors
///
/// Returns a `JavaScript` string error for oversized, malformed or
/// non-canonical input.
#[wasm_bindgen]
pub fn verify_structure(input: JsValue) -> Result<JsValue, JsValue> {
    let input: CapsuleInput = from_js(input)?;
    let decoded = decode_input(input).map_err(js_error)?;
    to_js(&StructureReport {
        schema_version: 1,
        valid: true,
        protocol_version: decoded.header.protocol_version.get(),
        files: decoded.header.file_count,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactInput {
    path: String,
    bytes: Vec<u8>,
    #[serde(default)]
    executable: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackInputOptions {
    producer: String,
    producer_version: Option<String>,
    capsule_name: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
enum CapsuleInput {
    Binary(Vec<u8>),
    Token(String),
}

#[derive(Debug)]
enum BuildError {
    Pack(rebyte_pack::PackError),
    Codec(rebyte_codec::CodecError),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pack(error) => error.fmt(formatter),
            Self::Codec(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<rebyte_pack::PackError> for BuildError {
    fn from(error: rebyte_pack::PackError) -> Self {
        Self::Pack(error)
    }
}

impl From<rebyte_codec::CodecError> for BuildError {
    fn from(error: rebyte_codec::CodecError) -> Self {
        Self::Codec(error)
    }
}

#[derive(Debug)]
enum InputError {
    Codec(rebyte_codec::CodecError),
}

impl core::fmt::Display for InputError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(formatter),
        }
    }
}

impl From<rebyte_codec::CodecError> for InputError {
    fn from(error: rebyte_codec::CodecError) -> Self {
        Self::Codec(error)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedRequest {
    schema_version: u16,
    protocol_version: u16,
    compression: &'static str,
    canonical_manifest: Vec<u8>,
    payload: Vec<u8>,
    uncompressed_payload_size: u64,
    files: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Inspection {
    schema_version: u16,
    protocol_version: u16,
    compression: &'static str,
    producer: String,
    file_count: u32,
    compressed_payload_size: u64,
    uncompressed_payload_size: u64,
    files: Vec<InspectionFile>,
    trust: &'static str,
}

impl Inspection {
    fn from_decoded(capsule: &DecodedCapsule) -> Self {
        Self {
            schema_version: 1,
            protocol_version: capsule.header.protocol_version.get(),
            compression: compression_name(capsule.header.compression),
            producer: capsule.manifest.producer.name.as_str().to_string(),
            file_count: capsule.header.file_count,
            compressed_payload_size: capsule.header.compressed_payload_size,
            uncompressed_payload_size: capsule.header.uncompressed_payload_size,
            files: capsule
                .manifest
                .files
                .iter()
                .map(|file| InspectionFile {
                    path: file.path.as_str().to_string(),
                    size: file.size,
                    executable: file.executable,
                    content_kind: match file.content_kind {
                        ContentKind::Binary => "binary",
                        ContentKind::TextUtf8 => "textUtf8",
                    },
                })
                .collect(),
            trust: "unverified",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectionFile {
    path: String,
    size: u64,
    executable: bool,
    content_kind: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StructureReport {
    schema_version: u16,
    valid: bool,
    protocol_version: u16,
    files: u32,
}

fn build_unsigned(
    inputs: Vec<ArtifactInput>,
    options: PackInputOptions,
) -> Result<UnsignedRequest, BuildError> {
    let artifacts = inputs
        .into_iter()
        .map(|input| {
            ArtifactFile::new(&input.path, input.bytes)
                .map(|file| file.with_executable(input.executable))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut pack_options = PackOptions::new(&options.producer)?;
    pack_options.compression = CompressionAlgorithm::None;
    if let Some(version) = options.producer_version {
        pack_options = pack_options.with_producer_version(&version)?;
    }
    if let Some(name) = options.capsule_name {
        pack_options = pack_options.with_capsule_name(&name)?;
    }
    if let Some(description) = options.description {
        pack_options = pack_options.with_description(&description)?;
    }
    let unsigned = pack(&artifacts, &pack_options)?;
    unsigned_request(unsigned)
}

fn unsigned_request(unsigned: UnsignedCapsule) -> Result<UnsignedRequest, BuildError> {
    let canonical_manifest = encode_manifest(&unsigned.manifest)?;
    Ok(UnsignedRequest {
        schema_version: 1,
        protocol_version: rebyte_format::PROTOCOL_VERSION,
        compression: compression_name(unsigned.compression),
        canonical_manifest,
        payload: unsigned.compressed_payload,
        uncompressed_payload_size: unsigned.uncompressed_payload_size,
        files: unsigned.manifest.files.len(),
    })
}

fn decode_input(input: CapsuleInput) -> Result<DecodedCapsule, InputError> {
    let bytes = match input {
        CapsuleInput::Binary(bytes) => bytes,
        CapsuleInput::Token(token) => decode_token(&token, &SecurityLimits::V1)?,
    };
    decode_capsule(&bytes, &SecurityLimits::V1).map_err(Into::into)
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(js_error)
}

fn to_js(value: &impl Serialize) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(js_error)
}

fn js_error(error: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

const fn compression_name(algorithm: CompressionAlgorithm) -> &'static str {
    match algorithm {
        CompressionAlgorithm::None => "none",
        CompressionAlgorithm::Zstd => "zstd",
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactInput, PackInputOptions, build_unsigned};

    #[test]
    fn unsigned_browser_request_is_uncompressed_and_sorted()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = build_unsigned(
            vec![
                ArtifactInput {
                    path: "z.txt".to_string(),
                    bytes: b"z".to_vec(),
                    executable: false,
                },
                ArtifactInput {
                    path: "a.bin".to_string(),
                    bytes: vec![0, 0xff],
                    executable: true,
                },
            ],
            PackInputOptions {
                producer: "wasm-tests".to_string(),
                producer_version: None,
                capsule_name: None,
                description: None,
            },
        )?;
        assert_eq!(request.compression, "none");
        assert_eq!(request.payload, [0, 0xff, b'z']);
        assert_eq!(request.files, 2);
        Ok(())
    }
}
