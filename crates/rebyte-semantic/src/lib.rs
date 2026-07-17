// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded semantic patches for JSON and TOML configuration.
//!
//! A patch performs data-model operations and never executes code. JSON uses
//! RFC 6901 pointer syntax. TOML supports table-key pointers while preserving
//! formatting and comments outside values that are deliberately replaced.

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::{BTreeMap, HashSet};

use rebyte_format::Digest32;
use rebyte_integrity::{digest_matches, file_digest};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;
use toml_edit::{DocumentMut, Item};

/// Maximum accepted semantic patch document size.
pub const MAX_PATCH_BYTES: u64 = 2 * 1_024 * 1_024;
/// Maximum operations in one semantic patch.
pub const MAX_OPERATIONS: usize = 512;
/// Maximum decoded JSON Pointer length.
pub const MAX_POINTER_BYTES: usize = 1_024;
/// Maximum JSON Pointer component count.
pub const MAX_POINTER_DEPTH: usize = 64;

/// Structured target syntax.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PatchFormat {
    /// Strict JSON with duplicate object keys rejected.
    Json,
    /// TOML edited through its syntax tree to retain surrounding presentation.
    Toml,
}

/// One deterministic semantic operation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
#[non_exhaustive]
pub enum PatchOperation {
    /// Require the current semantic value to equal `value`.
    Test {
        /// RFC 6901 JSON Pointer.
        path: String,
        /// Required semantic value.
        value: JsonValue,
    },
    /// Insert or replace a value under an existing parent.
    Set {
        /// RFC 6901 JSON Pointer.
        path: String,
        /// New semantic value.
        value: JsonValue,
    },
    /// Remove an existing object member or array element.
    Remove {
        /// RFC 6901 JSON Pointer.
        path: String,
    },
}

impl PatchOperation {
    /// Returns the encoded RFC 6901 pointer.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Test { path, .. } | Self::Set { path, .. } | Self::Remove { path } => path,
        }
    }
}

/// Versioned semantic patch document.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticPatch {
    schema_version: u16,
    format: PatchFormat,
    target_digest: Option<String>,
    operations: Vec<PatchOperation>,
}

impl SemanticPatch {
    /// Constructs and validates one version-1 semantic patch.
    ///
    /// # Errors
    ///
    /// Returns [`SemanticError`] for an unsupported version, malformed digest,
    /// invalid pointer or excessive operation count.
    pub fn new(
        format: PatchFormat,
        target_digest: Option<String>,
        operations: Vec<PatchOperation>,
    ) -> Result<Self, SemanticError> {
        let patch = Self {
            schema_version: 1,
            format,
            target_digest,
            operations,
        };
        patch.validate()?;
        Ok(patch)
    }

    /// Returns the document schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the required target syntax.
    #[must_use]
    pub const fn format(&self) -> PatchFormat {
        self.format
    }

    /// Returns the optional lowercase RAP file-domain precondition.
    #[must_use]
    pub fn target_digest(&self) -> Option<&str> {
        self.target_digest.as_deref()
    }

    /// Returns ordered semantic operations.
    #[must_use]
    pub fn operations(&self) -> &[PatchOperation] {
        &self.operations
    }

    /// Serializes a stable, human-reviewable patch document.
    ///
    /// # Errors
    ///
    /// Returns [`SemanticError::InvalidPatch`] if serialization fails.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SemanticError> {
        let mut output =
            serde_json::to_vec_pretty(self).map_err(|_| SemanticError::InvalidPatch)?;
        output.push(b'\n');
        Ok(output)
    }

    fn validate(&self) -> Result<(), SemanticError> {
        if self.schema_version != 1 {
            return Err(SemanticError::UnsupportedVersion(self.schema_version));
        }
        if self.operations.is_empty() || self.operations.len() > MAX_OPERATIONS {
            return Err(SemanticError::OperationLimit);
        }
        if let Some(value) = &self.target_digest {
            decode_digest(value)?;
        }
        for operation in &self.operations {
            let components = parse_pointer(operation.path())?;
            if self.format == PatchFormat::Toml
                && (components.is_empty()
                    || components
                        .iter()
                        .any(|component| component == "-" || component.parse::<usize>().is_ok()))
            {
                return Err(SemanticError::UnsupportedTomlPath);
            }
        }
        Ok(())
    }
}

/// Verified result of applying every semantic operation in memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticPatchResult {
    bytes: Vec<u8>,
    before_digest: Digest32,
    after_digest: Digest32,
    changed: bool,
    operations_applied: u32,
}

impl SemanticPatchResult {
    /// Returns the reconstructed target bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the report and returns reconstructed target bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the verified original RAP file digest.
    #[must_use]
    pub const fn before_digest(&self) -> Digest32 {
        self.before_digest
    }

    /// Returns the RAP file digest after semantic serialization.
    #[must_use]
    pub const fn after_digest(&self) -> Digest32 {
        self.after_digest
    }

    /// Returns whether output bytes differ from input bytes.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }

    /// Returns the number of successful ordered operations.
    #[must_use]
    pub const fn operations_applied(&self) -> u32 {
        self.operations_applied
    }
}

/// Semantic parsing, policy or operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SemanticError {
    /// Patch bytes exceeded the fixed document limit.
    PatchTooLarge,
    /// Patch JSON was malformed, duplicated a key or violated its schema.
    InvalidPatch,
    /// Patch schema version is unsupported.
    UnsupportedVersion(u16),
    /// Patch contained zero or too many operations.
    OperationLimit,
    /// A pointer was malformed, too deep or too long.
    InvalidPointer,
    /// The optional target digest was not canonical lowercase hexadecimal.
    InvalidDigest,
    /// Original target bytes did not match the patch precondition.
    TargetDigestMismatch,
    /// Target JSON was malformed or contained duplicate object keys.
    InvalidJson,
    /// Target TOML was malformed.
    InvalidToml,
    /// A pointer parent or selected value did not exist.
    MissingPath,
    /// A pointer tried to traverse a scalar or used an invalid array index.
    TypeConflict,
    /// A `test` operation did not match the current semantic value.
    TestFailed,
    /// TOML patches currently address table keys, not root or array indexes.
    UnsupportedTomlPath,
    /// A JSON value cannot be represented by TOML.
    UnsupportedTomlValue,
    /// A checked length conversion overflowed.
    LengthOverflow,
}

impl fmt::Display for SemanticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatchTooLarge => formatter.write_str("semantic patch exceeds its size limit"),
            Self::InvalidPatch => formatter.write_str("semantic patch document is invalid"),
            Self::UnsupportedVersion(value) => {
                write!(formatter, "unsupported semantic patch version {value}")
            }
            Self::OperationLimit => formatter.write_str("semantic patch operation limit violated"),
            Self::InvalidPointer => formatter.write_str("semantic patch pointer is invalid"),
            Self::InvalidDigest => formatter.write_str("semantic patch digest is invalid"),
            Self::TargetDigestMismatch => {
                formatter.write_str("semantic patch target digest mismatch")
            }
            Self::InvalidJson => formatter.write_str("semantic patch target is invalid JSON"),
            Self::InvalidToml => formatter.write_str("semantic patch target is invalid TOML"),
            Self::MissingPath => formatter.write_str("semantic patch path does not exist"),
            Self::TypeConflict => formatter.write_str("semantic patch path has a type conflict"),
            Self::TestFailed => formatter.write_str("semantic patch test operation failed"),
            Self::UnsupportedTomlPath => {
                formatter.write_str("semantic TOML patches support table-key pointers only")
            }
            Self::UnsupportedTomlValue => {
                formatter.write_str("semantic patch value cannot be represented in TOML")
            }
            Self::LengthOverflow => formatter.write_str("semantic patch length overflow"),
        }
    }
}

impl std::error::Error for SemanticError {}

/// Parses and validates a bounded semantic patch document.
///
/// # Errors
///
/// Returns [`SemanticError`] for oversized bytes, duplicate JSON keys,
/// malformed JSON or an invalid patch schema.
pub fn parse_patch(bytes: &[u8]) -> Result<SemanticPatch, SemanticError> {
    if u64::try_from(bytes.len()).map_err(|_| SemanticError::LengthOverflow)? > MAX_PATCH_BYTES {
        return Err(SemanticError::PatchTooLarge);
    }
    let strict: StrictJson =
        serde_json::from_slice(bytes).map_err(|_| SemanticError::InvalidPatch)?;
    let patch = serde_json::from_value(strict.0).map_err(|_| SemanticError::InvalidPatch)?;
    SemanticPatch::validate(&patch)?;
    Ok(patch)
}

/// Applies a validated patch to bounded target bytes entirely in memory.
///
/// The optional digest precondition and every `test` operation pass before
/// output is returned.
///
/// # Errors
///
/// Returns [`SemanticError`] for invalid target syntax, failed preconditions,
/// missing paths, type conflicts or unsupported TOML values.
pub fn apply_semantic_patch(
    patch: &SemanticPatch,
    target: &[u8],
) -> Result<SemanticPatchResult, SemanticError> {
    patch.validate()?;
    let before_digest = file_digest(target);
    if let Some(expected) = patch.target_digest.as_deref() {
        let expected = decode_digest(expected)?;
        if !digest_matches(&expected, &before_digest) {
            return Err(SemanticError::TargetDigestMismatch);
        }
    }
    let bytes = match patch.format {
        PatchFormat::Json => apply_json(target, &patch.operations)?,
        PatchFormat::Toml => apply_toml(target, &patch.operations)?,
    };
    let operations_applied =
        u32::try_from(patch.operations.len()).map_err(|_| SemanticError::LengthOverflow)?;
    Ok(SemanticPatchResult {
        changed: bytes != target,
        after_digest: file_digest(&bytes),
        before_digest,
        bytes,
        operations_applied,
    })
}

fn apply_json(target: &[u8], operations: &[PatchOperation]) -> Result<Vec<u8>, SemanticError> {
    let strict: StrictJson =
        serde_json::from_slice(target).map_err(|_| SemanticError::InvalidJson)?;
    let mut root = strict.0;
    apply_operations(&mut root, operations)?;
    let mut output = serde_json::to_vec_pretty(&root).map_err(|_| SemanticError::InvalidJson)?;
    output.push(b'\n');
    Ok(output)
}

fn apply_toml(target: &[u8], operations: &[PatchOperation]) -> Result<Vec<u8>, SemanticError> {
    let text = core::str::from_utf8(target).map_err(|_| SemanticError::InvalidToml)?;
    let mut document = text
        .parse::<DocumentMut>()
        .map_err(|_| SemanticError::InvalidToml)?;
    let mut mirror =
        toml_edit::de::from_str::<JsonValue>(text).map_err(|_| SemanticError::InvalidToml)?;
    apply_operations(&mut mirror, operations)?;
    for operation in operations {
        match operation {
            PatchOperation::Test { .. } => {}
            PatchOperation::Set { path, value } => {
                let components = parse_pointer(path)?;
                let item = json_to_toml_item(value)?;
                toml_set(document.as_table_mut(), &components, item)?;
            }
            PatchOperation::Remove { path } => {
                let components = parse_pointer(path)?;
                toml_remove(document.as_table_mut(), &components)?;
            }
        }
    }
    Ok(document.to_string().into_bytes())
}

fn apply_operations(
    root: &mut JsonValue,
    operations: &[PatchOperation],
) -> Result<(), SemanticError> {
    for operation in operations {
        let components = parse_pointer(operation.path())?;
        match operation {
            PatchOperation::Test { value, .. } => {
                if pointer_get(root, &components)? != value {
                    return Err(SemanticError::TestFailed);
                }
            }
            PatchOperation::Set { value, .. } => {
                pointer_set(root, &components, value.clone())?;
            }
            PatchOperation::Remove { .. } => {
                pointer_remove(root, &components)?;
            }
        }
    }
    Ok(())
}

fn pointer_get<'a>(
    mut current: &'a JsonValue,
    components: &[String],
) -> Result<&'a JsonValue, SemanticError> {
    for component in components {
        current = match current {
            JsonValue::Object(map) => map.get(component).ok_or(SemanticError::MissingPath)?,
            JsonValue::Array(values) => values
                .get(parse_array_index(component, values.len(), false)?)
                .ok_or(SemanticError::MissingPath)?,
            _ => return Err(SemanticError::TypeConflict),
        };
    }
    Ok(current)
}

fn pointer_parent_mut<'a>(
    mut current: &'a mut JsonValue,
    components: &[String],
) -> Result<(&'a mut JsonValue, String), SemanticError> {
    let (last, parents) = components
        .split_last()
        .ok_or(SemanticError::InvalidPointer)?;
    for component in parents {
        current = match current {
            JsonValue::Object(map) => map.get_mut(component).ok_or(SemanticError::MissingPath)?,
            JsonValue::Array(values) => {
                let index = parse_array_index(component, values.len(), false)?;
                values.get_mut(index).ok_or(SemanticError::MissingPath)?
            }
            _ => return Err(SemanticError::TypeConflict),
        };
    }
    Ok((current, last.clone()))
}

fn pointer_set(
    root: &mut JsonValue,
    components: &[String],
    value: JsonValue,
) -> Result<(), SemanticError> {
    if components.is_empty() {
        *root = value;
        return Ok(());
    }
    let (parent, last) = pointer_parent_mut(root, components)?;
    match parent {
        JsonValue::Object(map) => {
            map.insert(last, value);
            Ok(())
        }
        JsonValue::Array(values) if last == "-" => {
            values.push(value);
            Ok(())
        }
        JsonValue::Array(values) => {
            let index = parse_array_index(&last, values.len(), false)?;
            let slot = values.get_mut(index).ok_or(SemanticError::MissingPath)?;
            *slot = value;
            Ok(())
        }
        _ => Err(SemanticError::TypeConflict),
    }
}

fn pointer_remove(root: &mut JsonValue, components: &[String]) -> Result<(), SemanticError> {
    let (parent, last) = pointer_parent_mut(root, components)?;
    match parent {
        JsonValue::Object(map) => map
            .remove(&last)
            .map(|_| ())
            .ok_or(SemanticError::MissingPath),
        JsonValue::Array(values) => {
            let index = parse_array_index(&last, values.len(), false)?;
            if index >= values.len() {
                return Err(SemanticError::MissingPath);
            }
            values.remove(index);
            Ok(())
        }
        _ => Err(SemanticError::TypeConflict),
    }
}

fn parse_array_index(value: &str, length: usize, append: bool) -> Result<usize, SemanticError> {
    if value == "-" && append {
        return Ok(length);
    }
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(SemanticError::TypeConflict);
    }
    value
        .parse::<usize>()
        .map_err(|_| SemanticError::TypeConflict)
}

fn parse_pointer(value: &str) -> Result<Vec<String>, SemanticError> {
    if value.len() > MAX_POINTER_BYTES {
        return Err(SemanticError::InvalidPointer);
    }
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let body = value
        .strip_prefix('/')
        .ok_or(SemanticError::InvalidPointer)?;
    let mut components = Vec::new();
    for raw in body.split('/') {
        let mut decoded = String::with_capacity(raw.len());
        let mut characters = raw.chars();
        while let Some(character) = characters.next() {
            if character != '~' {
                decoded.push(character);
                continue;
            }
            match characters.next() {
                Some('0') => decoded.push('~'),
                Some('1') => decoded.push('/'),
                _ => return Err(SemanticError::InvalidPointer),
            }
        }
        components.push(decoded);
        if components.len() > MAX_POINTER_DEPTH {
            return Err(SemanticError::InvalidPointer);
        }
    }
    Ok(components)
}

fn toml_set(
    table: &mut dyn toml_edit::TableLike,
    components: &[String],
    mut item: Item,
) -> Result<(), SemanticError> {
    let (last, parents) = components
        .split_last()
        .ok_or(SemanticError::UnsupportedTomlPath)?;
    let mut current = table;
    for component in parents {
        let child = current
            .get_mut(component)
            .ok_or(SemanticError::MissingPath)?;
        current = child
            .as_table_like_mut()
            .ok_or(SemanticError::TypeConflict)?;
    }
    if let Some(existing) = current.get(last)
        && let (Some(previous), Some(replacement)) = (existing.as_value(), item.as_value_mut())
    {
        *replacement.decor_mut() = previous.decor().clone();
    }
    current.insert(last, item);
    Ok(())
}

fn toml_remove(
    table: &mut dyn toml_edit::TableLike,
    components: &[String],
) -> Result<(), SemanticError> {
    let (last, parents) = components
        .split_last()
        .ok_or(SemanticError::UnsupportedTomlPath)?;
    let mut current = table;
    for component in parents {
        let child = current
            .get_mut(component)
            .ok_or(SemanticError::MissingPath)?;
        current = child
            .as_table_like_mut()
            .ok_or(SemanticError::TypeConflict)?;
    }
    current
        .remove(last)
        .map(|_| ())
        .ok_or(SemanticError::MissingPath)
}

fn json_to_toml_item(value: &JsonValue) -> Result<Item, SemanticError> {
    let mut wrapper = BTreeMap::new();
    wrapper.insert("value", value);
    let mut document =
        toml_edit::ser::to_document(&wrapper).map_err(|_| SemanticError::UnsupportedTomlValue)?;
    document
        .as_table_mut()
        .remove("value")
        .ok_or(SemanticError::UnsupportedTomlValue)
}

fn decode_digest(value: &str) -> Result<Digest32, SemanticError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(SemanticError::InvalidDigest);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    Ok(Digest32(bytes))
}

const fn hex_value(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

struct StrictJson(JsonValue);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor).map(Self)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJson(value)) = sequence.next_element::<StrictJson>()? {
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let StrictJson(value) = map.next_value::<StrictJson>()?;
            values.insert(key, value);
        }
        Ok(JsonValue::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rebyte_integrity::file_digest;
    use serde_json::json;

    use super::{
        PatchFormat, PatchOperation, SemanticError, SemanticPatch, apply_semantic_patch,
        parse_patch,
    };

    #[test]
    fn json_test_set_remove_and_arrays_are_ordered() -> Result<(), SemanticError> {
        let source = br#"{"server":{"port":80,"old":true},"names":["a","b"]}"#;
        let patch = SemanticPatch::new(
            PatchFormat::Json,
            None,
            vec![
                PatchOperation::Test {
                    path: "/server/port".into(),
                    value: json!(80),
                },
                PatchOperation::Set {
                    path: "/server/port".into(),
                    value: json!(8080),
                },
                PatchOperation::Remove {
                    path: "/server/old".into(),
                },
                PatchOperation::Set {
                    path: "/names/-".into(),
                    value: json!("c"),
                },
            ],
        )?;
        let result = apply_semantic_patch(&patch, source)?;
        let value: serde_json::Value =
            serde_json::from_slice(result.bytes()).map_err(|_| SemanticError::InvalidJson)?;
        assert_eq!(value["server"]["port"], 8080);
        assert!(value["server"].get("old").is_none());
        assert_eq!(value["names"], json!(["a", "b", "c"]));
        Ok(())
    }

    #[test]
    fn toml_preserves_comments_while_setting_logical_key() -> Result<(), SemanticError> {
        let source = b"# deployment\n[server]\nport = 80 # keep this note\nhost = \"localhost\"\n";
        let patch = SemanticPatch::new(
            PatchFormat::Toml,
            None,
            vec![PatchOperation::Set {
                path: "/server/port".into(),
                value: json!(8080),
            }],
        )?;
        let result = apply_semantic_patch(&patch, source)?;
        let text = core::str::from_utf8(result.bytes()).map_err(|_| SemanticError::InvalidToml)?;
        assert!(text.contains("# deployment"));
        assert!(text.contains("port = 8080 # keep this note"));
        assert!(text.contains("host = \"localhost\""));
        Ok(())
    }

    #[test]
    fn digest_test_and_duplicate_keys_fail_closed() -> Result<(), SemanticError> {
        let source = br#"{"enabled":true}"#;
        let wrong = SemanticPatch::new(
            PatchFormat::Json,
            Some("00".repeat(32)),
            vec![PatchOperation::Set {
                path: "/enabled".into(),
                value: json!(false),
            }],
        )?;
        assert_eq!(
            apply_semantic_patch(&wrong, source),
            Err(SemanticError::TargetDigestMismatch)
        );
        let correct = SemanticPatch::new(
            PatchFormat::Json,
            Some(hex(file_digest(source).as_bytes())),
            vec![PatchOperation::Test {
                path: "/enabled".into(),
                value: json!(false),
            }],
        )?;
        assert_eq!(
            apply_semantic_patch(&correct, source),
            Err(SemanticError::TestFailed)
        );
        assert_eq!(
            parse_patch(br#"{"schemaVersion":1,"format":"json","format":"toml","operations":[]}"#),
            Err(SemanticError::InvalidPatch)
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn json_scalar_set_is_idempotent(value in any::<i64>()) {
            let patch = SemanticPatch::new(
                PatchFormat::Json,
                None,
                vec![PatchOperation::Set {
                    path: "/value".into(),
                    value: json!(value),
                }],
            );
            prop_assert!(patch.is_ok());
            if let Ok(patch) = patch {
                let first = apply_semantic_patch(&patch, br#"{"value":0,"untouched":true}"#);
                prop_assert!(first.is_ok());
                if let Ok(first) = first {
                    let second = apply_semantic_patch(&patch, first.bytes());
                    prop_assert!(second.is_ok());
                    if let Ok(second) = second {
                        prop_assert_eq!(second.bytes(), first.bytes());
                        prop_assert!(!second.changed());
                    }
                }
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }
}
