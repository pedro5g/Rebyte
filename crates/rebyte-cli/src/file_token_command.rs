//! Simple unsigned artifact CLI commands.

#![allow(clippy::redundant_pub_crate)]

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use rebyte_core::{
    ARTIFACT_TOKEN_PREFIX, Artifact, ArtifactCompression, ArtifactDictionary, ArtifactEntry,
    ArtifactEntryKind, ArtifactIoError, ArtifactKind, ArtifactOptions, ArtifactPathMetadata,
    ArtifactTokenError, CompressionProfile, DecodedArtifact, FileTokenError, StreamArtifactReport,
    decode_artifact, decode_artifact_file, decode_artifact_file_expected, decode_artifact_token,
    decode_file_token, encode_artifact, encode_artifact_path,
};
use rebyte_format::{CompressionAlgorithm, RelativeArtifactPath, SecurityLimits};
use serde::Serialize;

use super::security_io::{read_bounded_nofollow, sync_parent, write_new};
use super::{CliError, EXIT_DIGEST, EXIT_GENERIC, EXIT_MALFORMED, encode_digest, write_json};

const BINARY_MAGIC: &[u8; 4] = b"RBAT";

#[derive(Debug, Args)]
pub(super) struct EncodeCommand {
    /// File, directory or `-` for standard input.
    input: PathBuf,
    /// Compression strategy; `auto` keeps Zstandard only when smaller.
    #[arg(long, value_enum, default_value = "auto")]
    compression: CompressionArgument,
    /// Zstandard speed-versus-size policy.
    #[arg(long, value_enum, default_value = "balanced")]
    profile: ProfileArgument,
    /// Train an embedded dictionary only when it reduces total artifact size.
    #[arg(long, value_enum, default_value = "auto")]
    dictionary: DictionaryArgument,
    /// Embed the source basename as an untrusted reconstruction hint.
    #[arg(long)]
    include_name: bool,
    /// Embed this portable basename instead of the source basename.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
    /// Embed a portable relative destination hint.
    #[arg(long, value_name = "RELATIVE_PATH")]
    suggest_path: Option<String>,
    /// Emit an inline token or raw `.rba` binary envelope.
    #[arg(long, value_enum, default_value = "token")]
    format: RepresentationArgument,
    /// Resource bounds; `large` is streaming-only and must use binary format.
    #[arg(long, value_enum, default_value = "standard")]
    limits: ResourceLimitsArgument,
    /// Write into a new file instead of standard output.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Emit a stable JSON report; includes inline text when no output is used.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
pub(super) struct DecodeCommand {
    /// `ra1_`/legacy `rf1_` token, or `-` to read text from standard input.
    #[arg(value_name = "TOKEN", conflicts_with = "token_file")]
    token: Option<String>,
    /// Read an `ra1_`, legacy `rf1_` or binary `.rba` from a file.
    #[arg(long = "file", value_name = "PATH", conflicts_with = "token")]
    token_file: Option<PathBuf>,
    /// Exact output path; overrides all embedded destination metadata.
    #[arg(
        short,
        long,
        value_name = "PATH",
        conflicts_with_all = ["accept_suggested_path", "name"]
    )]
    output: Option<PathBuf>,
    /// Root below which an accepted relative destination will be reconstructed.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Explicitly allow use of the token's untrusted destination metadata.
    #[arg(long)]
    accept_suggested_path: bool,
    /// Override the final suggested basename.
    #[arg(
        long,
        value_name = "NAME",
        requires = "accept_suggested_path",
        conflicts_with = "output"
    )]
    name: Option<String>,
    /// Resource bounds for a binary `.rba`; inline text always stays standard.
    #[arg(long, value_enum, default_value = "standard")]
    limits: ResourceLimitsArgument,
    /// Emit a stable JSON report.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CompressionArgument {
    Auto,
    Zstd,
    None,
}

impl CompressionArgument {
    const fn to_policy(self) -> ArtifactCompression {
        match self {
            Self::Auto => ArtifactCompression::Auto,
            Self::Zstd => ArtifactCompression::Zstd,
            Self::None => ArtifactCompression::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ProfileArgument {
    Fast,
    Balanced,
    Maximum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum DictionaryArgument {
    Auto,
    None,
}

impl DictionaryArgument {
    const fn value(self) -> ArtifactDictionary {
        match self {
            Self::Auto => ArtifactDictionary::Auto,
            Self::None => ArtifactDictionary::None,
        }
    }
}

impl ProfileArgument {
    const fn to_profile(self) -> CompressionProfile {
        match self {
            Self::Fast => CompressionProfile::Fast,
            Self::Balanced => CompressionProfile::Balanced,
            Self::Maximum => CompressionProfile::Maximum,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RepresentationArgument {
    Token,
    Binary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ResourceLimitsArgument {
    Standard,
    Large,
}

impl ResourceLimitsArgument {
    const fn value(self) -> SecurityLimits {
        match self {
            Self::Standard => SecurityLimits::SIMPLE_ARTIFACT,
            Self::Large => SecurityLimits::LARGE_ARTIFACT,
        }
    }
}

impl RepresentationArgument {
    const fn name(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Binary => "binary",
        }
    }
}

pub(super) fn encode(command: &EncodeCommand) -> Result<(), CliError> {
    if command.format == RepresentationArgument::Binary && command.output.is_none() {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "--format binary requires --output to protect the terminal",
        ));
    }
    if command.limits == ResourceLimitsArgument::Large
        && command.format != RepresentationArgument::Binary
    {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "--limits large requires --format binary for bounded streaming",
        ));
    }
    if command.limits == ResourceLimitsArgument::Large && command.input.as_os_str() == "-" {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "--limits large requires a seekable file or directory input",
        ));
    }
    let limits = command.limits.value();
    let options = ArtifactOptions::default()
        .with_compression(command.compression.to_policy())
        .with_profile(command.profile.to_profile())
        .with_dictionary(command.dictionary.value())
        .with_limits(limits);
    if command.format == RepresentationArgument::Binary && command.input.as_os_str() != "-" {
        return encode_binary_path(command, &options);
    }
    let mut artifact = read_source(command, &limits)?;
    if let Some(name) = selected_name(command)? {
        artifact = artifact
            .with_suggested_name(&name)
            .map_err(artifact_encode_error)?;
    }
    if let Some(path) = &command.suggest_path {
        artifact =
            artifact.with_suggested_path(RelativeArtifactPath::new(path).map_err(|error| {
                CliError::new(EXIT_MALFORMED, format!("invalid suggested path: {error}"))
            })?);
    }
    let encoded = encode_artifact(&artifact, &options).map_err(artifact_encode_error)?;
    let token = if command.format == RepresentationArgument::Token {
        Some(
            encoded
                .to_token(&options.limits)
                .map_err(artifact_encode_error)?,
        )
    } else {
        None
    };
    if let Some(output) = &command.output {
        let bytes = token.as_ref().map_or_else(
            || encoded.binary().to_vec(),
            |value| {
                let mut bytes = Vec::with_capacity(value.len().saturating_add(1));
                bytes.extend_from_slice(value.as_bytes());
                bytes.push(b'\n');
                bytes
            },
        );
        write_new(output, &bytes, false).map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!(
                    "cannot create artifact output {}: {error}",
                    output.display()
                ),
            )
        })?;
    }

    let report = EncodeReport {
        schema_version: 2,
        kind: "unsignedArtifact",
        artifact_kind: artifact_kind_name(encoded.kind()),
        authenticated: false,
        content_digest: encode_digest(&encoded.content_digest()),
        envelope_digest: encode_digest(&encoded.envelope_digest()),
        entries: encoded.entry_count(),
        original_bytes: encoded.original_size(),
        stored_bytes: encoded.stored_size(),
        dictionary_bytes: encoded.dictionary_size(),
        representation: command.format.name(),
        output: command
            .output
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        token: if command.output.is_none() {
            token.as_deref()
        } else {
            None
        },
    };
    emit_encode_report(command, &report)
}

fn encode_binary_path(command: &EncodeCommand, options: &ArtifactOptions) -> Result<(), CliError> {
    let output = command
        .output
        .as_ref()
        .ok_or_else(|| CliError::new(EXIT_MALFORMED, "--format binary requires --output"))?;
    let mut metadata = ArtifactPathMetadata::new();
    if let Some(name) = selected_name(command)? {
        metadata = metadata
            .with_suggested_name(&name)
            .map_err(artifact_encode_error)?;
    }
    if let Some(path) = &command.suggest_path {
        metadata =
            metadata.with_suggested_path(RelativeArtifactPath::new(path).map_err(|error| {
                CliError::new(EXIT_MALFORMED, format!("invalid suggested path: {error}"))
            })?);
    }
    let streamed = encode_artifact_path(&command.input, output, &metadata, options)
        .map_err(|error| artifact_io_error(&error))?;
    let report = EncodeReport {
        schema_version: 2,
        kind: "unsignedArtifact",
        artifact_kind: artifact_kind_name(streamed.kind()),
        authenticated: false,
        content_digest: encode_digest(&streamed.content_digest()),
        envelope_digest: encode_digest(&streamed.envelope_digest()),
        entries: streamed.entry_count(),
        original_bytes: streamed.original_size(),
        stored_bytes: streamed.stored_size(),
        dictionary_bytes: streamed.dictionary_size(),
        representation: command.format.name(),
        output: Some(output.to_string_lossy().into_owned()),
        token: None,
    };
    emit_encode_report(command, &report)
}

fn emit_encode_report(command: &EncodeCommand, report: &EncodeReport<'_>) -> Result<(), CliError> {
    if command.json {
        write_json(report)
    } else if let Some(token) = report.token {
        println!("{token}");
        Ok(())
    } else {
        print_encode_report(report);
        Ok(())
    }
}

pub(super) fn decode(command: &DecodeCommand) -> Result<(), CliError> {
    if let Some(path) = command.token_file.as_deref()
        && is_binary_artifact_file(path)?
    {
        return decode_binary_command(command, path);
    }
    if command.limits == ResourceLimitsArgument::Large {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "--limits large is available only for binary .rba files",
        ));
    }
    match read_input(command)? {
        SimpleInput::LegacyToken(token) => decode_legacy(command, &token),
        SimpleInput::ArtifactToken(token) => {
            let decoded = decode_artifact_token(&token, &SecurityLimits::SIMPLE_ARTIFACT)
                .map_err(artifact_decode_error)?;
            decode_artifact_command(command, &decoded)
        }
        SimpleInput::ArtifactBinary(binary) => {
            let decoded = decode_artifact(&binary, &SecurityLimits::SIMPLE_ARTIFACT)
                .map_err(artifact_decode_error)?;
            decode_artifact_command(command, &decoded)
        }
    }
}

fn decode_binary_command(command: &DecodeCommand, input: &Path) -> Result<(), CliError> {
    let limits = command.limits.value();
    let (report, target) = if let Some(output) = &command.output {
        let report = decode_artifact_file(input, Some(output), &limits)
            .map_err(|error| artifact_io_error(&error))?;
        (report, Some(output.clone()))
    } else {
        let preview = decode_artifact_file(input, None, &limits)
            .map_err(|error| artifact_io_error(&error))?;
        let target =
            resolve_target_hints(command, preview.suggested_name(), preview.suggested_path())?;
        if let Some(target) = &target {
            let applied =
                decode_artifact_file_expected(input, target, &limits, &preview.envelope_digest())
                    .map_err(|error| artifact_io_error(&error))?;
            (applied, Some(target.clone()))
        } else {
            (preview, None)
        }
    };
    emit_stream_decode_report(command, &report, target)
}

fn emit_stream_decode_report(
    command: &DecodeCommand,
    streamed: &StreamArtifactReport,
    target: Option<PathBuf>,
) -> Result<(), CliError> {
    let written = target.is_some();
    let report = DecodeReport {
        schema_version: 2,
        kind: "unsignedArtifact",
        artifact_kind: artifact_kind_name(streamed.kind()),
        authenticated: false,
        integrity_verified: true,
        content_digest: encode_digest(&streamed.content_digest()),
        envelope_digest: encode_digest(&streamed.envelope_digest()),
        entries: streamed.entry_count(),
        reconstructed_bytes: streamed.original_size(),
        stored_bytes: streamed.stored_size(),
        dictionary_bytes: streamed.dictionary_size(),
        compression: compression_name(streamed.compression()),
        suggested_name: streamed.suggested_name(),
        suggested_path: streamed.suggested_path().map(RelativeArtifactPath::as_str),
        output: target.map(|path| path.to_string_lossy().into_owned()),
        written,
    };
    if command.json {
        write_json(&report)
    } else {
        print_decode_report(&report);
        Ok(())
    }
}

fn is_binary_artifact_file(path: &Path) -> Result<bool, CliError> {
    let mut file = File::open(path)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot open artifact: {error}")))?;
    let mut prefix = [0_u8; 4];
    let mut read = 0;
    while read < prefix.len() {
        let count = file.read(&mut prefix[read..]).map_err(|error| {
            CliError::new(EXIT_GENERIC, format!("cannot inspect artifact: {error}"))
        })?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(count)
            .ok_or_else(|| CliError::new(EXIT_GENERIC, "artifact length overflow"))?;
    }
    Ok(read == prefix.len() && &prefix == BINARY_MAGIC)
}

fn decode_artifact_command(
    command: &DecodeCommand,
    decoded: &DecodedArtifact,
) -> Result<(), CliError> {
    let target = resolve_target(command, decoded.artifact())?;
    if let Some(path) = &target {
        restore(decoded.artifact(), path)?;
    }
    let report = DecodeReport {
        schema_version: 2,
        kind: "unsignedArtifact",
        artifact_kind: artifact_kind_name(decoded.artifact().kind()),
        authenticated: false,
        integrity_verified: true,
        content_digest: encode_digest(&decoded.content_digest()),
        envelope_digest: encode_digest(&decoded.envelope_digest()),
        entries: u32::try_from(decoded.artifact().entries().len())
            .map_err(|_| CliError::new(EXIT_GENERIC, "artifact entry count overflow"))?,
        reconstructed_bytes: decoded.original_size(),
        stored_bytes: decoded.stored_size(),
        dictionary_bytes: decoded.dictionary_size(),
        compression: compression_name(decoded.compression()),
        suggested_name: decoded.artifact().suggested_name(),
        suggested_path: decoded
            .artifact()
            .suggested_path()
            .map(RelativeArtifactPath::as_str),
        output: target
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        written: target.is_some(),
    };
    if command.json {
        write_json(&report)
    } else {
        print_decode_report(&report);
        Ok(())
    }
}

fn decode_legacy(command: &DecodeCommand, token: &str) -> Result<(), CliError> {
    let output = command.output.as_ref().ok_or_else(|| {
        CliError::new(
            EXIT_MALFORMED,
            "legacy rf1_ tokens have no destination metadata; pass --output",
        )
    })?;
    let decoded =
        decode_file_token(token, &SecurityLimits::SIMPLE_ARTIFACT).map_err(legacy_decode_error)?;
    create_parent(output)?;
    write_new(output, decoded.bytes(), false).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create reconstructed file {}: {error}",
                output.display()
            ),
        )
    })?;
    if command.json {
        write_json(&LegacyDecodeReport {
            schema_version: 1,
            kind: "unsignedFileToken",
            authenticated: false,
            integrity_verified: true,
            digest: encode_digest(&decoded.digest()),
            reconstructed_bytes: decoded.original_size(),
            stored_bytes: decoded.stored_size(),
            compression: compression_name(decoded.compression()),
            output: output.to_string_lossy().into_owned(),
        })
    } else {
        println!(
            "{}",
            super::ui::success("✓ Legacy file token verified and reconstructed")
        );
        println!("  Output      {}", output.display());
        println!("  Bytes       {}", decoded.original_size());
        println!("  Digest      {}", encode_digest(&decoded.digest()));
        println!("  Authenticity unsigned · integrity only");
        Ok(())
    }
}

fn read_source(command: &EncodeCommand, limits: &SecurityLimits) -> Result<Artifact, CliError> {
    if command.input.as_os_str() == "-" {
        let bytes = read_bounded(io::stdin().lock(), limits.max_single_file_bytes)?;
        return Ok(Artifact::file(bytes, false));
    }
    let metadata = fs::symlink_metadata(&command.input).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot inspect artifact input: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "artifact input cannot be a symbolic link",
        ));
    }
    if metadata.is_file() {
        let bytes = read_bounded_nofollow(&command.input, limits.max_single_file_bytes).map_err(
            |error| CliError::new(EXIT_GENERIC, format!("cannot read artifact input: {error}")),
        )?;
        return Ok(Artifact::file(bytes, is_executable(&metadata)));
    }
    if metadata.is_dir() {
        let mut entries = Vec::new();
        collect_directory(&command.input, &command.input, &mut entries, limits)?;
        return Ok(Artifact::directory(entries));
    }
    Err(CliError::new(
        EXIT_MALFORMED,
        "artifact input must be a regular file or directory",
    ))
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<ArtifactEntry>,
    limits: &SecurityLimits,
) -> Result<(), CliError> {
    let iterator = fs::read_dir(directory).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot read directory {}: {error}", directory.display()),
        )
    })?;
    let mut children = iterator
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot read directory: {error}")))?;
    children.sort_by_key(fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot inspect {}: {error}", path.display()),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::new(
                EXIT_MALFORMED,
                format!("symbolic link is forbidden: {}", path.display()),
            ));
        }
        let portable = portable_relative(root, &path, limits)?;
        if metadata.is_dir() {
            push_entry(entries, ArtifactEntry::directory(portable), limits)?;
            collect_directory(root, &path, entries, limits)?;
        } else if metadata.is_file() {
            let bytes =
                read_bounded_nofollow(&path, limits.max_single_file_bytes).map_err(|error| {
                    CliError::new(
                        EXIT_GENERIC,
                        format!("cannot read artifact file {}: {error}", path.display()),
                    )
                })?;
            push_entry(
                entries,
                ArtifactEntry::file(portable, bytes, is_executable(&metadata)),
                limits,
            )?;
        } else {
            return Err(CliError::new(
                EXIT_MALFORMED,
                format!("unsupported filesystem entry: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn push_entry(
    entries: &mut Vec<ArtifactEntry>,
    entry: ArtifactEntry,
    limits: &SecurityLimits,
) -> Result<(), CliError> {
    let next = entries
        .len()
        .checked_add(1)
        .ok_or_else(|| CliError::new(EXIT_GENERIC, "artifact entry count overflow"))?;
    let next = u32::try_from(next)
        .map_err(|_| CliError::new(EXIT_GENERIC, "artifact entry count overflow"))?;
    if next > limits.max_file_count {
        return Err(CliError::new(
            EXIT_MALFORMED,
            format!(
                "artifact has more than {} filesystem entries",
                limits.max_file_count
            ),
        ));
    }
    entries.push(entry);
    Ok(())
}

fn portable_relative(
    root: &Path,
    path: &Path,
    limits: &SecurityLimits,
) -> Result<RelativeArtifactPath, CliError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| CliError::new(EXIT_MALFORMED, "artifact path escaped its source root"))?;
    let text = relative.to_str().ok_or_else(|| {
        CliError::new(
            EXIT_MALFORMED,
            format!("artifact path is not UTF-8: {}", path.display()),
        )
    })?;
    let portable = text.replace(std::path::MAIN_SEPARATOR, "/");
    RelativeArtifactPath::with_max_bytes(&portable, limits.max_path_bytes)
        .map_err(|error| CliError::new(EXIT_MALFORMED, format!("invalid artifact path: {error}")))
}

fn selected_name(command: &EncodeCommand) -> Result<Option<String>, CliError> {
    if let Some(name) = &command.name {
        return Ok(Some(name.clone()));
    }
    if !command.include_name {
        return Ok(None);
    }
    if command.input.as_os_str() == "-" {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "--include-name with stdin requires --name",
        ));
    }
    command
        .input
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| Some(value.to_string()))
        .ok_or_else(|| {
            CliError::new(
                EXIT_MALFORMED,
                "artifact source basename is absent or not UTF-8",
            )
        })
}

fn read_input(command: &DecodeCommand) -> Result<SimpleInput, CliError> {
    let bytes = if let Some(path) = &command.token_file {
        let maximum = SecurityLimits::SIMPLE_ARTIFACT
            .max_token_bytes
            .max(SecurityLimits::SIMPLE_ARTIFACT.max_capsule_bytes);
        read_bounded_nofollow(path, maximum).map_err(|error| {
            CliError::new(EXIT_GENERIC, format!("cannot read artifact: {error}"))
        })?
    } else {
        let token = command
            .token
            .as_deref()
            .ok_or_else(|| CliError::new(EXIT_MALFORMED, "TOKEN or --file is required"))?;
        if token == "-" {
            read_bounded(
                io::stdin().lock(),
                SecurityLimits::SIMPLE_ARTIFACT.max_token_bytes,
            )?
        } else {
            token.as_bytes().to_vec()
        }
    };
    if bytes.starts_with(BINARY_MAGIC) {
        return Ok(SimpleInput::ArtifactBinary(bytes));
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| CliError::new(EXIT_MALFORMED, "artifact token is not UTF-8"))?;
    let token = value
        .trim_matches(|character: char| character.is_ascii_whitespace())
        .to_string();
    if token.starts_with("rf1_") {
        Ok(SimpleInput::LegacyToken(token))
    } else if token.starts_with(ARTIFACT_TOKEN_PREFIX) {
        Ok(SimpleInput::ArtifactToken(token))
    } else {
        Err(CliError::new(
            EXIT_MALFORMED,
            "input is not an ra1_, rf1_ or binary .rba artifact",
        ))
    }
}

fn resolve_target(
    command: &DecodeCommand,
    artifact: &Artifact,
) -> Result<Option<PathBuf>, CliError> {
    resolve_target_hints(
        command,
        artifact.suggested_name(),
        artifact.suggested_path(),
    )
}

fn resolve_target_hints(
    command: &DecodeCommand,
    suggested_name: Option<&str>,
    suggested_path: Option<&RelativeArtifactPath>,
) -> Result<Option<PathBuf>, CliError> {
    if let Some(output) = &command.output {
        create_parent(output)?;
        return Ok(Some(output.clone()));
    }
    if !command.accept_suggested_path {
        return Ok(None);
    }
    let mut relative = suggested_path.map_or_else(
        || suggested_name.map_or_else(PathBuf::new, PathBuf::from),
        |path| portable_path(path.as_str()),
    );
    if let Some(name) = &command.name {
        validate_override_name(name)?;
        if relative.as_os_str().is_empty() {
            relative.push(name);
        } else {
            relative.set_file_name(name);
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "artifact has no suggested destination; pass --output or --name",
        ));
    }
    prepare_confined_target(&command.root, &relative).map(Some)
}

fn validate_override_name(value: &str) -> Result<(), CliError> {
    if value.contains('/') || value.contains('\\') {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "destination name must be one portable component",
        ));
    }
    RelativeArtifactPath::new(value)
        .map(|_| ())
        .map_err(|error| {
            CliError::new(EXIT_MALFORMED, format!("invalid destination name: {error}"))
        })
}

fn prepare_confined_target(root: &Path, relative: &Path) -> Result<PathBuf, CliError> {
    fs::create_dir_all(root).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot create artifact root {}: {error}", root.display()),
        )
    })?;
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot inspect artifact root {}: {error}", root.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "artifact root must be a real directory, not a symbolic link",
        ));
    }
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot resolve artifact root: {error}"),
        )
    })?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let mut current = canonical_root.clone();
    for component in parent.components() {
        let std::path::Component::Normal(value) = component else {
            return Err(CliError::new(
                EXIT_MALFORMED,
                "suggested destination contains an unsafe component",
            ));
        };
        current.push(value);
        match fs::symlink_metadata(&current) {
            Ok(item) if item.file_type().is_symlink() || !item.is_dir() => {
                return Err(CliError::new(
                    EXIT_MALFORMED,
                    format!(
                        "suggested destination crosses a non-directory or symlink: {}",
                        current.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|create_error| {
                    CliError::new(
                        EXIT_GENERIC,
                        format!("cannot create {}: {create_error}", current.display()),
                    )
                })?;
            }
            Err(error) => {
                return Err(CliError::new(
                    EXIT_GENERIC,
                    format!("cannot inspect {}: {error}", current.display()),
                ));
            }
        }
    }
    Ok(canonical_root.join(relative))
}

fn portable_path(value: &str) -> PathBuf {
    value.split('/').collect()
}

fn restore(artifact: &Artifact, target: &Path) -> Result<(), CliError> {
    if target.exists() {
        return Err(CliError::new(
            EXIT_GENERIC,
            format!("output already exists: {}", target.display()),
        ));
    }
    match artifact.kind() {
        ArtifactKind::File => restore_file(artifact, target),
        ArtifactKind::Directory => restore_directory(artifact, target),
    }
}

fn restore_file(artifact: &Artifact, target: &Path) -> Result<(), CliError> {
    let entry = artifact
        .entries()
        .first()
        .filter(|entry| entry.kind() == ArtifactEntryKind::File)
        .ok_or_else(|| CliError::new(EXIT_MALFORMED, "verified file artifact has no file"))?;
    create_parent(target)?;
    let parent = target
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".rebyte-artifact-")
        .tempfile_in(parent)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot stage artifact: {error}")))?;
    temporary.write_all(entry.bytes()).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot write staged artifact: {error}"),
        )
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot sync staged artifact: {error}"),
        )
    })?;
    set_executable(temporary.path(), entry.executable())?;
    temporary.persist_noclobber(target).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot commit reconstructed file: {}", error.error),
        )
    })?;
    sync_parent(target)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot sync output: {error}")))
}

fn restore_directory(artifact: &Artifact, target: &Path) -> Result<(), CliError> {
    create_parent(target)?;
    let parent = target
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".rebyte-artifact-")
        .tempdir_in(parent)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot stage directory: {error}")))?;
    for entry in artifact.entries() {
        let relative = entry
            .path()
            .ok_or_else(|| CliError::new(EXIT_MALFORMED, "directory entry has no path"))?;
        let destination = staging.path().join(portable_path(relative.as_str()));
        match entry.kind() {
            ArtifactEntryKind::Directory => {
                fs::create_dir_all(&destination).map_err(|error| {
                    CliError::new(
                        EXIT_GENERIC,
                        format!("cannot stage directory {}: {error}", relative.as_str()),
                    )
                })?;
            }
            ArtifactEntryKind::File => {
                create_parent(&destination)?;
                write_new(&destination, entry.bytes(), false).map_err(|error| {
                    CliError::new(
                        EXIT_GENERIC,
                        format!("cannot stage file {}: {error}", relative.as_str()),
                    )
                })?;
                set_executable(&destination, entry.executable())?;
            }
        }
    }
    let staging_path = staging.keep();
    if let Err(error) = fs::rename(&staging_path, target) {
        let _cleanup = fs::remove_dir_all(&staging_path);
        return Err(CliError::new(
            EXIT_GENERIC,
            format!("cannot commit reconstructed directory: {error}"),
        ));
    }
    sync_parent(target)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot sync output: {error}")))
}

fn create_parent(path: &Path) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create output directory {}: {error}",
                parent.display()
            ),
        )
    })
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
fn set_executable(path: &Path, executable: bool) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot read permissions: {error}")))?
        .permissions();
    let current = permissions.mode();
    let desired = if executable {
        current | 0o111
    } else {
        current & !0o111
    };
    permissions.set_mode(desired);
    fs::set_permissions(path, permissions)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot set permissions: {error}")))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<(), CliError> {
    Ok(())
}

fn read_bounded(mut reader: impl io::Read, maximum: u64) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot read stdin: {error}")))?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| CliError::new(EXIT_GENERIC, "input length overflow"))?;
    if length > maximum {
        return Err(CliError::new(
            EXIT_MALFORMED,
            format!("input has {length} bytes; maximum is {maximum}"),
        ));
    }
    Ok(bytes)
}

fn artifact_encode_error(error: ArtifactTokenError) -> CliError {
    CliError::new(EXIT_GENERIC, error.to_string())
}

fn artifact_io_error(error: &ArtifactIoError) -> CliError {
    let message = error.to_string();
    let exit_code = if matches!(
        error,
        ArtifactIoError::Format(
            ArtifactTokenError::EnvelopeDigestMismatch
                | ArtifactTokenError::ContentDigestMismatch
                | ArtifactTokenError::FileDigestMismatch
                | ArtifactTokenError::Compression(_)
        )
    ) {
        EXIT_DIGEST
    } else {
        EXIT_GENERIC
    };
    CliError::new(exit_code, message)
}

fn artifact_decode_error(error: ArtifactTokenError) -> CliError {
    let exit_code = if matches!(
        error,
        ArtifactTokenError::EnvelopeDigestMismatch
            | ArtifactTokenError::ContentDigestMismatch
            | ArtifactTokenError::FileDigestMismatch
            | ArtifactTokenError::Compression(_)
    ) {
        EXIT_DIGEST
    } else {
        EXIT_MALFORMED
    };
    CliError::new(exit_code, error.to_string())
}

fn legacy_decode_error(error: FileTokenError) -> CliError {
    let exit_code = if matches!(
        error,
        FileTokenError::DigestMismatch | FileTokenError::Compression(_)
    ) {
        EXIT_DIGEST
    } else {
        EXIT_MALFORMED
    };
    CliError::new(exit_code, error.to_string())
}

const fn artifact_kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::File => "file",
        ArtifactKind::Directory => "directory",
    }
}

const fn compression_name(compression: CompressionAlgorithm) -> &'static str {
    match compression {
        CompressionAlgorithm::None => "none",
        CompressionAlgorithm::Zstd => "zstd",
    }
}

fn print_encode_report(report: &EncodeReport<'_>) {
    println!(
        "{}",
        super::ui::success("✓ Unsigned artifact encoded and self-verified")
    );
    println!("  Type        {}", report.artifact_kind);
    println!("  Entries     {}", report.entries);
    println!("  Input       {} bytes", report.original_bytes);
    println!("  Stored      {} bytes", report.stored_bytes);
    if report.dictionary_bytes != 0 {
        println!("  Dictionary  {} bytes · embedded", report.dictionary_bytes);
    }
    println!("  Format      {}", report.representation);
    println!("  Content ID  {}", report.content_digest);
    if let Some(output) = &report.output {
        println!("  Output      {output}");
    }
    println!("  Authenticity unsigned · integrity only");
}

fn print_decode_report(report: &DecodeReport<'_>) {
    println!(
        "{}",
        super::ui::success("✓ Unsigned artifact fully verified")
    );
    println!("  Type        {}", report.artifact_kind);
    println!("  Entries     {}", report.entries);
    println!("  Bytes       {}", report.reconstructed_bytes);
    println!("  Compression {}", report.compression);
    if report.dictionary_bytes != 0 {
        println!("  Dictionary  {} bytes · verified", report.dictionary_bytes);
    }
    println!("  Content ID  {}", report.content_digest);
    if let Some(name) = report.suggested_name {
        println!("  Name hint   {name}");
    }
    if let Some(path) = report.suggested_path {
        println!("  Path hint   {path}");
    }
    if let Some(output) = &report.output {
        println!("  Output      {output}");
    } else {
        println!("  No files written");
        println!("  Pass --output, or explicitly use --accept-suggested-path.");
    }
    println!("  Authenticity unsigned · integrity only");
}

enum SimpleInput {
    LegacyToken(String),
    ArtifactToken(String),
    ArtifactBinary(Vec<u8>),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncodeReport<'a> {
    schema_version: u16,
    kind: &'static str,
    artifact_kind: &'static str,
    authenticated: bool,
    content_digest: String,
    envelope_digest: String,
    entries: u32,
    original_bytes: u64,
    stored_bytes: u64,
    dictionary_bytes: u32,
    representation: &'static str,
    output: Option<String>,
    token: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecodeReport<'a> {
    schema_version: u16,
    kind: &'static str,
    artifact_kind: &'static str,
    authenticated: bool,
    integrity_verified: bool,
    content_digest: String,
    envelope_digest: String,
    entries: u32,
    reconstructed_bytes: u64,
    stored_bytes: u64,
    dictionary_bytes: u32,
    compression: &'static str,
    suggested_name: Option<&'a str>,
    suggested_path: Option<&'a str>,
    output: Option<String>,
    written: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyDecodeReport {
    schema_version: u16,
    kind: &'static str,
    authenticated: bool,
    integrity_verified: bool,
    digest: String,
    reconstructed_bytes: u64,
    stored_bytes: u64,
    compression: &'static str,
    output: String,
}
