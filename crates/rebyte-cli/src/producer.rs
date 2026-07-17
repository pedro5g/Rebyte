//! Capability-confined directory packing and local signing.

#![allow(clippy::redundant_pub_crate)]

use std::io::Read as _;
use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use clap::{Args, ValueEnum};
use rebyte_core::{CapsuleInput, VerificationPolicy, sign_capsule, verify_capsule};
use rebyte_format::{CompressionAlgorithm, SecurityLimits};
use rebyte_pack::{ArtifactFile, PackOptions, pack};
use rebyte_signature::{KeyStatus, Signer as _, TrustChannel, TrustedKeyring, TrustedPublicKey};
use serde::Serialize;

use super::keys::{PassphraseArgs, load_local_signer};
use super::security_io::write_new;
use super::{CliError, EXIT_GENERIC, EXIT_POLICY, encode_digest, encode_key_id, write_json};

const MAX_DIRECTORY_DEPTH: usize = 128;

#[derive(Debug, Args)]
pub(super) struct PackCommand {
    /// Source directory reconstructed by the capsule.
    #[arg(long, value_name = "DIR", default_value = ".")]
    root: PathBuf,
    /// Encrypted private key created by `rebyte key generate`.
    #[arg(long, value_name = "PATH")]
    private_key: PathBuf,
    /// Destination `.rbc` or token-text file; existing files are not overwritten.
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,
    /// Signed producer identity (for example, an application or build pipeline).
    #[arg(long, value_name = "NAME")]
    producer: String,
    /// Optional signed producer version.
    #[arg(long, value_name = "VERSION")]
    producer_version: Option<String>,
    /// Optional signed capsule name.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
    /// Optional signed capsule description.
    #[arg(long, value_name = "TEXT")]
    description: Option<String>,
    /// Deterministic payload compression.
    #[arg(long, value_enum, default_value = "zstd")]
    compression: CompressionArgument,
    /// Output transport representation.
    #[arg(long, value_enum, default_value = "binary")]
    format: OutputFormat,
    #[command(flatten)]
    passphrase: PassphraseArgs,
    /// Emit a stable JSON report after writing the capsule.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CompressionArgument {
    Zstd,
    None,
}

impl CompressionArgument {
    const fn to_algorithm(self) -> CompressionAlgorithm {
        match self {
            Self::Zstd => CompressionAlgorithm::Zstd,
            Self::None => CompressionAlgorithm::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Binary,
    Token,
}

pub(super) fn run(command: &PackCommand) -> Result<(), CliError> {
    let artifacts = collect_artifacts(&command.root)?;
    if artifacts.is_empty() {
        return Err(CliError::new(
            EXIT_GENERIC,
            "source directory contains no files",
        ));
    }
    let mut options = PackOptions::new(&command.producer)
        .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    options.compression = command.compression.to_algorithm();
    if let Some(version) = &command.producer_version {
        options = options
            .with_producer_version(version)
            .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    }
    if let Some(name) = &command.name {
        options = options
            .with_capsule_name(name)
            .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    }
    if let Some(description) = &command.description {
        options = options
            .with_description(description)
            .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    }
    let unsigned = pack(&artifacts, &options)
        .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    let (signer, key_id) = load_local_signer(&command.private_key, &command.passphrase)?;
    let envelope = sign_capsule(&unsigned, &signer)
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;

    // Self-verification catches storage, codec and signing integration errors
    // before the newly created artifact is made visible to a publisher.
    let trusted = TrustedPublicKey::new(
        "local pack self-check",
        signer.public_key(),
        TrustChannel::Production,
        KeyStatus::Active,
    )
    .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    let keyring = TrustedKeyring::new(vec![trusted])
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    let verified = verify_capsule(
        CapsuleInput::Binary(envelope.as_bytes()),
        &VerificationPolicy::PRODUCTION,
        &keyring,
    )
    .map_err(super::CliError::verification)?;

    let output_bytes = match command.format {
        OutputFormat::Binary => envelope.as_bytes().to_vec(),
        OutputFormat::Token => {
            let mut bytes = envelope.to_token().into_bytes();
            bytes.push(b'\n');
            bytes
        }
    };
    write_new(&command.output, &output_bytes, false).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create capsule {}: {error}",
                command.output.display()
            ),
        )
    })?;
    let source_bytes = artifacts.iter().try_fold(0_u64, |total, artifact| {
        let length = u64::try_from(artifact.bytes.len())
            .map_err(|_| CliError::new(EXIT_GENERIC, "source length overflow"))?;
        total
            .checked_add(length)
            .ok_or_else(|| CliError::new(EXIT_GENERIC, "source length overflow"))
    })?;
    let report = PackReport {
        schema_version: 1,
        output: command.output.to_string_lossy().into_owned(),
        format: match command.format {
            OutputFormat::Binary => "binary",
            OutputFormat::Token => "token",
        },
        files: artifacts.len(),
        source_bytes,
        output_bytes: u64::try_from(output_bytes.len())
            .map_err(|_| CliError::new(EXIT_GENERIC, "output length overflow"))?,
        key_id: encode_key_id(&key_id),
        capsule_digest: encode_digest(&verified.capsule_digest()),
    };
    if command.json {
        write_json(&report)
    } else {
        println!(
            "{}",
            super::ui::success("✓ Capsule packed · signed · self-verified")
        );
        println!("  Files    {}", report.files);
        println!("  Input    {} bytes", report.source_bytes);
        println!(
            "  Output   {} ({} bytes)",
            report.output, report.output_bytes
        );
        println!("  Key ID   {}", report.key_id);
        println!("  Digest   {}", report.capsule_digest);
        Ok(())
    }
}

fn collect_artifacts(root_path: &Path) -> Result<Vec<ArtifactFile>, CliError> {
    let root = Dir::open_ambient_dir(root_path, ambient_authority()).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot open source root {}: {error}", root_path.display()),
        )
    })?;
    let mut artifacts = Vec::new();
    let mut total = 0_u64;
    walk_directory(&root, "", 0, &mut artifacts, &mut total)?;
    Ok(artifacts)
}

fn walk_directory(
    directory: &Dir,
    prefix: &str,
    depth: usize,
    artifacts: &mut Vec<ArtifactFile>,
    total: &mut u64,
) -> Result<(), CliError> {
    if depth > MAX_DIRECTORY_DEPTH {
        return Err(CliError::new(
            EXIT_GENERIC,
            "source directory nesting is too deep",
        ));
    }
    let entries = directory
        .entries()
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot list source: {error}")))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::new(EXIT_GENERIC, format!("cannot read source entry: {error}"))
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CliError::new(EXIT_GENERIC, "source paths must be valid UTF-8"))?;
        names.push(name);
    }
    names.sort_unstable();
    for name in names {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let metadata = directory.symlink_metadata(&name).map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot inspect source {path}: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::new(
                super::EXIT_UNSAFE_PATH,
                format!("source symlink is forbidden: {path}"),
            ));
        }
        if metadata.is_dir() {
            let child = directory.open_dir_nofollow(&name).map_err(|error| {
                CliError::new(
                    EXIT_GENERIC,
                    format!("cannot open source directory {path}: {error}"),
                )
            })?;
            walk_directory(&child, &path, depth.saturating_add(1), artifacts, total)?;
        } else if metadata.is_file() {
            read_artifact(directory, &name, &path, artifacts, total)?;
        } else {
            return Err(CliError::new(
                super::EXIT_UNSAFE_PATH,
                format!("source is not a regular file: {path}"),
            ));
        }
    }
    Ok(())
}

fn read_artifact(
    directory: &Dir,
    name: &str,
    path: &str,
    artifacts: &mut Vec<ArtifactFile>,
    total: &mut u64,
) -> Result<(), CliError> {
    let limits = SecurityLimits::V1;
    let count = u32::try_from(artifacts.len().saturating_add(1))
        .map_err(|_| CliError::new(EXIT_GENERIC, "source file count overflow"))?;
    if count > limits.max_file_count {
        return Err(CliError::new(
            EXIT_GENERIC,
            format!(
                "source exceeds the {}-file RAP limit",
                limits.max_file_count
            ),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = directory.open_with(name, &options).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot open source file {path}: {error}"),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot inspect source file {path}: {error}"),
        )
    })?;
    if !metadata.is_file() || metadata.len() > limits.max_single_file_bytes {
        return Err(CliError::new(
            EXIT_GENERIC,
            format!("source file exceeds the RAP limit or changed type: {path}"),
        ));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| CliError::new(EXIT_GENERIC, "source file length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limits.max_single_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot read source file {path}: {error}"),
            )
        })?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| CliError::new(EXIT_GENERIC, "source file length overflow"))?;
    if length > limits.max_single_file_bytes {
        return Err(CliError::new(
            EXIT_GENERIC,
            format!("source file exceeds the RAP limit: {path}"),
        ));
    }
    *total = total
        .checked_add(length)
        .ok_or_else(|| CliError::new(EXIT_GENERIC, "source payload length overflow"))?;
    if *total > limits.max_uncompressed_payload_bytes {
        return Err(CliError::new(
            EXIT_GENERIC,
            "source exceeds the RAP reconstructed-payload limit",
        ));
    }
    let artifact = ArtifactFile::new(path, bytes)
        .map_err(|error| CliError::new(super::EXIT_UNSAFE_PATH, error.to_string()))?
        .with_executable(is_executable(&metadata));
    artifacts.push(artifact);
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::PermissionsExt as _;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
const fn is_executable(_metadata: &cap_std::fs::Metadata) -> bool {
    false
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PackReport {
    schema_version: u16,
    output: String,
    format: &'static str,
    files: usize,
    source_bytes: u64,
    output_bytes: u64,
    key_id: String,
    capsule_digest: String,
}
