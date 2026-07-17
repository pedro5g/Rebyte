//! Rebyte command-line interface.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{self, Read as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory as _, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use rebyte_core::{ChangeKind, DiffReport, FullyVerifiedCapsule, diff_capsule};
use rebyte_format::{CompressionAlgorithm, Digest32, KeyId, SecurityLimits};
use rebyte_signature::{
    KeyStatus, SignatureError, TrustChannel, TrustedKeyring, TrustedPublicKey, VerificationPolicy,
};
use rebyte_verify::{
    CapsuleInput, StructurallyValidCapsule, UnverifiedCapsule, VerificationError, verify_capsule,
};
use serde::Serialize;

const EXIT_GENERIC: u8 = 1;
const EXIT_MALFORMED: u8 = 2;
const EXIT_INVALID_SIGNATURE: u8 = 3;
const EXIT_UNKNOWN_KEY: u8 = 4;
const EXIT_DIGEST: u8 = 5;
const EXIT_VERSION: u8 = 6;
const EXIT_POLICY: u8 = 7;
const DEVELOPMENT_PUBLIC_KEY: [u8; 32] = [
    88, 147, 102, 4, 171, 218, 17, 43, 201, 73, 51, 86, 156, 130, 248, 208, 204, 13, 223, 146, 163,
    248, 50, 159, 47, 68, 143, 127, 72, 74, 89, 76,
];

#[derive(Debug, Parser)]
#[command(
    name = "rebyte",
    version,
    about = "Verify and reconstruct signed Rebyte capsules",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect bounded capsule metadata; verification status is reported separately.
    Inspect(ReadCommand),
    /// Verify structure, publisher, signature and every reconstructed file.
    Verify(ReadCommand),
    /// Compare a verified capsule with a local root without writing.
    Diff(DiffCommand),
    /// Report local Rebyte capabilities and trust configuration.
    Doctor {
        /// Emit stable JSON instead of terminal text.
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completion definitions.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Args)]
struct ReadCommand {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    trust: TrustArgs,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DiffCommand {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    trust: TrustArgs,
    /// Local application root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct InputArgs {
    /// `rb1_` token, or `-` to read a token from standard input.
    #[arg(value_name = "TOKEN", conflicts_with = "file")]
    token: Option<String>,
    /// Read a binary `.rbc` capsule from a file.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct TrustArgs {
    /// Explicitly permit a non-production trust channel.
    #[arg(long = "trust-channel", value_enum)]
    channels: Vec<ChannelArgument>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ChannelArgument {
    Staging,
    Development,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rebyte: {}", sanitize_terminal(&error.to_string()));
            ExitCode::from(error.exit_code)
        }
    }
}

fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Commands::Inspect(command) => inspect(&command),
        Commands::Verify(command) => verify(&command),
        Commands::Diff(command) => diff(&command),
        Commands::Doctor { json } => doctor(json),
        Commands::Completions { shell } => {
            generate(shell, &mut Cli::command(), "rebyte", &mut io::stdout());
            Ok(())
        }
    }
}

fn inspect(command: &ReadCommand) -> Result<(), CliError> {
    let input = read_input(&command.input)?;
    let limits = SecurityLimits::V1;
    let structural = UnverifiedCapsule::from_input(input.as_capsule_input(), &limits)
        .map_err(CliError::verification)?
        .decode(&limits)
        .map_err(CliError::verification)?;
    let verification = verify_structural_status(&structural, &command.trust)?;
    let report = InspectionReport::from_capsule(&structural, verification);
    if command.json {
        write_json(&report)
    } else {
        print_inspection(&report);
        Ok(())
    }
}

fn verify(command: &ReadCommand) -> Result<(), CliError> {
    let input = read_input(&command.input)?;
    let policy = trust_policy(&command.trust);
    let keyring = development_keyring()?;
    let verified = verify_capsule(input.as_capsule_input(), &policy, &keyring)
        .map_err(CliError::verification)?;
    let report = VerificationReport::from_capsule(&verified);
    if command.json {
        write_json(&report)
    } else {
        print_verification(&report);
        Ok(())
    }
}

fn diff(command: &DiffCommand) -> Result<(), CliError> {
    let input = read_input(&command.input)?;
    let policy = trust_policy(&command.trust);
    let keyring = development_keyring()?;
    let verified = verify_capsule(input.as_capsule_input(), &policy, &keyring)
        .map_err(CliError::verification)?;
    let report = diff_capsule(&verified, &command.root)
        .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    if command.json {
        write_json(&DiffJson::from_report(&report))
    } else {
        print_diff(&report);
        Ok(())
    }
}

fn doctor(json: bool) -> Result<(), CliError> {
    let keyring = development_keyring()?;
    let report = DoctorReport {
        schema_version: 1,
        version: env!("CARGO_PKG_VERSION"),
        protocol_version: rebyte_core::PROTOCOL_VERSION,
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        production_keys: 0,
        development_keys: u32::try_from(keyring.len())
            .map_err(|_| CliError::new(EXIT_GENERIC, "key count overflow"))?,
        filesystem_apply_available: false,
    };
    if json {
        write_json(&report)
    } else {
        println!("Rebyte {}", report.version);
        println!("Protocol: RAP v{}", report.protocol_version);
        println!(
            "Platform: {}-{}",
            report.operating_system, report.architecture
        );
        println!("Production keys: {}", report.production_keys);
        println!(
            "Development keys: {} (explicit opt-in required)",
            report.development_keys
        );
        println!("Filesystem apply: not implemented in this build phase");
        Ok(())
    }
}

fn verify_structural_status(
    structural: &StructurallyValidCapsule,
    trust: &TrustArgs,
) -> Result<String, CliError> {
    let policy = trust_policy(trust);
    let keyring = development_keyring()?;
    let result = structural
        .clone()
        .verify_signature(&policy, &keyring)
        .and_then(|capsule| capsule.verify_payload(&SecurityLimits::V1));
    Ok(match result {
        Ok(_) => "valid".to_string(),
        Err(error) => format!("not verified: {error}"),
    })
}

fn development_keyring() -> Result<TrustedKeyring, CliError> {
    let key = TrustedPublicKey::new(
        "Rebyte development test key",
        DEVELOPMENT_PUBLIC_KEY,
        TrustChannel::Development,
        KeyStatus::Active,
    )
    .map_err(CliError::signature)?;
    TrustedKeyring::new(vec![key]).map_err(CliError::signature)
}

fn trust_policy(args: &TrustArgs) -> VerificationPolicy {
    VerificationPolicy {
        allow_staging: args.channels.contains(&ChannelArgument::Staging),
        allow_development: args.channels.contains(&ChannelArgument::Development),
    }
}

enum OwnedInput {
    Binary(Vec<u8>),
    Token(String),
}

impl OwnedInput {
    fn as_capsule_input(&self) -> CapsuleInput<'_> {
        match self {
            Self::Binary(bytes) => CapsuleInput::Binary(bytes),
            Self::Token(token) => CapsuleInput::Token(token),
        }
    }
}

fn read_input(args: &InputArgs) -> Result<OwnedInput, CliError> {
    if let Some(path) = &args.file {
        return fs::read(path).map(OwnedInput::Binary).map_err(|error| {
            CliError::new(EXIT_GENERIC, format!("cannot read capsule file: {error}"))
        });
    }
    let token = args
        .token
        .as_deref()
        .ok_or_else(|| CliError::new(EXIT_MALFORMED, "TOKEN or --file is required"))?;
    if token == "-" {
        let mut value = String::new();
        io::stdin()
            .read_to_string(&mut value)
            .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot read stdin: {error}")))?;
        let trimmed = value
            .trim_matches(|character: char| character.is_ascii_whitespace())
            .to_string();
        Ok(OwnedInput::Token(trimmed))
    } else {
        Ok(OwnedInput::Token(token.to_string()))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectionReport {
    schema_version: u16,
    protocol_version: u16,
    compression: &'static str,
    publisher_key_id: String,
    producer: String,
    producer_version: Option<String>,
    file_count: u32,
    compressed_payload_size: u64,
    uncompressed_payload_size: u64,
    claimed_capsule_digest: String,
    verification: String,
    files: Vec<InspectionFile>,
}

impl InspectionReport {
    fn from_capsule(capsule: &StructurallyValidCapsule, verification: String) -> Self {
        let header = capsule.header();
        let manifest = capsule.manifest();
        Self {
            schema_version: 1,
            protocol_version: header.protocol_version.get(),
            compression: compression_name(header.compression),
            publisher_key_id: encode_hex(header.publisher_key_id.as_bytes()),
            producer: manifest.producer.name.as_str().to_string(),
            producer_version: manifest
                .producer
                .version
                .as_ref()
                .map(|value| value.as_str().to_string()),
            file_count: header.file_count,
            compressed_payload_size: header.compressed_payload_size,
            uncompressed_payload_size: header.uncompressed_payload_size,
            claimed_capsule_digest: encode_hex(capsule.claimed_capsule_digest().as_bytes()),
            verification,
            files: manifest
                .files
                .iter()
                .map(|file| InspectionFile {
                    path: file.path.as_str().to_string(),
                    size: file.size,
                    executable: file.executable,
                    content_kind: match file.content_kind {
                        rebyte_format::ContentKind::Binary => "binary",
                        rebyte_format::ContentKind::TextUtf8 => "textUtf8",
                    },
                    digest: encode_hex(file.digest.as_bytes()),
                })
                .collect(),
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
    digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationReport {
    schema_version: u16,
    valid: bool,
    publisher: String,
    trust_channel: &'static str,
    key_id: String,
    capsule_digest: String,
    files: usize,
    reconstructed_bytes: u64,
}

impl VerificationReport {
    fn from_capsule(capsule: &FullyVerifiedCapsule) -> Self {
        Self {
            schema_version: 1,
            valid: true,
            publisher: capsule.publisher().display_name.clone(),
            trust_channel: channel_name(capsule.publisher().channel),
            key_id: encode_key_id(&capsule.publisher().key_id),
            capsule_digest: encode_digest(&capsule.capsule_digest()),
            files: capsule.files().len(),
            reconstructed_bytes: capsule.header().uncompressed_payload_size,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorReport {
    schema_version: u16,
    version: &'static str,
    protocol_version: u16,
    operating_system: &'static str,
    architecture: &'static str,
    production_keys: u32,
    development_keys: u32,
    filesystem_apply_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffJson {
    schema_version: u16,
    created: u32,
    updated: u32,
    unchanged: u32,
    bytes: u64,
    added_lines: u64,
    removed_lines: u64,
    entries: Vec<DiffEntryJson>,
}

impl DiffJson {
    fn from_report(report: &DiffReport) -> Self {
        Self {
            schema_version: 1,
            created: report.summary.created,
            updated: report.summary.updated,
            unchanged: report.summary.unchanged,
            bytes: report.summary.bytes,
            added_lines: report.summary.added_lines,
            removed_lines: report.summary.removed_lines,
            entries: report
                .entries
                .iter()
                .map(|entry| DiffEntryJson {
                    path: entry.path.as_str().to_string(),
                    kind: change_name(entry.kind),
                    old_size: entry.old_size,
                    new_size: entry.new_size,
                    added_lines: entry.added_lines,
                    removed_lines: entry.removed_lines,
                    unified_text: entry.unified_text.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffEntryJson {
    path: String,
    kind: &'static str,
    old_size: u64,
    new_size: u64,
    added_lines: u64,
    removed_lines: u64,
    unified_text: Option<String>,
}

fn print_inspection(report: &InspectionReport) {
    println!("Rebyte Capsule (structurally bounded, metadata may be untrusted)");
    println!("Protocol: RAP v{}", report.protocol_version);
    println!("Compression: {}", report.compression);
    println!("Producer: {}", sanitize_terminal(&report.producer));
    println!("Key ID: {}", report.publisher_key_id);
    println!("Capsule digest: {}", report.claimed_capsule_digest);
    println!("Verification: {}", sanitize_terminal(&report.verification));
    println!("Files:");
    for file in &report.files {
        println!(
            "  {}  {} bytes  {}",
            sanitize_terminal(&file.path),
            file.size,
            file.content_kind
        );
    }
}

fn print_verification(report: &VerificationReport) {
    println!("✓ Capsule valid");
    println!("Publisher: {}", sanitize_terminal(&report.publisher));
    println!("Channel: {}", report.trust_channel);
    println!("Key ID: {}", report.key_id);
    println!("Digest: {}", report.capsule_digest);
    println!("Files: {}", report.files);
    println!("Reconstructed bytes: {}", report.reconstructed_bytes);
}

fn print_diff(report: &DiffReport) {
    for entry in &report.entries {
        println!("{}  {}", change_name(entry.kind), entry.path);
        if let Some(text) = &entry.unified_text {
            print!("{}", sanitize_terminal(text));
        }
    }
    println!(
        "Summary: {} create, {} update, {} unchanged, +{} -{} lines, {} bytes",
        report.summary.created,
        report.summary.updated,
        report.summary.unchanged,
        report.summary.added_lines,
        report.summary.removed_lines,
        report.summary.bytes
    );
}

fn write_json(value: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_writer_pretty(io::stdout().lock(), value)
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot write JSON: {error}")))?;
    println!();
    Ok(())
}

const fn compression_name(value: CompressionAlgorithm) -> &'static str {
    match value {
        CompressionAlgorithm::None => "none",
        CompressionAlgorithm::Zstd => "zstd",
    }
}

const fn channel_name(value: TrustChannel) -> &'static str {
    match value {
        TrustChannel::Production => "production",
        TrustChannel::Staging => "staging",
        TrustChannel::Development => "development",
        _ => "unknown",
    }
}

const fn change_name(value: ChangeKind) -> &'static str {
    match value {
        ChangeKind::Create => "CREATE",
        ChangeKind::Unchanged => "UNCHANGED",
        ChangeKind::UpdateText => "UPDATE",
        ChangeKind::UpdateBinary => "UPDATE-BINARY",
        _ => "UNKNOWN",
    }
}

fn encode_key_id(value: &KeyId) -> String {
    encode_hex(value.as_bytes())
}

fn encode_digest(value: &Digest32) -> String {
    encode_hex(value.as_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}

fn sanitize_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            output.extend(character.escape_default());
        }
    }
    output
}

#[derive(Debug)]
struct CliError {
    exit_code: u8,
    message: String,
}

impl CliError {
    fn new(exit_code: u8, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }

    fn verification(error: VerificationError) -> Self {
        let message = error.to_string();
        let exit_code = match error {
            VerificationError::Codec(rebyte_codec_error) => match rebyte_codec_error {
                rebyte_codec::CodecError::Format(
                    rebyte_format::FormatError::UnsupportedProtocolVersion(_),
                ) => EXIT_VERSION,
                _ => EXIT_MALFORMED,
            },
            VerificationError::Signature(SignatureError::InvalidSignature) => {
                EXIT_INVALID_SIGNATURE
            }
            VerificationError::Signature(SignatureError::UnknownKey) => EXIT_UNKNOWN_KEY,
            VerificationError::Signature(_) => EXIT_POLICY,
            VerificationError::CapsuleDigestMismatch
            | VerificationError::FileDigestMismatch
            | VerificationError::PayloadRangeMismatch
            | VerificationError::InvalidTextContent
            | VerificationError::Compression(_) => EXIT_DIGEST,
            VerificationError::InputTooLarge { .. } | VerificationError::LengthOverflow => {
                EXIT_MALFORMED
            }
            _ => EXIT_GENERIC,
        };
        Self::new(exit_code, message)
    }

    fn signature(error: SignatureError) -> Self {
        Self::new(EXIT_POLICY, error.to_string())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::{encode_hex, sanitize_terminal};

    #[test]
    fn terminal_controls_are_escaped_but_layout_is_preserved() {
        assert_eq!(
            sanitize_terminal("ok\x1b[31m\nnext\t"),
            "ok\\u{1b}[31m\nnext\t"
        );
    }

    #[test]
    fn lower_hex_is_stable() {
        assert_eq!(encode_hex(&[0, 0xab, 0xff]), "00abff");
    }
}
