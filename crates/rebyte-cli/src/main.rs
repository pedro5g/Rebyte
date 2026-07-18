//! Rebyte command-line interface.

#![forbid(unsafe_code)]

mod artifact_command;
mod chain_command;
mod fingerprint;
mod hardening;
mod hash_command;
mod keys;
mod producer;
mod release_ledger;
mod security_io;
mod semantic_command;
mod shell_env;
mod ui;

use std::fmt;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Args, CommandFactory as _, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use rebyte_core::{
    ApplyError, ApplyOptions, ApplyReport, ChangeKind, DiffReport, FullyVerifiedCapsule,
    TransactionState, TransactionSummary, apply_transaction, diff_capsule, list_transactions,
    resume_transaction, rollback_transaction,
};
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
const EXIT_UNSAFE_PATH: u8 = 8;
const EXIT_CONFLICT: u8 = 9;
const EXIT_TRANSACTION: u8 = 10;
const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Yellow.on_default());
const DEVELOPMENT_PUBLIC_KEY: [u8; 32] = [
    88, 147, 102, 4, 171, 218, 17, 43, 201, 73, 51, 86, 156, 130, 248, 208, 204, 13, 223, 146, 163,
    248, 50, 159, 47, 68, 143, 127, 72, 74, 89, 76,
];

#[derive(Debug, Parser)]
#[command(
    name = "rebyte",
    version,
    about = "Reconstruct files and folders exactly with simple artifacts or signed capsules",
    long_about = "Rebyte creates byte-exact unsigned artifact tokens and deterministic signed RAP v1 capsules without network access, command execution or lifecycle hooks.",
    after_help = "Simple: rebyte encode FILE --include-name > file.ra1\n        rebyte decode --file file.ra1 --accept-suggested-path\nLarge:  rebyte encode FOLDER --format binary -o backup.rba\nSigned: rebyte key generate --name 'My publisher'",
    styles = CLI_STYLES
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encode one file or folder as an unsigned, integrity-checked artifact.
    Encode(artifact_command::EncodeCommand),
    /// Preview or reconstruct an unsigned artifact byte for byte.
    Decode(artifact_command::DecodeCommand),
    /// Pack a directory, sign it and self-verify the resulting capsule.
    Pack(producer::PackCommand),
    /// Compute or check a domain-separated RAP file digest.
    Hash(hash_command::HashCommand),
    /// Create, inspect or safely apply structured JSON/TOML patches.
    Patch(semantic_command::PatchCommand),
    /// Create self-custodied identities, consensus groups and encrypted capsules.
    Chain(chain_command::ChainCommand),
    /// Generate and manage publisher key documents.
    Key(keys::KeyCommand),
    /// Inspect bounded capsule metadata; verification status is reported separately.
    Inspect(ReadCommand),
    /// Verify structure, publisher, signature and every reconstructed file.
    Verify(VerifyCommand),
    /// Compare a verified capsule with a local root without writing.
    Diff(DiffCommand),
    /// Verify, preview and safely apply a capsule to a local root.
    Apply(ApplyCommand),
    /// List retained or interrupted filesystem transactions.
    Transactions(RootCommand),
    /// Resume an interrupted transaction from verified staged bytes.
    Resume(RecoveryCommand),
    /// Restore the original state from an interrupted or retained transaction.
    Rollback(RecoveryCommand),
    /// Report local Rebyte capabilities and trust configuration.
    Doctor(DoctorCommand),
    /// Print shell code that exports the absolute Rebyte path as `$REBYTE`.
    ShellEnv(shell_env::ShellEnvCommand),
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
struct VerifyCommand {
    #[command(flatten)]
    read: ReadCommand,
    /// Report each verification stage in its enforced order.
    #[arg(long)]
    explain: bool,
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
struct ApplyCommand {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    trust: TrustArgs,
    /// Local application root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[command(flatten)]
    mode: ApplyModeArgs,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ApplyModeArgs {
    /// Verify and preview without modifying the filesystem.
    #[arg(long)]
    dry_run: bool,
    /// Apply without the interactive confirmation prompt.
    #[arg(long)]
    yes: bool,
    /// Retain the committed journal and original-file backups.
    #[arg(long)]
    backup: bool,
}

#[derive(Debug, Args)]
struct RootCommand {
    /// Local application root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RecoveryCommand {
    /// UUID of a transaction reported by `rebyte transactions`.
    transaction_id: String,
    /// Local application root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DoctorCommand {
    /// Load a public trust document when checking the local configuration.
    #[arg(long = "trusted-key", value_name = "PATH")]
    trusted_keys: Vec<PathBuf>,
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
    /// Public trust document; repeat for key rotation or multiple publishers.
    #[arg(long = "trusted-key", value_name = "PATH")]
    trusted_keys: Vec<PathBuf>,
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
    hardening::harden_process();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{} {}",
                ui::error("rebyte error:"),
                sanitize_terminal(&error.to_string())
            );
            ExitCode::from(error.exit_code)
        }
    }
}

fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Commands::Encode(command) => artifact_command::encode(&command),
        Commands::Decode(command) => artifact_command::decode(&command),
        Commands::Pack(command) => producer::run(&command),
        Commands::Hash(command) => hash_command::run(&command),
        Commands::Patch(command) => semantic_command::run(&command),
        Commands::Chain(command) => chain_command::run(&command),
        Commands::Key(command) => keys::run(&command),
        Commands::Inspect(command) => inspect(&command),
        Commands::Verify(command) => verify(&command),
        Commands::Diff(command) => diff(&command),
        Commands::Apply(command) => apply(&command),
        Commands::Transactions(command) => transactions(&command),
        Commands::Resume(command) => resume(&command),
        Commands::Rollback(command) => rollback(&command),
        Commands::Doctor(command) => doctor(&command),
        Commands::ShellEnv(command) => shell_env::run(&command),
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

const EXPLAIN_STEPS: [&str; 5] = [
    "input bound and token decoded",
    "canonical header and manifest parsed within limits",
    "capsule digest, trust policy and Ed25519 signature verified",
    "payload decompressed and every file digest verified",
    "fully verified capsule released",
];

fn verify(command: &VerifyCommand) -> Result<(), CliError> {
    if command.explain {
        return verify_explained(command);
    }
    let input = read_input(&command.read.input)?;
    let policy = trust_policy(&command.read.trust);
    let keyring = trusted_keyring(&command.read.trust)?;
    let verified = verify_capsule(input.as_capsule_input(), &policy, &keyring)
        .map_err(CliError::verification)?;
    let report = VerificationReport::from_capsule(&verified);
    if command.read.json {
        write_json(&report)
    } else {
        print_verification(&report);
        Ok(())
    }
}

fn verify_explained(command: &VerifyCommand) -> Result<(), CliError> {
    let input = read_input(&command.read.input)?;
    let policy = trust_policy(&command.read.trust);
    let keyring = trusted_keyring(&command.read.trust)?;
    let human = !command.read.json;
    let mut passed: Vec<&'static str> = Vec::new();
    if human {
        println!("{}", ui::heading("Verification steps"));
    }
    let limits = SecurityLimits::V1;
    let unverified = explain_step(
        UnverifiedCapsule::from_input(input.as_capsule_input(), &limits),
        EXPLAIN_STEPS[0],
        &mut passed,
        human,
    )?;
    let structural = explain_step(
        unverified.decode(&limits),
        EXPLAIN_STEPS[1],
        &mut passed,
        human,
    )?;
    let signature_verified = explain_step(
        structural.verify_signature(&policy, &keyring),
        EXPLAIN_STEPS[2],
        &mut passed,
        human,
    )?;
    let payload_verified = explain_step(
        signature_verified.verify_payload(&limits),
        EXPLAIN_STEPS[3],
        &mut passed,
        human,
    )?;
    let verified = payload_verified.finish();
    record_step(EXPLAIN_STEPS[4], &mut passed, human);
    let mut report = VerificationReport::from_capsule(&verified);
    report.steps = Some(passed);
    if command.read.json {
        write_json(&report)
    } else {
        println!();
        print_verification(&report);
        Ok(())
    }
}

fn explain_step<T>(
    result: Result<T, VerificationError>,
    name: &'static str,
    passed: &mut Vec<&'static str>,
    human: bool,
) -> Result<T, CliError> {
    match result {
        Ok(value) => {
            record_step(name, passed, human);
            Ok(value)
        }
        Err(error) => {
            if human {
                println!("  ✗ {name}");
            }
            Err(CliError::verification(error))
        }
    }
}

fn record_step(name: &'static str, passed: &mut Vec<&'static str>, human: bool) {
    passed.push(name);
    if human {
        println!("  ✓ {name}");
    }
}

fn diff(command: &DiffCommand) -> Result<(), CliError> {
    let input = read_input(&command.input)?;
    let policy = trust_policy(&command.trust);
    let keyring = trusted_keyring(&command.trust)?;
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

fn apply(command: &ApplyCommand) -> Result<(), CliError> {
    let input = read_input(&command.input)?;
    let policy = trust_policy(&command.trust);
    let keyring = trusted_keyring(&command.trust)?;
    let verified = verify_capsule(input.as_capsule_input(), &policy, &keyring)
        .map_err(CliError::verification)?;
    let changes = diff_capsule(&verified, &command.root)
        .map_err(|error| CliError::new(EXIT_TRANSACTION, error.to_string()))?;

    if command.mode.dry_run {
        if command.json {
            return write_json(&ApplyPreviewJson::from_report(&changes));
        }
        println!(
            "{}",
            ui::heading("Dry run · fully verified · no files will be written")
        );
        print_diff(&changes);
        return Ok(());
    }
    if !command.mode.yes && !confirm_apply(&changes, !command.json)? {
        if command.json {
            return write_json(&ApplyCancelledJson {
                schema_version: 1,
                applied: false,
                reason: "cancelled",
            });
        }
        println!(
            "{}",
            ui::heading("Application cancelled · no files were written")
        );
        return Ok(());
    }
    let report = apply_transaction(
        &verified,
        &command.root,
        &ApplyOptions {
            retain_backup: command.mode.backup,
        },
    )
    .map_err(CliError::apply)?;
    print_apply_result(&report, command.json)
}

fn transactions(command: &RootCommand) -> Result<(), CliError> {
    let summaries = list_transactions(&command.root).map_err(CliError::apply)?;
    let report = TransactionsJson::from_summaries(&summaries);
    if command.json {
        write_json(&report)
    } else {
        if summaries.is_empty() {
            println!("No retained or interrupted transactions.");
        }
        for transaction in summaries {
            println!(
                "{}  {}  {}/{} files{}",
                transaction.id,
                transaction_state_name(transaction.state),
                transaction.committed,
                transaction.operations,
                if transaction.retained {
                    "  retained"
                } else {
                    ""
                }
            );
        }
        Ok(())
    }
}

fn resume(command: &RecoveryCommand) -> Result<(), CliError> {
    let report =
        resume_transaction(&command.root, &command.transaction_id).map_err(CliError::apply)?;
    print_apply_result(&report, command.json)
}

fn rollback(command: &RecoveryCommand) -> Result<(), CliError> {
    rollback_transaction(&command.root, &command.transaction_id).map_err(CliError::apply)?;
    let report = RecoveryJson {
        schema_version: 1,
        transaction_id: command.transaction_id.clone(),
        state: "rolledBack",
    };
    if command.json {
        write_json(&report)
    } else {
        println!("Rolled back transaction {}.", command.transaction_id);
        Ok(())
    }
}

fn confirm_apply(report: &DiffReport, print_preview: bool) -> Result<bool, CliError> {
    if print_preview {
        print_diff(report);
    }
    eprint!("Apply these verified changes? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot flush prompt: {error}")))?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).map_err(|error| {
        CliError::new(EXIT_GENERIC, format!("cannot read confirmation: {error}"))
    })?;
    Ok(is_affirmative(&answer))
}

fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn print_apply_result(report: &ApplyReport, json: bool) -> Result<(), CliError> {
    let value = ApplyReportJson::from_report(report);
    if json {
        write_json(&value)
    } else {
        println!(
            "{}",
            ui::success(&format!(
                "✓ Applied {} verified files ({} bytes) · transaction {}",
                report.files_written, report.bytes_written, report.transaction_id
            ))
        );
        if let Some(path) = &report.retained_backup {
            println!("Backup retained at {}.", path.display());
        }
        Ok(())
    }
}

fn doctor(command: &DoctorCommand) -> Result<(), CliError> {
    let keys = trusted_keys(&command.trusted_keys)?;
    let production_keys = keys
        .iter()
        .filter(|key| key.channel() == TrustChannel::Production)
        .count();
    let staging_keys = keys
        .iter()
        .filter(|key| key.channel() == TrustChannel::Staging)
        .count();
    let development_keys = keys
        .iter()
        .filter(|key| key.channel() == TrustChannel::Development)
        .count();
    let report = DoctorReport {
        schema_version: 1,
        version: env!("CARGO_PKG_VERSION"),
        protocol_version: rebyte_core::PROTOCOL_VERSION,
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        production_keys: u32::try_from(production_keys)
            .map_err(|_| CliError::new(EXIT_GENERIC, "key count overflow"))?,
        staging_keys: u32::try_from(staging_keys)
            .map_err(|_| CliError::new(EXIT_GENERIC, "key count overflow"))?,
        development_keys: u32::try_from(development_keys)
            .map_err(|_| CliError::new(EXIT_GENERIC, "key count overflow"))?,
        filesystem_apply_available: true,
    };
    if command.json {
        write_json(&report)
    } else {
        println!("{}", ui::heading(&format!("Rebyte {}", report.version)));
        println!("Protocol: RAP v{}", report.protocol_version);
        println!(
            "Platform: {}-{}",
            report.operating_system, report.architecture
        );
        println!("Production keys: {}", report.production_keys);
        println!(
            "Staging keys: {} (explicit opt-in required)",
            report.staging_keys
        );
        println!(
            "Development keys: {} (explicit opt-in required)",
            report.development_keys
        );
        println!("Filesystem apply: available (confirmation required by default)");
        Ok(())
    }
}

fn verify_structural_status(
    structural: &StructurallyValidCapsule,
    trust: &TrustArgs,
) -> Result<String, CliError> {
    let policy = trust_policy(trust);
    let keyring = trusted_keyring(trust)?;
    let result = structural
        .clone()
        .verify_signature(&policy, &keyring)
        .and_then(|capsule| capsule.verify_payload(&SecurityLimits::V1));
    Ok(match result {
        Ok(_) => "valid".to_string(),
        Err(error) => format!("not verified: {error}"),
    })
}

fn trusted_keyring(args: &TrustArgs) -> Result<TrustedKeyring, CliError> {
    TrustedKeyring::new(trusted_keys(&args.trusted_keys)?).map_err(CliError::signature)
}

fn trusted_keys(paths: &[PathBuf]) -> Result<Vec<TrustedPublicKey>, CliError> {
    let development = TrustedPublicKey::new(
        "Rebyte development test key",
        DEVELOPMENT_PUBLIC_KEY,
        TrustChannel::Development,
        KeyStatus::Active,
    )
    .map_err(CliError::signature)?;
    let mut keys = Vec::with_capacity(paths.len().saturating_add(1));
    keys.push(development);
    for path in paths {
        keys.push(keys::load_trusted_key(path)?);
    }
    Ok(keys)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    steps: Option<Vec<&'static str>>,
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
            steps: None,
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
    staging_keys: u32,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyPreviewJson {
    schema_version: u16,
    dry_run: bool,
    verified: bool,
    diff: DiffJson,
}

impl ApplyPreviewJson {
    fn from_report(report: &DiffReport) -> Self {
        Self {
            schema_version: 1,
            dry_run: true,
            verified: true,
            diff: DiffJson::from_report(report),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyCancelledJson {
    schema_version: u16,
    applied: bool,
    reason: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyReportJson {
    schema_version: u16,
    applied: bool,
    transaction_id: String,
    files_written: usize,
    directories_ensured: usize,
    bytes_written: u64,
    retained_backup: Option<String>,
}

impl ApplyReportJson {
    fn from_report(report: &ApplyReport) -> Self {
        Self {
            schema_version: 1,
            applied: true,
            transaction_id: report.transaction_id.clone(),
            files_written: report.files_written,
            directories_ensured: report.directories_ensured,
            bytes_written: report.bytes_written,
            retained_backup: report
                .retained_backup
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionsJson {
    schema_version: u16,
    transactions: Vec<TransactionJson>,
}

impl TransactionsJson {
    fn from_summaries(summaries: &[TransactionSummary]) -> Self {
        Self {
            schema_version: 1,
            transactions: summaries
                .iter()
                .map(|transaction| TransactionJson {
                    id: transaction.id.clone(),
                    state: transaction_state_name(transaction.state),
                    operations: transaction.operations,
                    committed: transaction.committed,
                    capsule_digest: encode_digest(&transaction.capsule_digest),
                    retained: transaction.retained,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionJson {
    id: String,
    state: &'static str,
    operations: usize,
    committed: usize,
    capsule_digest: String,
    retained: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryJson {
    schema_version: u16,
    transaction_id: String,
    state: &'static str,
}

fn print_inspection(report: &InspectionReport) {
    println!(
        "{}",
        ui::heading("Rebyte capsule · bounded structure · metadata may be untrusted")
    );
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
    println!("{}", ui::success("✓ Capsule fully verified"));
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

const fn transaction_state_name(value: TransactionState) -> &'static str {
    match value {
        TransactionState::Prepared => "prepared",
        TransactionState::Staged => "staged",
        TransactionState::Committing => "committing",
        TransactionState::Committed => "committed",
        TransactionState::RollingBack => "rollingBack",
        TransactionState::RolledBack => "rolledBack",
        _ => "unknown",
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

    fn apply(error: ApplyError) -> Self {
        let exit_code = match error {
            ApplyError::Symlink | ApplyError::NotRegularFile => EXIT_UNSAFE_PATH,
            ApplyError::IncompleteTransaction
            | ApplyError::Conflict
            | ApplyError::TransactionFinished => EXIT_CONFLICT,
            _ => EXIT_TRANSACTION,
        };
        Self::new(exit_code, error.to_string())
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
    use super::{encode_hex, is_affirmative, sanitize_terminal};

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

    #[test]
    fn confirmation_is_explicit_and_case_insensitive() {
        assert!(is_affirmative("yes\n"));
        assert!(is_affirmative(" Y "));
        assert!(!is_affirmative(""));
        assert!(!is_affirmative("maybe"));
    }
}
