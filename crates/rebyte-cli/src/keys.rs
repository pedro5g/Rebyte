//! CLI key generation, inspection, status and loading.

#![allow(clippy::redundant_pub_crate)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use rebyte_format::KeyId;
use rebyte_signature::{KeyStatus, TrustChannel, TrustedPublicKey};
use rebyte_signer::{
    EncryptedPrivateKeyDocument, LocalKeySigner, PublicKeyDocument, generate_encrypted_key,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::security_io::{read_bounded_nofollow, require_private_permissions, write_new};
use super::{CliError, EXIT_GENERIC, EXIT_POLICY, encode_key_id, write_json};

const MAX_KEY_DOCUMENT_BYTES: u64 = 64 * 1_024;
const MAX_PASSPHRASE_FILE_BYTES: u64 = 1_026;

#[derive(Debug, Args)]
pub(super) struct KeyCommand {
    #[command(subcommand)]
    command: KeySubcommand,
}

#[derive(Debug, Subcommand)]
enum KeySubcommand {
    /// Generate a random encrypted private key and distributable public key.
    Generate(GenerateCommand),
    /// Validate and display a public trust document.
    Inspect(InspectCommand),
    /// Create a new trust document with an updated local key status.
    Status(StatusCommand),
}

#[derive(Debug, Args)]
struct GenerateCommand {
    /// Encrypted private-key output; created with mode 0600 on Unix.
    #[arg(long, value_name = "PATH", default_value = "rebyte-private-key.json")]
    private_key: PathBuf,
    /// Distributable public trust-document output.
    #[arg(long, value_name = "PATH", default_value = "rebyte-public-key.json")]
    public_key: PathBuf,
    /// Publisher name shown after successful verification.
    #[arg(long, value_name = "NAME")]
    name: String,
    /// Environment in which this key is trusted.
    #[arg(long, value_enum, default_value = "production")]
    channel: KeyChannelArgument,
    #[command(flatten)]
    passphrase: PassphraseArgs,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct InspectCommand {
    /// Public trust document to validate.
    public_key: PathBuf,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusCommand {
    /// Existing public trust document.
    public_key: PathBuf,
    /// New administrative status.
    #[arg(long, value_enum)]
    status: KeyStatusArgument,
    /// New public document; existing files are never overwritten.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KeyChannelArgument {
    Production,
    Staging,
    Development,
}

impl KeyChannelArgument {
    const fn to_trust(self) -> TrustChannel {
        match self {
            Self::Production => TrustChannel::Production,
            Self::Staging => TrustChannel::Staging,
            Self::Development => TrustChannel::Development,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KeyStatusArgument {
    Retired,
    Revoked,
}

impl KeyStatusArgument {
    const fn to_status(self) -> KeyStatus {
        match self {
            Self::Retired => KeyStatus::Retired,
            Self::Revoked => KeyStatus::Revoked,
        }
    }
}

#[derive(Clone, Debug, Args)]
pub(super) struct PassphraseArgs {
    /// Read the passphrase from a mode-0600 file instead of a TTY prompt.
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,
}

pub(super) fn run(command: &KeyCommand) -> Result<(), CliError> {
    match &command.command {
        KeySubcommand::Generate(command) => generate(command),
        KeySubcommand::Inspect(command) => inspect(command),
        KeySubcommand::Status(command) => status(command),
    }
}

pub(super) fn load_trusted_key(path: &Path) -> Result<TrustedPublicKey, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_KEY_DOCUMENT_BYTES).map_err(|error| {
        CliError::new(
            EXIT_POLICY,
            format!("cannot read trusted key {}: {error}", path.display()),
        )
    })?;
    PublicKeyDocument::from_json(&bytes)
        .and_then(|document| document.to_trusted_key())
        .map_err(|error| {
            CliError::new(
                EXIT_POLICY,
                format!("invalid trusted key {}: {error}", path.display()),
            )
        })
}

pub(super) fn load_local_signer(
    private_key: &Path,
    passphrase: &PassphraseArgs,
) -> Result<(LocalKeySigner, KeyId), CliError> {
    require_private_permissions(private_key).map_err(|error| {
        CliError::new(
            EXIT_POLICY,
            format!("unsafe private key {}: {error}", private_key.display()),
        )
    })?;
    let bytes = read_bounded_nofollow(private_key, MAX_KEY_DOCUMENT_BYTES).map_err(|error| {
        CliError::new(
            EXIT_POLICY,
            format!("cannot read private key {}: {error}", private_key.display()),
        )
    })?;
    let document = EncryptedPrivateKeyDocument::from_json(&bytes).map_err(|error| {
        CliError::new(
            EXIT_POLICY,
            format!("invalid private key document: {error}"),
        )
    })?;
    let secret = read_passphrase(passphrase, false)?;
    let signer = document
        .unlock(secret.as_bytes())
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    let fingerprint = document
        .key_id()
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    Ok((signer, fingerprint))
}

fn generate(command: &GenerateCommand) -> Result<(), CliError> {
    if command.private_key == command.public_key {
        return Err(CliError::new(
            EXIT_GENERIC,
            "private and public key outputs must be different",
        ));
    }
    ensure_output_absent(&command.private_key)?;
    ensure_output_absent(&command.public_key)?;
    let passphrase = read_passphrase(&command.passphrase, true)?;
    let (private, public) = generate_encrypted_key(
        passphrase.as_bytes(),
        &command.name,
        command.channel.to_trust(),
    )
    .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    let private_json = private
        .to_json()
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    let public_json = public
        .to_json()
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    write_new(&command.private_key, &private_json, true).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create private key {}: {error}",
                command.private_key.display()
            ),
        )
    })?;
    if let Err(error) = write_new(&command.public_key, &public_json, false) {
        let _cleanup = fs::remove_file(&command.private_key);
        return Err(CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create public key {}: {error}",
                command.public_key.display()
            ),
        ));
    }
    let report = KeyReport::from_document(&public)?;
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Publisher key generated"));
        println!("  Key ID       {}", report.key_id);
        println!("  Channel      {}", report.channel);
        println!("  Private key  {}", command.private_key.display());
        println!("  Public key   {}", command.public_key.display());
        println!(
            "\nKeep the private key and passphrase separate; distribute only the public file."
        );
        Ok(())
    }
}

fn inspect(command: &InspectCommand) -> Result<(), CliError> {
    let document = read_public_document(&command.public_key)?;
    let report = KeyReport::from_document(&document)?;
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::heading("Rebyte publisher key"));
        println!("  Name       {}", report.display_name);
        println!("  Key ID     {}", report.key_id);
        println!("  Channel    {}", report.channel);
        println!("  Status     {}", report.status);
        println!("  Algorithm  Ed25519");
        Ok(())
    }
}

fn status(command: &StatusCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let document = read_public_document(&command.public_key)?;
    let updated = document
        .with_status(command.status.to_status())
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    write_new(
        &command.output,
        &updated
            .to_json()
            .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?,
        false,
    )
    .map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create trust document {}: {error}",
                command.output.display()
            ),
        )
    })?;
    let report = KeyReport::from_document(&updated)?;
    if command.json {
        write_json(&report)
    } else {
        println!(
            "{}",
            super::ui::success(&format!("✓ Trust status written · {}", report.status))
        );
        println!("  Key ID  {}", report.key_id);
        println!("  Output  {}", command.output.display());
        Ok(())
    }
}

fn read_public_document(path: &Path) -> Result<PublicKeyDocument, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_KEY_DOCUMENT_BYTES).map_err(|error| {
        CliError::new(
            EXIT_POLICY,
            format!("cannot read public key {}: {error}", path.display()),
        )
    })?;
    PublicKeyDocument::from_json(&bytes)
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))
}

fn read_passphrase(args: &PassphraseArgs, confirm: bool) -> Result<Zeroizing<String>, CliError> {
    if let Some(path) = &args.passphrase_file {
        require_private_permissions(path).map_err(|error| {
            CliError::new(
                EXIT_POLICY,
                format!("unsafe passphrase file {}: {error}", path.display()),
            )
        })?;
        let bytes = read_bounded_nofollow(path, MAX_PASSPHRASE_FILE_BYTES).map_err(|error| {
            CliError::new(
                EXIT_POLICY,
                format!("cannot read passphrase file {}: {error}", path.display()),
            )
        })?;
        let mut value = String::from_utf8(bytes)
            .map_err(|_| CliError::new(EXIT_POLICY, "passphrase file is not UTF-8"))?;
        if value.ends_with("\r\n") {
            value.truncate(value.len().saturating_sub(2));
        } else if value.ends_with('\n') {
            value.truncate(value.len().saturating_sub(1));
        }
        return Ok(Zeroizing::new(value));
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("Private-key passphrase: ").map_err(|error| {
            CliError::new(EXIT_GENERIC, format!("cannot read passphrase: {error}"))
        })?,
    );
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ").map_err(
            |error| CliError::new(EXIT_GENERIC, format!("cannot confirm passphrase: {error}")),
        )?);
        if first.as_bytes() != second.as_bytes() {
            return Err(CliError::new(EXIT_POLICY, "passphrases do not match"));
        }
    }
    Ok(first)
}

fn ensure_output_absent(path: &Path) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CliError::new(
            EXIT_GENERIC,
            format!("output already exists: {}", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::new(
            EXIT_GENERIC,
            format!("cannot inspect output {}: {error}", path.display()),
        )),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyReport {
    schema_version: u16,
    display_name: String,
    algorithm: &'static str,
    key_id: String,
    public_key: String,
    channel: &'static str,
    status: &'static str,
}

impl KeyReport {
    fn from_document(document: &PublicKeyDocument) -> Result<Self, CliError> {
        Ok(Self {
            schema_version: 1,
            display_name: document.display_name().to_string(),
            algorithm: "Ed25519",
            key_id: encode_key_id(
                &document
                    .key_id()
                    .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?,
            ),
            public_key: encode_base64(
                &document
                    .public_key()
                    .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?,
            ),
            channel: channel_name(document.channel()),
            status: status_name(document.status()),
        })
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    URL_SAFE_NO_PAD.encode(bytes)
}

const fn channel_name(channel: TrustChannel) -> &'static str {
    match channel {
        TrustChannel::Production => "production",
        TrustChannel::Staging => "staging",
        TrustChannel::Development => "development",
        _ => "unknown",
    }
}

const fn status_name(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Active => "active",
        KeyStatus::Retired => "retired",
        KeyStatus::Revoked => "revoked",
        _ => "unknown",
    }
}
