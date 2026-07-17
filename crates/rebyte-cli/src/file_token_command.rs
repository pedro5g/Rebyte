//! Simple unsigned file-token CLI commands.

#![allow(clippy::redundant_pub_crate)]

use std::io::{self, Read as _};
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use rebyte_core::{
    FileTokenCompression, FileTokenError, FileTokenOptions, decode_file_token, encode_file_token,
};
use rebyte_format::{CompressionAlgorithm, SecurityLimits};
use serde::Serialize;

use super::security_io::{read_bounded_nofollow, write_new};
use super::{CliError, EXIT_DIGEST, EXIT_GENERIC, EXIT_MALFORMED, encode_digest, write_json};

#[derive(Debug, Args)]
pub(super) struct EncodeCommand {
    /// File to encode, or `-` for standard input.
    input: PathBuf,
    /// Compression strategy; `auto` keeps Zstandard only when smaller.
    #[arg(long, value_enum, default_value = "auto")]
    compression: CompressionArgument,
    /// Write the token to a new file instead of standard output.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Emit a stable JSON report; includes the token when `--output` is absent.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
pub(super) struct DecodeCommand {
    /// `rf1_` token, or `-` to read a token from standard input.
    #[arg(value_name = "TOKEN", conflicts_with = "token_file")]
    token: Option<String>,
    /// Read a newline-terminated `rf1_` token from a file.
    #[arg(long = "file", value_name = "PATH", conflicts_with = "token")]
    token_file: Option<PathBuf>,
    /// Reconstruct into this new file; existing paths are never overwritten.
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,
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
    const fn to_policy(self) -> FileTokenCompression {
        match self {
            Self::Auto => FileTokenCompression::Auto,
            Self::Zstd => FileTokenCompression::Zstd,
            Self::None => FileTokenCompression::None,
        }
    }
}

pub(super) fn encode(command: &EncodeCommand) -> Result<(), CliError> {
    let bytes = if command.input.as_os_str() == "-" {
        read_bounded(io::stdin().lock(), SecurityLimits::V1.max_single_file_bytes)?
    } else {
        read_bounded_nofollow(&command.input, SecurityLimits::V1.max_single_file_bytes).map_err(
            |error| {
                CliError::new(
                    EXIT_GENERIC,
                    format!("cannot read file-token input: {error}"),
                )
            },
        )?
    };
    let options = FileTokenOptions::default()
        .with_compression(command.compression.to_policy())
        .with_limits(SecurityLimits::V1);
    let encoded = encode_file_token(&bytes, &options).map_err(encode_error)?;
    if let Some(output) = &command.output {
        let mut token_file = Vec::with_capacity(encoded.token().len().saturating_add(1));
        token_file.extend_from_slice(encoded.token().as_bytes());
        token_file.push(b'\n');
        write_new(output, &token_file, false).map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!(
                    "cannot create file-token output {}: {error}",
                    output.display()
                ),
            )
        })?;
    }

    let report = EncodeReport {
        schema_version: 1,
        kind: "unsignedFileToken",
        authenticated: false,
        digest: encode_digest(&encoded.digest()),
        original_bytes: encoded.original_size(),
        stored_bytes: encoded.stored_size(),
        token_bytes: u64::try_from(encoded.token().len())
            .map_err(|_| CliError::new(EXIT_GENERIC, "file-token length overflow"))?,
        compression: compression_name(encoded.compression()),
        output: command
            .output
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        token: command.output.is_none().then_some(encoded.token()),
    };
    if command.json {
        write_json(&report)
    } else if command.output.is_none() {
        println!("{}", encoded.token());
        Ok(())
    } else {
        println!(
            "{}",
            super::ui::success("✓ Unsigned file token encoded and self-verified")
        );
        println!("  Input       {} bytes", report.original_bytes);
        println!(
            "  Stored      {} bytes ({})",
            report.stored_bytes, report.compression
        );
        println!("  Token       {} bytes", report.token_bytes);
        println!("  Digest      {}", report.digest);
        if let Some(output) = &report.output {
            println!("  Output      {output}");
        }
        println!("  Authenticity unsigned · integrity only");
        Ok(())
    }
}

pub(super) fn decode(command: &DecodeCommand) -> Result<(), CliError> {
    let token = read_token(command)?;
    let decoded = decode_file_token(&token, &SecurityLimits::V1).map_err(decode_error)?;
    write_new(&command.output, decoded.bytes(), false).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create reconstructed file {}: {error}",
                command.output.display()
            ),
        )
    })?;
    let report = DecodeReport {
        schema_version: 1,
        kind: "unsignedFileToken",
        authenticated: false,
        integrity_verified: true,
        digest: encode_digest(&decoded.digest()),
        reconstructed_bytes: decoded.original_size(),
        stored_bytes: decoded.stored_size(),
        compression: compression_name(decoded.compression()),
        output: command.output.to_string_lossy().into_owned(),
    };
    if command.json {
        write_json(&report)
    } else {
        println!(
            "{}",
            super::ui::success("✓ Unsigned file token verified and reconstructed")
        );
        println!("  Output      {}", report.output);
        println!("  Bytes       {}", report.reconstructed_bytes);
        println!("  Compression {}", report.compression);
        println!("  Digest      {}", report.digest);
        println!("  Authenticity unsigned · integrity only");
        Ok(())
    }
}

fn read_token(command: &DecodeCommand) -> Result<String, CliError> {
    let value = if let Some(path) = &command.token_file {
        let bytes =
            read_bounded_nofollow(path, SecurityLimits::V1.max_token_bytes).map_err(|error| {
                CliError::new(EXIT_GENERIC, format!("cannot read file token: {error}"))
            })?;
        String::from_utf8(bytes)
            .map_err(|_| CliError::new(EXIT_MALFORMED, "file token is not UTF-8"))?
    } else {
        let token = command
            .token
            .as_deref()
            .ok_or_else(|| CliError::new(EXIT_MALFORMED, "TOKEN or --file is required"))?;
        if token == "-" {
            let bytes = read_bounded(io::stdin().lock(), SecurityLimits::V1.max_token_bytes)?;
            String::from_utf8(bytes)
                .map_err(|_| CliError::new(EXIT_MALFORMED, "file token is not UTF-8"))?
        } else {
            token.to_string()
        }
    };
    Ok(value
        .trim_matches(|character: char| character.is_ascii_whitespace())
        .to_string())
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

fn encode_error(error: FileTokenError) -> CliError {
    CliError::new(EXIT_GENERIC, error.to_string())
}

fn decode_error(error: FileTokenError) -> CliError {
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

const fn compression_name(compression: CompressionAlgorithm) -> &'static str {
    match compression {
        CompressionAlgorithm::None => "none",
        CompressionAlgorithm::Zstd => "zstd",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncodeReport<'a> {
    schema_version: u16,
    kind: &'static str,
    authenticated: bool,
    digest: String,
    original_bytes: u64,
    stored_bytes: u64,
    token_bytes: u64,
    compression: &'static str,
    output: Option<String>,
    token: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecodeReport {
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
