//! Streaming RAP file-domain digest command.

#![allow(clippy::redundant_pub_crate)]

use std::io;
use std::path::{Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use clap::Args;
use rebyte_format::{Digest32, SecurityLimits};
use rebyte_integrity::{DomainHasher, digest_matches};
use serde::Serialize;

use super::{CliError, EXIT_DIGEST, EXIT_GENERIC, EXIT_MALFORMED, encode_digest, write_json};

#[derive(Debug, Args)]
pub(super) struct HashCommand {
    /// File to hash, or `-` for standard input.
    input: PathBuf,
    /// Require the computed lowercase hexadecimal digest to match.
    #[arg(long, value_name = "HEX")]
    check: Option<String>,
    /// Emit stable JSON instead of terminal text.
    #[arg(long)]
    json: bool,
}

pub(super) fn run(command: &HashCommand) -> Result<(), CliError> {
    let (digest, bytes) = if command.input.as_os_str() == "-" {
        hash_reader(io::stdin().lock())?
    } else {
        hash_path(&command.input)?
    };
    if let Some(expected) = &command.check {
        let expected = decode_digest(expected)?;
        if !digest_matches(&expected, &digest) {
            return Err(CliError::new(
                EXIT_DIGEST,
                format!(
                    "RAP file digest mismatch: expected {}, computed {}",
                    encode_digest(&expected),
                    encode_digest(&digest)
                ),
            ));
        }
    }
    let report = HashReport {
        schema_version: 1,
        algorithm: "BLAKE3",
        domain: rebyte_integrity::FILE_CONTEXT,
        digest: encode_digest(&digest),
        bytes,
        input: command.input.to_string_lossy().into_owned(),
        matched: command.check.as_ref().map(|_| true),
    };
    if command.json {
        write_json(&report)
    } else {
        println!("{}  {}", report.digest, report.input);
        if report.matched == Some(true) {
            println!("{}", super::ui::success("✓ RAP file digest matches"));
        }
        Ok(())
    }
}

fn hash_path(path: &Path) -> Result<(Digest32, u64), CliError> {
    let filename = path
        .file_name()
        .ok_or_else(|| CliError::new(EXIT_GENERIC, "hash input has no file name"))?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot open hash input directory: {error}"),
        )
    })?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory.open_with(filename, &options).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot open hash input {}: {error}", path.display()),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        CliError::new(EXIT_GENERIC, format!("cannot inspect hash input: {error}"))
    })?;
    if !metadata.is_file() || metadata.len() > SecurityLimits::V1.max_single_file_bytes {
        return Err(CliError::new(
            EXIT_GENERIC,
            "hash input is not a regular file within the RAP file-size limit",
        ));
    }
    hash_reader(file)
}

fn hash_reader(mut reader: impl io::Read) -> Result<(Digest32, u64), CliError> {
    let maximum = SecurityLimits::V1.max_single_file_bytes;
    let mut hasher = DomainHasher::file();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            CliError::new(EXIT_GENERIC, format!("cannot read hash input: {error}"))
        })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| CliError::new(EXIT_GENERIC, "hash input length overflow"))?,
            )
            .ok_or_else(|| CliError::new(EXIT_GENERIC, "hash input length overflow"))?;
        if total > maximum {
            return Err(CliError::new(
                EXIT_GENERIC,
                "hash input exceeds the RAP single-file limit",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((hasher.finalize(), total))
}

fn decode_digest(value: &str) -> Result<Digest32, CliError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "--check must be a 64-character lowercase hexadecimal digest",
        ));
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HashReport {
    schema_version: u16,
    algorithm: &'static str,
    domain: &'static str,
    digest: String,
    bytes: u64,
    input: String,
    matched: Option<bool>,
}
