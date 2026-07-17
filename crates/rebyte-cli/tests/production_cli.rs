//! End-to-end production publisher workflow for the Rebyte CLI.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

#[test]
#[allow(clippy::too_many_lines)] // One scenario preserves the complete publisher trust chain.
fn publisher_workflow_generates_packs_verifies_hashes_and_applies()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let source = directory.path().join("source");
    let target = directory.path().join("target");
    fs::create_dir_all(source.join("bin"))?;
    fs::create_dir(&target)?;
    fs::write(source.join("README.txt"), b"production artifact\n")?;
    fs::write(source.join("bin/data.bin"), [0_u8, 1, 2, 0xff])?;

    let passphrase = directory.path().join("passphrase.txt");
    write_private(&passphrase, b"a strong offline test passphrase\n")?;
    let private_key = directory.path().join("publisher.private.json");
    let public_key = directory.path().join("publisher.public.json");
    let capsule = directory.path().join("release.rbc");

    let generated = rebyte()
        .args([
            "key",
            "generate",
            "--private-key",
            path_text(&private_key)?,
            "--public-key",
            path_text(&public_key)?,
            "--name",
            "Production integration publisher",
            "--passphrase-file",
            path_text(&passphrase)?,
            "--json",
        ])
        .output()?;
    assert_success(&generated);
    assert!(stdout_text(&generated).contains("\"channel\": \"production\""));
    assert_private_mode(&private_key)?;

    let inspected_key = rebyte()
        .args(["key", "inspect", path_text(&public_key)?, "--json"])
        .output()?;
    assert_success(&inspected_key);
    assert!(stdout_text(&inspected_key).contains("\"status\": \"active\""));

    let packed = rebyte()
        .args([
            "pack",
            "--root",
            path_text(&source)?,
            "--private-key",
            path_text(&private_key)?,
            "--passphrase-file",
            path_text(&passphrase)?,
            "--output",
            path_text(&capsule)?,
            "--producer",
            "integration-build",
            "--producer-version",
            "1.0.0",
            "--name",
            "Production fixture",
            "--json",
        ])
        .output()?;
    assert_success(&packed);
    assert!(stdout_text(&packed).contains("\"files\": 2"));

    let verified = rebyte()
        .args([
            "verify",
            "--file",
            path_text(&capsule)?,
            "--trusted-key",
            path_text(&public_key)?,
            "--json",
        ])
        .output()?;
    assert_success(&verified);
    assert!(stdout_text(&verified).contains("\"valid\": true"));

    let applied = rebyte()
        .args([
            "apply",
            "--file",
            path_text(&capsule)?,
            "--trusted-key",
            path_text(&public_key)?,
            "--root",
            path_text(&target)?,
            "--yes",
            "--json",
        ])
        .output()?;
    assert_success(&applied);
    assert_eq!(
        fs::read(target.join("README.txt"))?,
        b"production artifact\n"
    );
    assert_eq!(fs::read(target.join("bin/data.bin"))?, [0_u8, 1, 2, 0xff]);

    let hashed = rebyte()
        .args(["hash", path_text(&source.join("README.txt"))?, "--json"])
        .output()?;
    assert_success(&hashed);
    let hash_json: serde_json::Value = serde_json::from_slice(&hashed.stdout)?;
    let digest = hash_json
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or("hash report has no digest")?;
    let checked = rebyte()
        .args([
            "hash",
            path_text(&source.join("README.txt"))?,
            "--check",
            digest,
        ])
        .output()?;
    assert_success(&checked);

    let revoked_key = directory.path().join("publisher.revoked.json");
    let revoked = rebyte()
        .args([
            "key",
            "status",
            path_text(&public_key)?,
            "--status",
            "revoked",
            "--output",
            path_text(&revoked_key)?,
            "--json",
        ])
        .output()?;
    assert_success(&revoked);
    let rejected = rebyte()
        .args([
            "verify",
            "--file",
            path_text(&capsule)?,
            "--trusted-key",
            path_text(&revoked_key)?,
        ])
        .output()?;
    assert_eq!(
        rejected.status.code(),
        Some(7),
        "{}",
        stderr_text(&rejected)
    );
    Ok(())
}

#[test]
fn version_and_every_command_expose_help() -> Result<(), Box<dyn std::error::Error>> {
    let version = rebyte().arg("--version").output()?;
    assert_success(&version);
    assert!(stdout_text(&version).starts_with("rebyte "));

    for command in [
        "pack",
        "hash",
        "key",
        "inspect",
        "verify",
        "diff",
        "apply",
        "transactions",
        "resume",
        "rollback",
        "doctor",
        "completions",
    ] {
        let help = rebyte().args([command, "-h"]).output()?;
        assert_success(&help);
        assert!(
            stdout_text(&help).contains("Usage:"),
            "help missing for {command}"
        );
    }
    for command in ["generate", "inspect", "status"] {
        let help = rebyte().args(["key", command, "-h"]).output()?;
        assert_success(&help);
        assert!(
            stdout_text(&help).contains("Usage:"),
            "key help missing for {command}"
        );
    }
    Ok(())
}

fn rebyte() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rebyte"))
}

fn path_text(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| "test path is not UTF-8".into())
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", stderr_text(output));
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_creation_mode(&mut options);
    let mut file = options.open(path)?;
    file.write_all(bytes)
}

#[cfg(unix)]
fn set_private_creation_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_creation_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn assert_private_mode(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o077, 0);
    Ok(())
}

#[cfg(not(unix))]
fn assert_private_mode(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
