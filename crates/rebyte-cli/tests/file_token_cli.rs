//! End-to-end unsigned single-file token workflow.

#![forbid(unsafe_code)]

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::tempdir;

#[test]
fn large_text_round_trips_through_a_short_token() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let original = directory.path().join("large.txt");
    let reconstructed = directory.path().join("reconstructed.txt");
    let mut text = String::new();
    for index in 0..25_000 {
        use std::fmt::Write as _;

        writeln!(
            text,
            "Linha {index:05}: conteúdo extenso para validar reconstrução, compressão e integridade."
        )?;
    }
    fs::write(&original, text.as_bytes())?;

    let encoded = rebyte().args(["encode", path_text(&original)?]).output()?;
    assert_success(&encoded);
    let token = stdout_text(&encoded).trim().to_string();
    assert!(token.starts_with("rf1_"));
    assert!(token.len() < text.len() / 4);

    let decoded = rebyte()
        .args(["decode", &token, "--output", path_text(&reconstructed)?])
        .output()?;
    assert_success(&decoded);
    assert_eq!(fs::read(&reconstructed)?, text.as_bytes());

    let original_hash = hash_digest(&original)?;
    let reconstructed_hash = hash_digest(&reconstructed)?;
    assert_eq!(original_hash, reconstructed_hash);
    Ok(())
}

#[test]
fn token_files_stdin_json_integrity_and_no_overwrite_are_enforced()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let input = b"stdin bytes with zeros\0and exact newlines\n";
    let token_file = directory.path().join("payload.rf1");
    let output = directory.path().join("output.bin");

    let mut encode = rebyte()
        .args([
            "encode",
            "-",
            "--compression",
            "none",
            "--output",
            path_text(&token_file)?,
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    encode
        .stdin
        .take()
        .ok_or("encode stdin pipe is unavailable")?
        .write_all(input)?;
    let encoded = encode.wait_with_output()?;
    assert_success(&encoded);
    assert!(stdout_text(&encoded).contains("\"authenticated\": false"));
    assert!(fs::read_to_string(&token_file)?.starts_with("rf1_"));

    let decoded = rebyte()
        .args([
            "decode",
            "--file",
            path_text(&token_file)?,
            "--output",
            path_text(&output)?,
            "--json",
        ])
        .output()?;
    assert_success(&decoded);
    assert!(stdout_text(&decoded).contains("\"integrityVerified\": true"));
    assert_eq!(fs::read(&output)?, input);

    let overwrite = rebyte()
        .args([
            "decode",
            "--file",
            path_text(&token_file)?,
            "--output",
            path_text(&output)?,
        ])
        .output()?;
    assert!(!overwrite.status.success());

    let mut token = fs::read_to_string(&token_file)?;
    let last = token
        .trim_end()
        .len()
        .checked_sub(1)
        .ok_or("token is empty")?;
    token.replace_range(
        last..=last,
        if &token[last..=last] == "A" { "B" } else { "A" },
    );
    let corrupted_output = directory.path().join("corrupted.bin");
    let corrupted = rebyte()
        .args([
            "decode",
            token.trim(),
            "--output",
            path_text(&corrupted_output)?,
        ])
        .output()?;
    assert!(!corrupted.status.success());
    assert!(!corrupted_output.exists());
    Ok(())
}

#[test]
fn shell_env_emits_all_supported_assignment_syntax() -> Result<(), Box<dyn std::error::Error>> {
    for (shell, marker) in [
        ("bash", "export REBYTE='"),
        ("zsh", "export REBYTE='"),
        ("fish", "set -gx REBYTE '"),
        ("powershell", "$env:REBYTE = '"),
    ] {
        let output = rebyte().args(["shell-env", shell]).output()?;
        assert_success(&output);
        assert!(stdout_text(&output).starts_with(marker));
    }
    Ok(())
}

fn hash_digest(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = rebyte()
        .args(["hash", path_text(path)?, "--json"])
        .output()?;
    assert_success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    report
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "hash report has no digest".into())
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
    assert!(
        output.status.success(),
        "status: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout_text(output),
        stderr_text(output)
    );
}
