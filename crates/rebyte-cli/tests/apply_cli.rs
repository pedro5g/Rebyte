//! Cross-process application and recovery tests for the Rebyte CLI.

#![forbid(unsafe_code)]

use core::convert::Infallible;
use std::fs;
use std::process::Command;

use ed25519_dalek::SigningKey;
use rebyte_format::CompressionAlgorithm;
use rebyte_pack::{ArtifactFile, PackOptions, pack};
use rebyte_signature::Signer;
use rebyte_verify::sign_capsule;
use tempfile::tempdir;

const DEVELOPMENT_PUBLIC_KEY: [u8; 32] = [
    88, 147, 102, 4, 171, 218, 17, 43, 201, 73, 51, 86, 156, 130, 248, 208, 204, 13, 223, 146, 163,
    248, 50, 159, 47, 68, 143, 127, 72, 74, 89, 76,
];
const DEVELOPMENT_TEST_SEED: [u8; 32] = [0x24; 32];

struct DevelopmentSigner(SigningKey);

impl Signer for DevelopmentSigner {
    type Error = Infallible;

    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok(ed25519_dalek::Signer::sign(&self.0, message).to_bytes())
    }
}

#[test]
fn apply_backup_and_rollback_cross_process() -> Result<(), Box<dyn std::error::Error>> {
    let signer = DevelopmentSigner(SigningKey::from_bytes(&DEVELOPMENT_TEST_SEED));
    assert_eq!(signer.public_key(), DEVELOPMENT_PUBLIC_KEY);
    let directory = tempdir()?;
    let root = directory.path().join("root");
    fs::create_dir(&root)?;
    fs::write(root.join("existing.txt"), b"before\n")?;
    let mut options = PackOptions::new("cli-integration-test")?;
    options.compression = CompressionAlgorithm::None;
    let unsigned = pack(
        &[
            ArtifactFile::new("existing.txt", b"after\n".to_vec())?,
            ArtifactFile::new("nested/created.bin", vec![0, 1, 0xff])?,
        ],
        &options,
    )?;
    let capsule = sign_capsule(&unsigned, &signer)?;
    let capsule_path = directory.path().join("fixture.rbc");
    fs::write(&capsule_path, capsule.as_bytes())?;

    let dry_run = rebyte()
        .args([
            "apply",
            "--file",
            path_text(&capsule_path)?,
            "--root",
            path_text(&root)?,
            "--trust-channel",
            "development",
            "--dry-run",
            "--json",
        ])
        .output()?;
    assert!(dry_run.status.success(), "{}", stderr_text(&dry_run));
    assert!(stdout_text(&dry_run).contains("\"dryRun\": true"));
    assert_eq!(fs::read(root.join("existing.txt"))?, b"before\n");
    assert!(!root.join("nested/created.bin").exists());

    let applied = rebyte()
        .args([
            "apply",
            "--file",
            path_text(&capsule_path)?,
            "--root",
            path_text(&root)?,
            "--trust-channel",
            "development",
            "--yes",
            "--backup",
            "--json",
        ])
        .output()?;
    assert!(applied.status.success(), "{}", stderr_text(&applied));
    assert_eq!(fs::read(root.join("existing.txt"))?, b"after\n");
    assert_eq!(fs::read(root.join("nested/created.bin"))?, [0, 1, 0xff]);
    let transaction_id = json_string_field(&stdout_text(&applied), "transactionId")?;

    let listed = rebyte()
        .args(["transactions", "--root", path_text(&root)?, "--json"])
        .output()?;
    assert!(listed.status.success(), "{}", stderr_text(&listed));
    assert!(stdout_text(&listed).contains(&transaction_id));

    let rolled_back = rebyte()
        .args([
            "rollback",
            &transaction_id,
            "--root",
            path_text(&root)?,
            "--json",
        ])
        .output()?;
    assert!(
        rolled_back.status.success(),
        "{}",
        stderr_text(&rolled_back)
    );
    assert_eq!(fs::read(root.join("existing.txt"))?, b"before\n");
    assert!(!root.join("nested/created.bin").exists());
    Ok(())
}

fn rebyte() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rebyte"))
}

fn path_text(path: &std::path::Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| "test path is not UTF-8".into())
}

fn stdout_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json_string_field(document: &str, field: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(document)?;
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing JSON string field {field}").into())
}
