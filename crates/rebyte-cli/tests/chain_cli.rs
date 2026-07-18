//! End-to-end self-custodied consensus and encrypted reconstruction.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

#[test]
#[allow(clippy::too_many_lines)] // One scenario verifies every Chain state transition.
fn consensus_capsule_reconstructs_directory_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let source = directory.path().join("source");
    let restored = directory.path().join("restored");
    let applied = directory.path().join("applied");
    fs::create_dir(&source)?;
    fs::create_dir(&applied)?;
    fs::create_dir(source.join("empty"))?;
    fs::write(
        source.join("message.txt"),
        b"Only the authorized Chain recipient can reconstruct this.\n",
    )?;
    fs::write(source.join("binary.dat"), [0_u8, 1, 2, 0xff])?;

    let passphrase = directory.path().join("passphrase.txt");
    write_private(&passphrase, b"chain integration passphrase\n")?;
    let private = directory.path().join("owner.rbk");
    let public = directory.path().join("owner.public.json");
    let artifact = directory.path().join("source.rba");
    let group_proposal = directory.path().join("owners.rbgp.json");
    let acceptance = directory.path().join("owner.rbga.json");
    let group = directory.path().join("owners.rbg.json");
    let capsule_proposal = directory.path().join("release.rbep");
    let approval = directory.path().join("owner.rbca.json");
    let capsule = directory.path().join("release.rbe");

    assert_success(
        &rebyte()
            .args([
                "chain",
                "identity",
                "generate",
                "--name",
                "Owner",
                "--private-key",
                path_text(&private)?,
                "--public-key",
                path_text(&public)?,
                "--passphrase-file",
                path_text(&passphrase)?,
                "--json",
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "chain",
                "identity",
                "inspect",
                path_text(&public)?,
                "--json",
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "encode",
                path_text(&source)?,
                "--format",
                "binary",
                "--output",
                path_text(&artifact)?,
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "chain",
                "group",
                "create",
                "--name",
                "Release owners",
                "--member",
                path_text(&public)?,
                "--threshold",
                "1",
                "--output",
                path_text(&group_proposal)?,
                "--json",
            ])
            .output()?,
    );
    let inspected_group_proposal = rebyte()
        .args([
            "chain",
            "group",
            "inspect",
            path_text(&group_proposal)?,
            "--json",
        ])
        .output()?;
    assert_success(&inspected_group_proposal);
    assert!(stdout_text(&inspected_group_proposal).contains("\"formationComplete\": false"));
    assert_success(
        &rebyte()
            .args([
                "chain",
                "group",
                "accept",
                path_text(&group_proposal)?,
                "--private-key",
                path_text(&private)?,
                "--passphrase-file",
                path_text(&passphrase)?,
                "--output",
                path_text(&acceptance)?,
                "--json",
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "chain",
                "group",
                "finalize",
                path_text(&group_proposal)?,
                "--acceptance",
                path_text(&acceptance)?,
                "--output",
                path_text(&group)?,
                "--json",
            ])
            .output()?,
    );
    let inspected_group = rebyte()
        .args(["chain", "group", "inspect", path_text(&group)?, "--json"])
        .output()?;
    assert_success(&inspected_group);
    assert!(stdout_text(&inspected_group).contains("\"formationComplete\": true"));

    assert_success(
        &rebyte()
            .args([
                "chain",
                "capsule",
                "create",
                "--group",
                path_text(&group)?,
                "--artifact",
                path_text(&artifact)?,
                "--recipient",
                path_text(&public)?,
                "--output",
                path_text(&capsule_proposal)?,
                "--json",
            ])
            .output()?,
    );
    let inspected_capsule_proposal = rebyte()
        .args([
            "chain",
            "capsule",
            "inspect",
            "--file",
            path_text(&capsule_proposal)?,
            "--json",
        ])
        .output()?;
    assert_success(&inspected_capsule_proposal);
    assert!(stdout_text(&inspected_capsule_proposal).contains("\"finalized\": false"));
    assert_success(
        &rebyte()
            .args([
                "chain",
                "capsule",
                "approve",
                path_text(&capsule_proposal)?,
                "--private-key",
                path_text(&private)?,
                "--passphrase-file",
                path_text(&passphrase)?,
                "--output",
                path_text(&approval)?,
                "--json",
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "chain",
                "capsule",
                "finalize",
                path_text(&capsule_proposal)?,
                "--approval",
                path_text(&approval)?,
                "--output",
                path_text(&capsule)?,
                "--json",
            ])
            .output()?,
    );
    let inspected_capsule = rebyte()
        .args([
            "chain",
            "capsule",
            "inspect",
            "--file",
            path_text(&capsule)?,
            "--json",
        ])
        .output()?;
    assert_success(&inspected_capsule);
    assert!(stdout_text(&inspected_capsule).contains("\"finalized\": true"));
    assert!(stdout_text(&inspected_capsule).contains("\"contractId\""));
    assert!(stdout_text(&inspected_capsule).contains("\"releasePolicy\": \"directRecipients\""));

    let diff = rebyte()
        .args([
            "chain",
            "capsule",
            "diff",
            "--file",
            path_text(&capsule)?,
            "--private-key",
            path_text(&private)?,
            "--passphrase-file",
            path_text(&passphrase)?,
            "--root",
            path_text(&applied)?,
            "--json",
        ])
        .output()?;
    assert_success(&diff);
    assert!(stdout_text(&diff).contains("\"kind\": \"create\""));
    assert!(stdout_text(&diff).contains("\"path\": \"empty\""));

    let dry_run = rebyte()
        .args([
            "chain",
            "capsule",
            "apply",
            "--file",
            path_text(&capsule)?,
            "--private-key",
            path_text(&private)?,
            "--passphrase-file",
            path_text(&passphrase)?,
            "--root",
            path_text(&applied)?,
            "--dry-run",
            "--json",
        ])
        .output()?;
    assert_success(&dry_run);
    assert!(stdout_text(&dry_run).contains("\"status\": \"preview\""));
    assert!(!applied.join("message.txt").exists());
    assert!(!applied.join("empty").exists());

    let apply = rebyte()
        .args([
            "chain",
            "capsule",
            "apply",
            "--file",
            path_text(&capsule)?,
            "--private-key",
            path_text(&private)?,
            "--passphrase-file",
            path_text(&passphrase)?,
            "--root",
            path_text(&applied)?,
            "--yes",
            "--json",
        ])
        .output()?;
    assert_success(&apply);
    assert!(stdout_text(&apply).contains("\"status\": \"applied\""));
    assert!(stdout_text(&apply).contains("\"directoriesEnsured\": 1"));
    assert_eq!(
        fs::read(applied.join("message.txt"))?,
        fs::read(source.join("message.txt"))?
    );
    assert_eq!(
        fs::read(applied.join("binary.dat"))?,
        fs::read(source.join("binary.dat"))?
    );
    assert!(applied.join("empty").is_dir());

    let patch = directory.path().join("emergency.patch.json");
    let patch_target = directory.path().join("service.json");
    let patch_proposal = directory.path().join("emergency.rbep");
    let patch_approval = directory.path().join("emergency.rbca.json");
    let patch_capsule = directory.path().join("emergency.rbe");
    fs::write(
        &patch_target,
        br#"{"service":{"port":80,"name":"api"}}"#.as_slice(),
    )?;
    assert_success(
        &rebyte()
            .args([
                "patch",
                "create",
                "--format",
                "json",
                "--operation",
                "set:/service/port=8080",
                "--output",
                path_text(&patch)?,
                "--json",
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "chain",
                "capsule",
                "create",
                "--group",
                path_text(&group)?,
                "--patch",
                path_text(&patch)?,
                "--recipient",
                path_text(&public)?,
                "--output",
                path_text(&patch_proposal)?,
                "--json",
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "chain",
                "capsule",
                "approve",
                path_text(&patch_proposal)?,
                "--private-key",
                path_text(&private)?,
                "--passphrase-file",
                path_text(&passphrase)?,
                "--output",
                path_text(&patch_approval)?,
                "--json",
            ])
            .output()?,
    );
    assert_success(
        &rebyte()
            .args([
                "chain",
                "capsule",
                "finalize",
                path_text(&patch_proposal)?,
                "--approval",
                path_text(&patch_approval)?,
                "--output",
                path_text(&patch_capsule)?,
                "--json",
            ])
            .output()?,
    );
    let patch_preview = rebyte()
        .args([
            "chain",
            "capsule",
            "patch",
            "--file",
            path_text(&patch_capsule)?,
            "--private-key",
            path_text(&private)?,
            "--passphrase-file",
            path_text(&passphrase)?,
            "--target",
            path_text(&patch_target)?,
            "--dry-run",
            "--json",
        ])
        .output()?;
    assert_success(&patch_preview);
    assert!(stdout_text(&patch_preview).contains("\"authorization\": \"Chain contract"));
    assert!(String::from_utf8(fs::read(&patch_target)?)?.contains("\"port\":80"));
    let patch_apply = rebyte()
        .args([
            "chain",
            "capsule",
            "patch",
            "--file",
            path_text(&patch_capsule)?,
            "--private-key",
            path_text(&private)?,
            "--passphrase-file",
            path_text(&passphrase)?,
            "--target",
            path_text(&patch_target)?,
            "--yes",
            "--backup",
            "--json",
        ])
        .output()?;
    assert_success(&patch_apply);
    assert!(stdout_text(&patch_apply).contains("\"applied\": true"));
    assert!(String::from_utf8(fs::read(&patch_target)?)?.contains("8080"));
    assert!(patch_target.with_extension("json.rebyte.bak").exists());

    assert_success(
        &rebyte()
            .args([
                "chain",
                "capsule",
                "open",
                "--file",
                path_text(&capsule)?,
                "--private-key",
                path_text(&private)?,
                "--passphrase-file",
                path_text(&passphrase)?,
                "--output",
                path_text(&restored)?,
                "--json",
            ])
            .output()?,
    );
    assert_eq!(
        fs::read(restored.join("message.txt"))?,
        fs::read(source.join("message.txt"))?
    );
    assert_eq!(
        fs::read(restored.join("binary.dat"))?,
        fs::read(source.join("binary.dat"))?
    );
    assert!(restored.join("empty").is_dir());
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
    assert!(
        output.status.success(),
        "status: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout_text(output),
        stderr_text(output)
    );
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
