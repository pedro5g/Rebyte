//! End-to-end semantic patch safety and reconstruction.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

#[test]
fn toml_patch_previews_applies_backs_up_and_preserves_comments()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let target = directory.path().join("service.toml");
    let patch = directory.path().join("emergency.rbp.json");
    let original = b"# production service\n[server]\nport = 80 # public listener\nlegacy = true\n";
    fs::write(&target, original)?;
    let digest = hash_digest(&target)?;

    let created = rebyte()
        .args([
            "patch",
            "create",
            "--format",
            "toml",
            "--target-digest",
            &digest,
            "--operation",
            "test:/server/port=80",
            "--operation",
            "set:/server/port=8080",
            "--operation",
            "remove:/server/legacy",
            "--output",
            path_text(&patch)?,
            "--json",
        ])
        .output()?;
    assert_success(&created);

    let inspected = rebyte()
        .args(["patch", "inspect", path_text(&patch)?, "--json"])
        .output()?;
    assert_success(&inspected);
    assert!(stdout_text(&inspected).contains("\"operations\": 3"));

    let preview = rebyte()
        .args([
            "patch",
            "apply",
            path_text(&patch)?,
            "--target",
            path_text(&target)?,
            "--dry-run",
        ])
        .output()?;
    assert_success(&preview);
    assert!(stdout_text(&preview).contains("+port = 8080 # public listener"));
    assert_eq!(fs::read(&target)?, original);

    let applied = rebyte()
        .args([
            "patch",
            "apply",
            path_text(&patch)?,
            "--target",
            path_text(&target)?,
            "--yes",
            "--backup",
            "--json",
        ])
        .output()?;
    assert_success(&applied);
    assert!(stdout_text(&applied).contains("\"applied\": true"));
    let updated = fs::read_to_string(&target)?;
    assert!(updated.contains("# production service"));
    assert!(updated.contains("port = 8080 # public listener"));
    assert!(!updated.contains("legacy"));
    let mut backup_name = target.as_os_str().to_owned();
    backup_name.push(".rebyte.bak");
    assert_eq!(fs::read(std::path::PathBuf::from(backup_name))?, original);

    let stale = rebyte()
        .args([
            "patch",
            "apply",
            path_text(&patch)?,
            "--target",
            path_text(&target)?,
            "--yes",
        ])
        .output()?;
    assert_eq!(stale.status.code(), Some(5));
    assert!(fs::read_to_string(&target)?.contains("port = 8080"));
    Ok(())
}

#[test]
fn json_patch_handles_arrays_and_rejects_duplicate_patch_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let target = directory.path().join("service.json");
    let patch = directory.path().join("service.rbp.json");
    fs::write(&target, br#"{"ports":[80],"enabled":true}"#)?;

    let created = rebyte()
        .args([
            "patch",
            "create",
            "--format",
            "json",
            "--operation",
            "test:/enabled=true",
            "--operation",
            "set:/ports/-=443",
            "--operation",
            "set:/enabled=false",
            "--output",
            path_text(&patch)?,
        ])
        .output()?;
    assert_success(&created);
    let applied = rebyte()
        .args([
            "patch",
            "apply",
            path_text(&patch)?,
            "--target",
            path_text(&target)?,
            "--yes",
        ])
        .output()?;
    assert_success(&applied);
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&target)?)?;
    assert_eq!(value["ports"], serde_json::json!([80, 443]));
    assert_eq!(value["enabled"], false);

    let duplicate = directory.path().join("duplicate.json");
    fs::write(
        &duplicate,
        br#"{"schemaVersion":1,"format":"json","format":"toml","operations":[]}"#,
    )?;
    let rejected = rebyte()
        .args(["patch", "inspect", path_text(&duplicate)?])
        .output()?;
    assert!(!rejected.status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn semantic_patch_rejects_symlink_targets() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempdir()?;
    let outside = directory.path().join("outside.json");
    let target = directory.path().join("target.json");
    let patch = directory.path().join("patch.json");
    fs::write(&outside, br#"{"safe":true}"#)?;
    symlink(&outside, &target)?;
    let created = rebyte()
        .args([
            "patch",
            "create",
            "--format",
            "json",
            "--operation",
            "set:/safe=false",
            "--output",
            path_text(&patch)?,
        ])
        .output()?;
    assert_success(&created);
    let rejected = rebyte()
        .args([
            "patch",
            "apply",
            path_text(&patch)?,
            "--target",
            path_text(&target)?,
            "--yes",
        ])
        .output()?;
    assert!(!rejected.status.success());
    assert_eq!(fs::read(&outside)?, br#"{"safe":true}"#);
    Ok(())
}

fn hash_digest(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = rebyte()
        .args(["hash", path_text(path)?, "--json"])
        .output()?;
    assert_success(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    value["digest"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| "hash output omitted digest".into())
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
