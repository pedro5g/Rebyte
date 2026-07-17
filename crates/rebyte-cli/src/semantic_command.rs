//! Safe semantic patch creation, inspection and application.

#![allow(clippy::redundant_pub_crate)]

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use rebyte_core::{
    MAX_PATCH_BYTES, PatchFormat, PatchOperation, SemanticError, SemanticPatch,
    apply_semantic_patch, parse_patch,
};
use rebyte_format::SecurityLimits;
use rebyte_integrity::{digest_matches, file_digest};
use serde::Serialize;
use similar::{ChangeTag, TextDiff};

use super::security_io::{read_bounded_nofollow, sync_parent, write_new};
use super::{
    CliError, EXIT_CONFLICT, EXIT_DIGEST, EXIT_GENERIC, EXIT_MALFORMED, encode_digest,
    sanitize_terminal, write_json,
};

const MAX_DIFF_LINES: usize = 400;

#[derive(Debug, Args)]
pub(super) struct PatchCommand {
    #[command(subcommand)]
    command: PatchSubcommand,
}

#[derive(Debug, Subcommand)]
enum PatchSubcommand {
    /// Create a strict, reviewable semantic patch document.
    Create(CreateCommand),
    /// Validate and display a semantic patch without reading a target.
    Inspect(InspectCommand),
    /// Preview and atomically apply a patch to one existing configuration file.
    Apply(ApplyCommand),
}

#[derive(Debug, Args)]
struct CreateCommand {
    /// Target configuration syntax.
    #[arg(long, value_enum)]
    format: FormatArgument,
    /// Optional 64-character RAP file digest required before application.
    #[arg(long, value_name = "HEX")]
    target_digest: Option<String>,
    /// Ordered operation: `test:/pointer=JSON`, `set:/pointer=JSON`, or `remove:/pointer`.
    #[arg(
        short = 'O',
        long = "operation",
        value_name = "EXPRESSION",
        required = true
    )]
    operations: Vec<String>,
    /// New patch document path.
    #[arg(short, long)]
    output: PathBuf,
    /// Emit a stable JSON report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct InspectCommand {
    /// Semantic patch JSON document.
    patch: PathBuf,
    /// Emit a stable JSON report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ApplyCommand {
    /// Semantic patch JSON document.
    patch: PathBuf,
    /// Existing JSON or TOML file to patch.
    #[arg(long)]
    target: PathBuf,
    /// Preview, confirmation and backup controls.
    #[command(flatten)]
    mode: PatchApplyMode,
    /// Emit a stable JSON report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PatchApplyMode {
    /// Validate and preview without modifying the target.
    #[arg(long)]
    dry_run: bool,
    /// Apply without the interactive confirmation prompt.
    #[arg(long)]
    yes: bool,
    /// Retain the exact original as `<target>.rebyte.bak`.
    #[arg(long)]
    backup: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FormatArgument {
    Json,
    Toml,
}

impl FormatArgument {
    const fn value(self) -> PatchFormat {
        match self {
            Self::Json => PatchFormat::Json,
            Self::Toml => PatchFormat::Toml,
        }
    }
}

pub(super) fn run(command: &PatchCommand) -> Result<(), CliError> {
    match &command.command {
        PatchSubcommand::Create(command) => create(command),
        PatchSubcommand::Inspect(command) => inspect(command),
        PatchSubcommand::Apply(command) => apply(command),
    }
}

fn create(command: &CreateCommand) -> Result<(), CliError> {
    let operations = command
        .operations
        .iter()
        .map(|expression| parse_operation(expression))
        .collect::<Result<Vec<_>, _>>()?;
    let patch = SemanticPatch::new(
        command.format.value(),
        command.target_digest.clone(),
        operations,
    )
    .map_err(semantic_error)?;
    let bytes = patch.to_json_bytes().map_err(semantic_error)?;
    write_new(&command.output, &bytes, false).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot create semantic patch: {error}"),
        )
    })?;
    let report = patch_report(&patch, Some(command.output.to_string_lossy().into_owned()));
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Semantic patch created"));
        print_patch_report(&report);
        Ok(())
    }
}

fn inspect(command: &InspectCommand) -> Result<(), CliError> {
    let patch = read_patch(&command.patch)?;
    let report = patch_report(&patch, None);
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Semantic patch is valid"));
        print_patch_report(&report);
        Ok(())
    }
}

fn apply(command: &ApplyCommand) -> Result<(), CliError> {
    if command.mode.dry_run && command.mode.yes {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "--dry-run conflicts with --yes",
        ));
    }
    let patch = read_patch(&command.patch)?;
    let original = read_bounded_nofollow(&command.target, SecurityLimits::V1.max_single_file_bytes)
        .map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot read semantic patch target: {error}"),
            )
        })?;
    let result = apply_semantic_patch(&patch, &original).map_err(semantic_error)?;
    let report = ApplyReport {
        schema_version: 1,
        format: format_name(patch.format()),
        target: command.target.to_string_lossy().into_owned(),
        operations: result.operations_applied(),
        changed: result.changed(),
        before_digest: encode_digest(&result.before_digest()),
        after_digest: encode_digest(&result.after_digest()),
        dry_run: command.mode.dry_run,
        applied: false,
        backup: None,
    };
    if command.mode.dry_run || !result.changed() {
        return emit_apply_report(command, &report, &original, result.bytes());
    }
    if !command.mode.yes {
        if command.json {
            eprintln!(
                "Semantic patch preview: {} operation(s), {} -> {}",
                report.operations, report.before_digest, report.after_digest
            );
        } else {
            emit_preview(&report, &original, result.bytes());
        }
        if !confirm(&command.target)? {
            if command.json {
                return write_json(&report);
            }
            println!("Semantic patch cancelled · no files were written.");
            return Ok(());
        }
    }
    revalidate_target(&command.target, &result.before_digest())?;
    let backup = if command.mode.backup {
        Some(create_backup(&command.target, &original)?)
    } else {
        None
    };
    replace_atomically(&command.target, result.bytes(), &result.before_digest())?;
    let committed =
        read_bounded_nofollow(&command.target, SecurityLimits::V1.max_single_file_bytes).map_err(
            |error| {
                CliError::new(
                    EXIT_GENERIC,
                    format!("cannot verify patched target: {error}"),
                )
            },
        )?;
    if !digest_matches(&file_digest(&committed), &result.after_digest()) {
        return Err(CliError::new(
            EXIT_DIGEST,
            "patched target failed post-write digest verification",
        ));
    }
    let report = ApplyReport {
        applied: true,
        backup: backup.map(|path| path.to_string_lossy().into_owned()),
        ..report
    };
    if command.json {
        write_json(&report)
    } else {
        println!(
            "{}",
            super::ui::success("✓ Semantic patch applied atomically")
        );
        print_apply_summary(&report);
        Ok(())
    }
}

fn emit_apply_report(
    command: &ApplyCommand,
    report: &ApplyReport,
    before: &[u8],
    after: &[u8],
) -> Result<(), CliError> {
    if command.json {
        write_json(report)
    } else {
        emit_preview(report, before, after);
        if report.changed {
            println!("Dry run · no files written.");
        } else {
            println!("Target is already semantically up to date.");
        }
        Ok(())
    }
}

fn emit_preview(report: &ApplyReport, before: &[u8], after: &[u8]) {
    println!("{}", super::ui::heading("Semantic patch preview"));
    print_apply_summary(report);
    let before = String::from_utf8_lossy(before);
    let after = String::from_utf8_lossy(after);
    let diff = TextDiff::from_lines(&before, &after);
    let mut shown = 0_usize;
    for change in diff.iter_all_changes() {
        if shown >= MAX_DIFF_LINES {
            println!("… diff truncated after {MAX_DIFF_LINES} lines");
            break;
        }
        let marker = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        print!("{marker}{}", sanitize_terminal(change.value()));
        shown = shown.saturating_add(1);
    }
}

fn print_apply_summary(report: &ApplyReport) {
    println!("  Format      {}", report.format);
    println!("  Target      {}", report.target);
    println!("  Operations  {}", report.operations);
    println!("  Before      {}", report.before_digest);
    println!("  After       {}", report.after_digest);
    if let Some(backup) = &report.backup {
        println!("  Backup      {backup}");
    }
}

fn confirm(target: &Path) -> Result<bool, CliError> {
    eprint!("Apply this semantic patch to {}? [y/N] ", target.display());
    io::stderr()
        .flush()
        .map_err(|error| CliError::new(EXIT_GENERIC, format!("cannot flush prompt: {error}")))?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).map_err(|error| {
        CliError::new(EXIT_GENERIC, format!("cannot read confirmation: {error}"))
    })?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn read_patch(path: &Path) -> Result<SemanticPatch, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_PATCH_BYTES).map_err(|error| {
        CliError::new(EXIT_GENERIC, format!("cannot read semantic patch: {error}"))
    })?;
    parse_patch(&bytes).map_err(semantic_error)
}

fn parse_operation(expression: &str) -> Result<PatchOperation, CliError> {
    if let Some(path) = expression.strip_prefix("remove:") {
        return Ok(PatchOperation::Remove {
            path: path.to_string(),
        });
    }
    let (kind, remainder) = expression.split_once(':').ok_or_else(|| {
        CliError::new(
            EXIT_MALFORMED,
            "operation must start with test:, set:, or remove:",
        )
    })?;
    let (path, value) = remainder
        .split_once('=')
        .ok_or_else(|| CliError::new(EXIT_MALFORMED, "test/set operation must use POINTER=JSON"))?;
    let value = serde_json::from_str(value)
        .map_err(|_| CliError::new(EXIT_MALFORMED, "operation value is not valid JSON"))?;
    match kind {
        "test" => Ok(PatchOperation::Test {
            path: path.to_string(),
            value,
        }),
        "set" => Ok(PatchOperation::Set {
            path: path.to_string(),
            value,
        }),
        _ => Err(CliError::new(
            EXIT_MALFORMED,
            "operation must start with test:, set:, or remove:",
        )),
    }
}

fn revalidate_target(path: &Path, expected: &rebyte_format::Digest32) -> Result<(), CliError> {
    let bytes =
        read_bounded_nofollow(path, SecurityLimits::V1.max_single_file_bytes).map_err(|error| {
            CliError::new(
                EXIT_CONFLICT,
                format!("cannot revalidate semantic patch target: {error}"),
            )
        })?;
    if digest_matches(&file_digest(&bytes), expected) {
        Ok(())
    } else {
        Err(CliError::new(
            EXIT_CONFLICT,
            "semantic patch target changed after preview",
        ))
    }
}

fn create_backup(target: &Path, original: &[u8]) -> Result<PathBuf, CliError> {
    let mut name: OsString = target.as_os_str().to_owned();
    name.push(".rebyte.bak");
    let backup = PathBuf::from(name);
    write_new(&backup, original, false).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot create semantic patch backup: {error}"),
        )
    })?;
    preserve_permissions(target, &backup)?;
    synchronize_backup_metadata(&backup)?;
    Ok(backup)
}

#[cfg(unix)]
fn synchronize_backup_metadata(backup: &Path) -> Result<(), CliError> {
    // `write_new` already syncs the bytes. This second sync persists the mode
    // copied by `preserve_permissions` before the original file is replaced.
    std::fs::File::open(backup)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot synchronize semantic patch backup: {error}"),
            )
        })
}

#[cfg(not(unix))]
fn synchronize_backup_metadata(_backup: &Path) -> Result<(), CliError> {
    // `File::open` creates a read-only Windows handle and `sync_all` maps to
    // `FlushFileBuffers`, which rejects that handle. `write_new` has already
    // flushed the writable file handle; there is no Unix mode change to sync.
    Ok(())
}

fn replace_atomically(
    target: &Path,
    bytes: &[u8],
    expected: &rebyte_format::Digest32,
) -> Result<(), CliError> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::Builder::new()
        .prefix(".rebyte-semantic-")
        .tempfile_in(parent)
        .map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot stage semantic patch: {error}"),
            )
        })?;
    staged.write_all(bytes).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot write semantic patch staging file: {error}"),
        )
    })?;
    preserve_permissions(target, staged.path())?;
    staged.as_file().sync_all().map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot synchronize semantic patch: {error}"),
        )
    })?;
    revalidate_target(target, expected)?;
    staged.persist(target).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot commit semantic patch: {}", error.error),
        )
    })?;
    sync_parent(target).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot synchronize patched directory: {error}"),
        )
    })
}

#[cfg(unix)]
fn preserve_permissions(source: &Path, staged: &Path) -> Result<(), CliError> {
    let permissions = std::fs::symlink_metadata(source)
        .map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot inspect target permissions: {error}"),
            )
        })?
        .permissions();
    std::fs::set_permissions(staged, permissions).map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot preserve target permissions: {error}"),
        )
    })
}

#[cfg(not(unix))]
fn preserve_permissions(_source: &Path, _staged: &Path) -> Result<(), CliError> {
    Ok(())
}

fn semantic_error(error: SemanticError) -> CliError {
    let exit_code = match error {
        SemanticError::TargetDigestMismatch => EXIT_DIGEST,
        SemanticError::TestFailed | SemanticError::MissingPath | SemanticError::TypeConflict => {
            EXIT_CONFLICT
        }
        _ => EXIT_MALFORMED,
    };
    CliError::new(exit_code, error.to_string())
}

fn patch_report(patch: &SemanticPatch, output: Option<String>) -> PatchReport {
    PatchReport {
        schema_version: 1,
        patch_schema_version: patch.schema_version(),
        format: format_name(patch.format()),
        target_digest: patch.target_digest().map(ToString::to_string),
        operations: u32::try_from(patch.operations().len()).unwrap_or(u32::MAX),
        output,
    }
}

fn print_patch_report(report: &PatchReport) {
    println!("  Format      {}", report.format);
    println!("  Operations  {}", report.operations);
    if let Some(digest) = &report.target_digest {
        println!("  Precondition {digest}");
    } else {
        println!("  Precondition semantic tests only");
    }
    if let Some(output) = &report.output {
        println!("  Output      {output}");
    }
}

const fn format_name(format: PatchFormat) -> &'static str {
    match format {
        PatchFormat::Json => "json",
        PatchFormat::Toml => "toml",
        _ => "unknown",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PatchReport {
    schema_version: u16,
    patch_schema_version: u16,
    format: &'static str,
    target_digest: Option<String>,
    operations: u32,
    output: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyReport {
    schema_version: u16,
    format: &'static str,
    target: String,
    operations: u32,
    changed: bool,
    before_digest: String,
    after_digest: String,
    dry_run: bool,
    applied: bool,
    backup: Option<String>,
}
