//! Read-only comparison of fully verified capsules with a local root.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use rebyte_format::{ContentKind, RelativeArtifactPath};
use rebyte_verify::{FullyVerifiedCapsule, VerifiedFile};
use similar::{ChangeTag, TextDiff};

/// High-level effect a verified file would have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChangeKind {
    /// Target does not exist.
    Create,
    /// Target already has the exact verified bytes.
    Unchanged,
    /// UTF-8 target differs and a textual diff is available.
    UpdateText,
    /// Target differs but at least one side is binary.
    UpdateBinary,
}

/// Comparison result for one verified file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffEntry {
    /// Portable verified path.
    pub path: RelativeArtifactPath,
    /// Planned change kind.
    pub kind: ChangeKind,
    /// Existing byte count, or zero for a create.
    pub old_size: u64,
    /// Verified replacement byte count.
    pub new_size: u64,
    /// Inserted text lines.
    pub added_lines: u64,
    /// Removed text lines.
    pub removed_lines: u64,
    /// Unified text diff when both sides are valid UTF-8.
    pub unified_text: Option<String>,
}

/// Aggregate read-only diff statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiffSummary {
    /// Missing files that would be created.
    pub created: u32,
    /// Existing files that would be updated.
    pub updated: u32,
    /// Existing files already equal to the capsule.
    pub unchanged: u32,
    /// Total verified bytes in the plan.
    pub bytes: u64,
    /// Total inserted text lines.
    pub added_lines: u64,
    /// Total removed text lines.
    pub removed_lines: u64,
}

/// Complete comparison report in canonical path order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiffReport {
    /// Per-file changes.
    pub entries: Vec<DiffEntry>,
    /// Aggregate statistics.
    pub summary: DiffSummary,
}

/// Compares a fully verified capsule with a capability-confined local root.
///
/// # Errors
///
/// Returns [`DiffError`] when the root cannot be opened, a target is a symlink
/// or non-file, a confined read fails, or a length cannot be represented.
pub fn diff_capsule(capsule: &FullyVerifiedCapsule, root: &Path) -> Result<DiffReport, DiffError> {
    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| DiffError::Root(error.kind()))?;
    let mut report = DiffReport::default();
    for file in capsule.files() {
        let existing = read_existing(&directory, file.path.as_str())?;
        let entry = compare_file(file, existing.as_deref())?;
        accumulate(&mut report.summary, &entry)?;
        report.entries.push(entry);
    }
    Ok(report)
}

/// Read-only diff failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiffError {
    /// Root directory could not be opened.
    Root(io::ErrorKind),
    /// Confined target metadata or bytes could not be read.
    Io(io::ErrorKind),
    /// Final target was a symbolic link.
    SymlinkTarget,
    /// Final target existed but was not a regular file.
    NotRegularFile,
    /// Platform length conversion or summary arithmetic overflowed.
    LengthOverflow,
}

impl fmt::Display for DiffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(kind) => write!(formatter, "cannot open root directory: {kind}"),
            Self::Io(kind) => write!(formatter, "cannot read confined target: {kind}"),
            Self::SymlinkTarget => formatter.write_str("target is a symbolic link"),
            Self::NotRegularFile => formatter.write_str("target is not a regular file"),
            Self::LengthOverflow => formatter.write_str("diff length overflow"),
        }
    }
}

impl std::error::Error for DiffError {}

fn read_existing(directory: &Dir, path: &str) -> Result<Option<Vec<u8>>, DiffError> {
    let metadata = match directory.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DiffError::Io(error.kind())),
    };
    if metadata.file_type().is_symlink() {
        return Err(DiffError::SymlinkTarget);
    }
    if !metadata.is_file() {
        return Err(DiffError::NotRegularFile);
    }
    directory
        .read(path)
        .map(Some)
        .map_err(|error| DiffError::Io(error.kind()))
}

fn compare_file(file: &VerifiedFile, existing: Option<&[u8]>) -> Result<DiffEntry, DiffError> {
    let new_size = u64::try_from(file.bytes.len()).map_err(|_| DiffError::LengthOverflow)?;
    let Some(existing) = existing else {
        return compare_text(file, &[], ChangeKind::Create, 0, new_size);
    };
    let old_size = u64::try_from(existing.len()).map_err(|_| DiffError::LengthOverflow)?;
    if existing == file.bytes {
        return Ok(DiffEntry {
            path: file.path.clone(),
            kind: ChangeKind::Unchanged,
            old_size,
            new_size,
            added_lines: 0,
            removed_lines: 0,
            unified_text: None,
        });
    }
    if file.content_kind == ContentKind::TextUtf8 && core::str::from_utf8(existing).is_ok() {
        compare_text(file, existing, ChangeKind::UpdateText, old_size, new_size)
    } else {
        Ok(DiffEntry {
            path: file.path.clone(),
            kind: ChangeKind::UpdateBinary,
            old_size,
            new_size,
            added_lines: 0,
            removed_lines: 0,
            unified_text: None,
        })
    }
}

fn compare_text(
    file: &VerifiedFile,
    existing: &[u8],
    kind: ChangeKind,
    old_size: u64,
    new_size: u64,
) -> Result<DiffEntry, DiffError> {
    if file.content_kind != ContentKind::TextUtf8 {
        return Ok(DiffEntry {
            path: file.path.clone(),
            kind: ChangeKind::Create,
            old_size,
            new_size,
            added_lines: 0,
            removed_lines: 0,
            unified_text: None,
        });
    }
    let old_text = core::str::from_utf8(existing).map_err(|_| DiffError::NotRegularFile)?;
    let new_text = core::str::from_utf8(&file.bytes).map_err(|_| DiffError::NotRegularFile)?;
    let diff = TextDiff::from_lines(old_text, new_text);
    let mut added_lines = 0_u64;
    let mut removed_lines = 0_u64;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => removed_lines = removed_lines.saturating_add(1),
            ChangeTag::Insert => added_lines = added_lines.saturating_add(1),
            ChangeTag::Equal => {}
        }
    }
    let unified_text = Some(
        diff.unified_diff()
            .header("existing", "capsule")
            .to_string(),
    );
    Ok(DiffEntry {
        path: file.path.clone(),
        kind,
        old_size,
        new_size,
        added_lines,
        removed_lines,
        unified_text,
    })
}

fn accumulate(summary: &mut DiffSummary, entry: &DiffEntry) -> Result<(), DiffError> {
    match entry.kind {
        ChangeKind::Create => {
            summary.created = summary
                .created
                .checked_add(1)
                .ok_or(DiffError::LengthOverflow)?;
        }
        ChangeKind::UpdateText | ChangeKind::UpdateBinary => {
            summary.updated = summary
                .updated
                .checked_add(1)
                .ok_or(DiffError::LengthOverflow)?;
        }
        ChangeKind::Unchanged => {
            summary.unchanged = summary
                .unchanged
                .checked_add(1)
                .ok_or(DiffError::LengthOverflow)?;
        }
    }
    summary.bytes = summary
        .bytes
        .checked_add(entry.new_size)
        .ok_or(DiffError::LengthOverflow)?;
    summary.added_lines = summary
        .added_lines
        .checked_add(entry.added_lines)
        .ok_or(DiffError::LengthOverflow)?;
    summary.removed_lines = summary
        .removed_lines
        .checked_add(entry.removed_lines)
        .ok_or(DiffError::LengthOverflow)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rebyte_format::{ContentKind, RelativeArtifactPath};
    use rebyte_verify::VerifiedFile;

    use super::{ChangeKind, DiffError, compare_file};

    fn text_file() -> Result<VerifiedFile, rebyte_format::PathError> {
        Ok(VerifiedFile {
            path: RelativeArtifactPath::new("file.txt")?,
            bytes: b"new\nline\n".to_vec(),
            executable: false,
            content_kind: ContentKind::TextUtf8,
        })
    }

    #[test]
    fn exact_bytes_are_unchanged() -> Result<(), DiffError> {
        let file = text_file().map_err(|_| DiffError::NotRegularFile)?;
        let entry = compare_file(&file, Some(&file.bytes))?;
        assert_eq!(entry.kind, ChangeKind::Unchanged);
        assert!(entry.unified_text.is_none());
        Ok(())
    }

    #[test]
    fn text_update_counts_lines() -> Result<(), DiffError> {
        let file = text_file().map_err(|_| DiffError::NotRegularFile)?;
        let entry = compare_file(&file, Some(b"old\nline\n"))?;
        assert_eq!(entry.kind, ChangeKind::UpdateText);
        assert_eq!(entry.added_lines, 1);
        assert_eq!(entry.removed_lines, 1);
        assert!(entry.unified_text.is_some());
        Ok(())
    }

    #[test]
    fn binary_create_has_no_text_diff() -> Result<(), DiffError> {
        let file = VerifiedFile {
            path: RelativeArtifactPath::new("file.bin").map_err(|_| DiffError::NotRegularFile)?,
            bytes: vec![0xff],
            executable: false,
            content_kind: ContentKind::Binary,
        };
        let entry = compare_file(&file, None)?;
        assert_eq!(entry.kind, ChangeKind::Create);
        assert!(entry.unified_text.is_none());
        Ok(())
    }
}
