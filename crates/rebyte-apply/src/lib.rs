// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recoverable filesystem transactions for fully verified RAP capsules.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use cap_fs_ext::DirExt as _;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use rebyte_format::{Digest32, RelativeArtifactPath};
use rebyte_integrity::{digest_matches, file_digest};
use rebyte_verify::{FullyVerifiedCapsule, VerifiedFile};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const CONTROL_DIR: &str = ".rebyte";
const TRANSACTIONS_DIR: &str = "transactions";
const JOURNAL_FILE: &str = "journal.json";
const JOURNAL_TEMP_FILE: &str = "journal.tmp";
const MAX_JOURNAL_BYTES: u64 = 2 * 1_024 * 1_024;

/// Configures retention after a successful transaction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplyOptions {
    /// Keep the committed transaction and original-file backups for inspection.
    pub retain_backup: bool,
}

/// Durable state of a filesystem transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransactionState {
    /// Journal and operation plan exist.
    Prepared,
    /// New bytes and original backups are verified.
    Staged,
    /// Target renames are in progress.
    Committing,
    /// Every target was written and post-verified.
    Committed,
    /// Rollback is in progress.
    RollingBack,
    /// Original state was restored.
    RolledBack,
}

/// Summary of a retained or interrupted transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionSummary {
    /// UUID transaction identifier.
    pub id: String,
    /// Last persisted state.
    pub state: TransactionState,
    /// Number of planned file operations.
    pub operations: usize,
    /// Number of renames recorded as committed.
    pub committed: usize,
    /// Digest of the signed capsule associated with this transaction.
    pub capsule_digest: Digest32,
    /// Whether committed backups are intentionally retained.
    pub retained: bool,
}

/// Successful application report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReport {
    /// UUID transaction identifier.
    pub transaction_id: String,
    /// Number of target files atomically replaced.
    pub files_written: usize,
    /// Number of explicit artifact directories verified or created.
    pub directories_ensured: usize,
    /// Total verified bytes written.
    pub bytes_written: u64,
    /// Relative retained transaction path when backups were requested.
    pub retained_backup: Option<PathBuf>,
}

/// Applies verified files through staging, precondition checks and atomic
/// per-file renames.
///
/// # Errors
///
/// Returns [`ApplyError`] when another incomplete transaction exists, a path
/// component is unsafe, local state changed, journal I/O fails, a staged or
/// committed digest differs, or rollback cannot restore the original state.
pub fn apply_transaction(
    capsule: &FullyVerifiedCapsule,
    root: &Path,
    options: &ApplyOptions,
) -> Result<ApplyReport, ApplyError> {
    apply_verified_files(capsule.capsule_digest(), capsule.files(), root, options)
}

/// Applies an independently authenticated file set through the same
/// recoverable transaction engine as a verified RAP capsule.
///
/// `source_digest` must identify the complete authorized source object, not
/// only one file. Chain uses its contract-bound encrypted proposal digest.
/// The caller is responsible for retaining the authorization typestate and
/// checking the contract's `apply` capability before calling this function.
///
/// # Errors
///
/// Returns [`ApplyError`] under the same transaction, confinement, conflict
/// and verification conditions as [`apply_transaction`].
pub fn apply_verified_files(
    source_digest: Digest32,
    files: &[VerifiedFile],
    root: &Path,
    options: &ApplyOptions,
) -> Result<ApplyReport, ApplyError> {
    apply_verified_tree(source_digest, files, &[], root, options)
}

/// Applies authenticated files and explicit directories as one recoverable
/// tree transaction.
///
/// Existing directories are preserved. Missing directories are recorded in
/// the journal before creation and removed on rollback when still empty.
///
/// # Errors
///
/// Returns [`ApplyError`] for unsafe, duplicate or conflicting directory
/// paths and the failures documented by [`apply_verified_files`].
pub fn apply_verified_tree(
    source_digest: Digest32,
    files: &[VerifiedFile],
    directories: &[RelativeArtifactPath],
    root: &Path,
    options: &ApplyOptions,
) -> Result<ApplyReport, ApplyError> {
    let root = open_root(root)?;
    reject_incomplete_transactions(&root)?;
    let (transactions, transaction_id, transaction) = create_transaction(&root)?;
    let mut journal = prepare(
        source_digest,
        files,
        directories,
        &root,
        &transaction_id,
        options.retain_backup,
    )?;
    persist_journal(&transaction, &journal)?;

    if let Err(error) = stage(files, &root, &transaction, &mut journal) {
        // Windows refuses to remove a transaction tree while this directory
        // capability still owns an open handle to it.
        drop(transaction);
        let _cleanup_result = cleanup_transaction(&transactions, &transaction_id);
        return Err(error);
    }
    persist_journal(&transaction, &journal)?;

    if let Err(error) = commit(&root, &transaction, &mut journal) {
        if rollback(&root, &transaction, &mut journal).is_err() {
            return Err(ApplyError::RollbackFailed);
        }
        drop(transaction);
        let _cleanup_result = cleanup_transaction(&transactions, &transaction_id);
        return Err(error);
    }

    journal.state = TransactionState::Committed;
    persist_journal(&transaction, &journal)?;
    let bytes_written = journal
        .operations
        .iter()
        .try_fold(0_u64, |total, operation| {
            total
                .checked_add(operation.new_size)
                .ok_or(ApplyError::LengthOverflow)
        })?;
    let retained_backup = if options.retain_backup {
        Some(PathBuf::from(format!(
            "{CONTROL_DIR}/{TRANSACTIONS_DIR}/{transaction_id}"
        )))
    } else {
        drop(transaction);
        cleanup_transaction(&transactions, &transaction_id)?;
        None
    };
    Ok(ApplyReport {
        transaction_id,
        files_written: journal.operations.len(),
        directories_ensured: journal.required_directories.len(),
        bytes_written,
        retained_backup,
    })
}

/// Lists retained and interrupted transactions without modifying them.
///
/// # Errors
///
/// Returns [`ApplyError`] when the control directory or a bounded journal
/// cannot be read and validated.
pub fn list_transactions(root: &Path) -> Result<Vec<TransactionSummary>, ApplyError> {
    let root = open_root(root)?;
    let Some(transactions) = open_transactions(&root, false)? else {
        return Ok(Vec::new());
    };
    let mut summaries = Vec::new();
    let entries = transactions
        .entries()
        .map_err(|error| ApplyError::Io(error.kind()))?;
    for entry in entries {
        let entry = entry.map_err(|error| ApplyError::Io(error.kind()))?;
        let name = entry.file_name();
        let Some(id) = name.to_str() else {
            continue;
        };
        if Uuid::parse_str(id).is_err() {
            continue;
        }
        let transaction = transactions
            .open_dir_nofollow(id)
            .map_err(|error| ApplyError::Io(error.kind()))?;
        let journal = load_journal(&transaction)?;
        summaries.push(TransactionSummary {
            id: journal.id.clone(),
            state: journal.state,
            operations: journal.operations.len(),
            committed: journal.committed,
            capsule_digest: Digest32(journal.capsule_digest),
            retained: journal.retain_backup,
        });
    }
    summaries.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(summaries)
}

/// Resumes a staged or interrupted transaction from verified staged bytes.
///
/// # Errors
///
/// Returns [`ApplyError`] when the identifier or journal is invalid, staged
/// bytes no longer match their signed digests, target preconditions conflict,
/// or commit fails.
pub fn resume_transaction(root: &Path, transaction_id: &str) -> Result<ApplyReport, ApplyError> {
    validate_transaction_id(transaction_id)?;
    let root = open_root(root)?;
    let transactions = open_transactions(&root, false)?.ok_or(ApplyError::TransactionNotFound)?;
    let transaction = transactions
        .open_dir_nofollow(transaction_id)
        .map_err(|error| map_not_found(&error, ApplyError::TransactionNotFound))?;
    let mut journal = load_journal(&transaction)?;
    if matches!(
        journal.state,
        TransactionState::Committed | TransactionState::RolledBack
    ) {
        return Err(ApplyError::TransactionFinished);
    }
    reconcile(&root, &transaction, &mut journal)?;
    verify_staged(&transaction, &journal)?;
    commit(&root, &transaction, &mut journal)?;
    journal.state = TransactionState::Committed;
    persist_journal(&transaction, &journal)?;
    let bytes_written = journal
        .operations
        .iter()
        .try_fold(0_u64, |total, operation| {
            total
                .checked_add(operation.new_size)
                .ok_or(ApplyError::LengthOverflow)
        })?;
    Ok(ApplyReport {
        transaction_id: transaction_id.to_string(),
        files_written: journal.operations.len(),
        directories_ensured: journal.required_directories.len(),
        bytes_written,
        retained_backup: Some(PathBuf::from(format!(
            "{CONTROL_DIR}/{TRANSACTIONS_DIR}/{transaction_id}"
        ))),
    })
}

/// Restores original files for a retained or interrupted transaction.
///
/// # Errors
///
/// Returns [`ApplyError`] when the identifier, journal, target state or backup
/// bytes are invalid, or an atomic restore fails.
pub fn rollback_transaction(root: &Path, transaction_id: &str) -> Result<(), ApplyError> {
    validate_transaction_id(transaction_id)?;
    let root = open_root(root)?;
    let transactions = open_transactions(&root, false)?.ok_or(ApplyError::TransactionNotFound)?;
    let transaction = transactions
        .open_dir_nofollow(transaction_id)
        .map_err(|error| map_not_found(&error, ApplyError::TransactionNotFound))?;
    let mut journal = load_journal(&transaction)?;
    reconcile(&root, &transaction, &mut journal)?;
    rollback(&root, &transaction, &mut journal)?;
    drop(transaction);
    cleanup_transaction(&transactions, transaction_id)?;
    Ok(())
}

/// Filesystem transaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplyError {
    /// Root directory could not be opened.
    Root(io::ErrorKind),
    /// Confined filesystem operation failed.
    Io(io::ErrorKind),
    /// Another non-finished transaction must be recovered first.
    IncompleteTransaction,
    /// Requested transaction does not exist.
    TransactionNotFound,
    /// Requested transaction is already committed or rolled back.
    TransactionFinished,
    /// Transaction UUID was malformed.
    InvalidTransactionId,
    /// Journal was malformed, oversized or inconsistent.
    InvalidJournal,
    /// A target or path component was a symbolic link.
    Symlink,
    /// Existing target was not a regular file.
    NotRegularFile,
    /// Target changed after planning or has an ambiguous recovery state.
    Conflict,
    /// Staged, backup or post-write bytes failed digest verification.
    Integrity,
    /// Original state could not be restored after a failed commit.
    RollbackFailed,
    /// Platform length conversion or arithmetic overflowed.
    LengthOverflow,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(kind) => write!(formatter, "cannot open application root: {kind}"),
            Self::Io(kind) => write!(formatter, "filesystem transaction failed: {kind}"),
            Self::IncompleteTransaction => {
                formatter.write_str("an incomplete Rebyte transaction requires recovery")
            }
            Self::TransactionNotFound => formatter.write_str("transaction was not found"),
            Self::TransactionFinished => formatter.write_str("transaction is already finished"),
            Self::InvalidTransactionId => formatter.write_str("invalid transaction identifier"),
            Self::InvalidJournal => formatter.write_str("invalid transaction journal"),
            Self::Symlink => formatter.write_str("symbolic links are forbidden in target paths"),
            Self::NotRegularFile => formatter.write_str("target is not a regular file"),
            Self::Conflict => formatter.write_str("target changed during the transaction"),
            Self::Integrity => formatter.write_str("transaction file digest mismatch"),
            Self::RollbackFailed => formatter.write_str("transaction rollback failed"),
            Self::LengthOverflow => formatter.write_str("transaction length overflow"),
        }
    }
}

impl std::error::Error for ApplyError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    schema_version: u16,
    id: String,
    capsule_digest: [u8; 32],
    state: TransactionState,
    committed: usize,
    retain_backup: bool,
    created_directories: Vec<String>,
    #[serde(default)]
    required_directories: Vec<JournalDirectory>,
    operations: Vec<JournalOperation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct JournalDirectory {
    path: String,
    existed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct JournalOperation {
    target: String,
    staged: String,
    backup: Option<String>,
    original_digest: Option<[u8; 32]>,
    original_executable: bool,
    new_digest: [u8; 32],
    new_size: u64,
    executable: bool,
}

struct TargetSnapshot {
    bytes: Vec<u8>,
    executable: bool,
}

fn open_root(path: &Path) -> Result<Dir, ApplyError> {
    Dir::open_ambient_dir(path, ambient_authority()).map_err(|error| ApplyError::Root(error.kind()))
}

fn prepare(
    source_digest: Digest32,
    files: &[VerifiedFile],
    directories: &[RelativeArtifactPath],
    root: &Dir,
    transaction_id: &str,
    retain_backup: bool,
) -> Result<Journal, ApplyError> {
    let required_directories = prepare_directories(root, files, directories)?;
    let mut operations = Vec::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        let snapshot = read_target(root, &file.path)?;
        let backup = snapshot.as_ref().map(|_| format!("backups/{index:08}.bin"));
        operations.push(JournalOperation {
            target: file.path.as_str().to_string(),
            staged: format!("staged/{index:08}.bin"),
            backup,
            original_digest: snapshot.as_ref().map(|value| file_digest(&value.bytes).0),
            original_executable: snapshot.as_ref().is_some_and(|value| value.executable),
            new_digest: file_digest(&file.bytes).0,
            new_size: u64::try_from(file.bytes.len()).map_err(|_| ApplyError::LengthOverflow)?,
            executable: file.executable,
        });
    }
    Ok(Journal {
        schema_version: 1,
        id: transaction_id.to_string(),
        capsule_digest: source_digest.0,
        state: TransactionState::Prepared,
        committed: 0,
        retain_backup,
        created_directories: Vec::new(),
        required_directories,
        operations,
    })
}

fn prepare_directories(
    root: &Dir,
    files: &[VerifiedFile],
    directories: &[RelativeArtifactPath],
) -> Result<Vec<JournalDirectory>, ApplyError> {
    let mut previous: Option<&str> = None;
    let mut prepared = Vec::with_capacity(directories.len());
    for directory in directories {
        let path = directory.as_str();
        if previous.is_some_and(|value| value >= path)
            || files.iter().any(|file| file.path.as_str() == path)
        {
            return Err(ApplyError::InvalidJournal);
        }
        prepared.push(JournalDirectory {
            path: path.to_string(),
            existed: directory_exists(root, directory)?,
        });
        previous = Some(path);
    }
    Ok(prepared)
}

fn create_transaction(root: &Dir) -> Result<(Dir, String, Dir), ApplyError> {
    let transactions = open_transactions(root, true)?.ok_or(ApplyError::InvalidJournal)?;
    let id = Uuid::new_v4().to_string();
    transactions
        .create_dir(&id)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    let transaction = transactions
        .open_dir_nofollow(&id)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    transaction
        .create_dir("staged")
        .map_err(|error| ApplyError::Io(error.kind()))?;
    transaction
        .create_dir("backups")
        .map_err(|error| ApplyError::Io(error.kind()))?;
    sync_directory(&transaction)?;
    sync_directory(&transactions)?;
    Ok((transactions, id, transaction))
}

fn open_transactions(root: &Dir, create: bool) -> Result<Option<Dir>, ApplyError> {
    let control = open_or_create_directory(root, CONTROL_DIR, create)?;
    let Some(control) = control else {
        return Ok(None);
    };
    open_or_create_directory(&control, TRANSACTIONS_DIR, create)
}

fn open_or_create_directory(
    parent: &Dir,
    name: &str,
    create: bool,
) -> Result<Option<Dir>, ApplyError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(ApplyError::Symlink);
            }
            if !metadata.is_dir() {
                return Err(ApplyError::NotRegularFile);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            parent
                .create_dir(name)
                .map_err(|error| ApplyError::Io(error.kind()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ApplyError::Io(error.kind())),
    }
    parent
        .open_dir_nofollow(name)
        .map(Some)
        .map_err(|error| ApplyError::Io(error.kind()))
}

fn reject_incomplete_transactions(root: &Dir) -> Result<(), ApplyError> {
    let Some(transactions) = open_transactions(root, false)? else {
        return Ok(());
    };
    let entries = transactions
        .entries()
        .map_err(|error| ApplyError::Io(error.kind()))?;
    for entry in entries {
        let entry = entry.map_err(|error| ApplyError::Io(error.kind()))?;
        let name = entry.file_name();
        let Some(id) = name.to_str() else {
            continue;
        };
        let Ok(transaction) = transactions.open_dir_nofollow(id) else {
            continue;
        };
        let Ok(journal) = load_journal(&transaction) else {
            return Err(ApplyError::IncompleteTransaction);
        };
        if !matches!(
            journal.state,
            TransactionState::Committed | TransactionState::RolledBack
        ) {
            return Err(ApplyError::IncompleteTransaction);
        }
    }
    Ok(())
}

fn stage(
    files: &[VerifiedFile],
    root: &Dir,
    transaction: &Dir,
    journal: &mut Journal,
) -> Result<(), ApplyError> {
    if files.len() != journal.operations.len() {
        return Err(ApplyError::InvalidJournal);
    }
    for (file, operation) in files.iter().zip(&journal.operations) {
        write_new_file(transaction, &operation.staged, &file.bytes, file.executable)?;
        verify_file(
            transaction,
            &operation.staged,
            &Digest32(operation.new_digest),
        )?;
        if let Some(backup) = &operation.backup {
            let snapshot = read_target(root, &file.path)?.ok_or(ApplyError::Conflict)?;
            let original = operation
                .original_digest
                .map(Digest32)
                .ok_or(ApplyError::InvalidJournal)?;
            if !digest_matches(&original, &file_digest(&snapshot.bytes)) {
                return Err(ApplyError::Conflict);
            }
            write_new_file(transaction, backup, &snapshot.bytes, snapshot.executable)?;
            verify_file(transaction, backup, &original)?;
        }
    }
    journal.state = TransactionState::Staged;
    Ok(())
}

fn verify_staged(transaction: &Dir, journal: &Journal) -> Result<(), ApplyError> {
    for operation in &journal.operations {
        verify_file(
            transaction,
            &operation.staged,
            &Digest32(operation.new_digest),
        )?;
        if let (Some(backup), Some(original)) = (&operation.backup, operation.original_digest) {
            verify_file(transaction, backup, &Digest32(original))?;
        }
    }
    Ok(())
}

fn commit(root: &Dir, transaction: &Dir, journal: &mut Journal) -> Result<(), ApplyError> {
    verify_staged(transaction, journal)?;
    journal.state = TransactionState::Committing;
    persist_journal(transaction, journal)?;
    for directory in journal.required_directories.clone() {
        let path =
            RelativeArtifactPath::new(&directory.path).map_err(|_| ApplyError::InvalidJournal)?;
        ensure_directory(root, &path, &mut journal.created_directories)?;
        persist_journal(transaction, journal)?;
    }
    for index in journal.committed..journal.operations.len() {
        let operation = journal
            .operations
            .get(index)
            .ok_or(ApplyError::InvalidJournal)?
            .clone();
        let path =
            RelativeArtifactPath::new(&operation.target).map_err(|_| ApplyError::InvalidJournal)?;
        verify_precondition(root, &path, &operation)?;
        let staged = transaction
            .read(&operation.staged)
            .map_err(|error| ApplyError::Io(error.kind()))?;
        if !digest_matches(&Digest32(operation.new_digest), &file_digest(&staged)) {
            return Err(ApplyError::Integrity);
        }
        let temporary = format!(".rebyte-{}-{index:08}.tmp", journal.id);
        atomic_replace(
            root,
            &path,
            &staged,
            operation.executable,
            &temporary,
            &mut journal.created_directories,
        )?;
        let committed = read_target(root, &path)?.ok_or(ApplyError::Integrity)?;
        if committed.executable != operation.executable
            || !digest_matches(
                &Digest32(operation.new_digest),
                &file_digest(&committed.bytes),
            )
        {
            return Err(ApplyError::Integrity);
        }
        journal.committed = index.checked_add(1).ok_or(ApplyError::LengthOverflow)?;
        persist_journal(transaction, journal)?;
    }
    Ok(())
}

fn verify_precondition(
    root: &Dir,
    path: &RelativeArtifactPath,
    operation: &JournalOperation,
) -> Result<(), ApplyError> {
    let current = read_target(root, path)?;
    match (operation.original_digest, current) {
        (None, None) => Ok(()),
        (Some(expected), Some(snapshot))
            if snapshot.executable == operation.original_executable
                && digest_matches(&Digest32(expected), &file_digest(&snapshot.bytes)) =>
        {
            Ok(())
        }
        _ => Err(ApplyError::Conflict),
    }
}

fn rollback(root: &Dir, transaction: &Dir, journal: &mut Journal) -> Result<(), ApplyError> {
    journal.state = TransactionState::RollingBack;
    persist_journal(transaction, journal)?;
    let possible_count = journal
        .committed
        .checked_add(1)
        .ok_or(ApplyError::LengthOverflow)?
        .min(journal.operations.len());
    for (index, operation) in journal
        .operations
        .iter()
        .take(possible_count)
        .enumerate()
        .rev()
    {
        let path =
            RelativeArtifactPath::new(&operation.target).map_err(|_| ApplyError::InvalidJournal)?;
        let current = read_target(root, &path)?;
        let is_new = current.as_ref().is_some_and(|snapshot| {
            snapshot.executable == operation.executable
                && digest_matches(
                    &Digest32(operation.new_digest),
                    &file_digest(&snapshot.bytes),
                )
        });
        if !is_new {
            if index == journal.committed {
                // The boundary operation failed its precondition before Rebyte
                // renamed anything. Its current state belongs to the caller
                // or a concurrent writer and is deliberately left untouched.
                continue;
            }
            if operation.original_digest.is_none() && current.is_none() {
                continue;
            }
            if let (Some(expected), Some(snapshot)) = (operation.original_digest, current)
                && snapshot.executable == operation.original_executable
                && digest_matches(&Digest32(expected), &file_digest(&snapshot.bytes))
            {
                continue;
            }
            // A concurrent writer owns this unrecognized target state. Leave
            // its bytes untouched, but remove transaction-created directories
            // when they are still empty before reporting the conflict.
            remove_created_directories(root, &journal.created_directories);
            remove_required_directories(root, &journal.required_directories);
            return Err(ApplyError::Conflict);
        }
        if let (Some(backup), Some(original_digest)) =
            (&operation.backup, operation.original_digest)
        {
            let bytes = transaction
                .read(backup)
                .map_err(|error| ApplyError::Io(error.kind()))?;
            if !digest_matches(&Digest32(original_digest), &file_digest(&bytes)) {
                return Err(ApplyError::Integrity);
            }
            let temporary = format!(
                ".rebyte-{}-rollback-{:08}.tmp",
                journal.id, journal.committed
            );
            atomic_replace(
                root,
                &path,
                &bytes,
                operation.original_executable,
                &temporary,
                &mut journal.created_directories,
            )?;
        } else {
            remove_target(root, &path)?;
        }
    }
    remove_created_directories(root, &journal.created_directories);
    remove_required_directories(root, &journal.required_directories);
    journal.committed = 0;
    journal.state = TransactionState::RolledBack;
    persist_journal(transaction, journal)
}

fn reconcile(root: &Dir, transaction: &Dir, journal: &mut Journal) -> Result<(), ApplyError> {
    let mut committed = 0_usize;
    let mut saw_original = false;
    for operation in &journal.operations {
        let path =
            RelativeArtifactPath::new(&operation.target).map_err(|_| ApplyError::InvalidJournal)?;
        let current = read_target(root, &path)?;
        let is_new = current.as_ref().is_some_and(|snapshot| {
            snapshot.executable == operation.executable
                && digest_matches(
                    &Digest32(operation.new_digest),
                    &file_digest(&snapshot.bytes),
                )
        });
        let is_original = match (operation.original_digest, &current) {
            (None, None) => true,
            (Some(expected), Some(snapshot)) => {
                snapshot.executable == operation.original_executable
                    && digest_matches(&Digest32(expected), &file_digest(&snapshot.bytes))
            }
            _ => false,
        };
        if is_new && !saw_original {
            committed = committed.checked_add(1).ok_or(ApplyError::LengthOverflow)?;
        } else if is_original {
            saw_original = true;
        } else {
            return Err(ApplyError::Conflict);
        }
    }
    journal.committed = committed;
    persist_journal(transaction, journal)
}

fn read_target(
    root: &Dir,
    path: &RelativeArtifactPath,
) -> Result<Option<TargetSnapshot>, ApplyError> {
    let Some((parent, filename)) = open_parent(root, path, false, &mut Vec::new())? else {
        return Ok(None);
    };
    let metadata = match parent.symlink_metadata(&filename) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ApplyError::Io(error.kind())),
    };
    if metadata.file_type().is_symlink() {
        return Err(ApplyError::Symlink);
    }
    if !metadata.is_file() {
        return Err(ApplyError::NotRegularFile);
    }
    let bytes = parent
        .read(&filename)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    Ok(Some(TargetSnapshot {
        bytes,
        executable: is_executable(&metadata),
    }))
}

fn directory_exists(root: &Dir, path: &RelativeArtifactPath) -> Result<bool, ApplyError> {
    let mut current = root
        .try_clone()
        .map_err(|error| ApplyError::Io(error.kind()))?;
    for component in path.as_str().split('/') {
        match current.symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(ApplyError::Symlink),
            Ok(metadata) if !metadata.is_dir() => return Err(ApplyError::NotRegularFile),
            Ok(_) => {
                current = current
                    .open_dir_nofollow(component)
                    .map_err(|error| ApplyError::Io(error.kind()))?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(ApplyError::Io(error.kind())),
        }
    }
    Ok(true)
}

fn ensure_directory(
    root: &Dir,
    path: &RelativeArtifactPath,
    created_directories: &mut Vec<String>,
) -> Result<(), ApplyError> {
    let mut current = root
        .try_clone()
        .map_err(|error| ApplyError::Io(error.kind()))?;
    let mut accumulated = String::new();
    for component in path.as_str().split('/') {
        if !accumulated.is_empty() {
            accumulated.push('/');
        }
        accumulated.push_str(component);
        match current.symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(ApplyError::Symlink),
            Ok(metadata) if !metadata.is_dir() => return Err(ApplyError::NotRegularFile),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current
                    .create_dir(component)
                    .map_err(|error| ApplyError::Io(error.kind()))?;
                sync_directory(&current)?;
                if !created_directories.iter().any(|path| path == &accumulated) {
                    created_directories.push(accumulated.clone());
                }
            }
            Err(error) => return Err(ApplyError::Io(error.kind())),
        }
        current = current
            .open_dir_nofollow(component)
            .map_err(|error| ApplyError::Io(error.kind()))?;
    }
    Ok(())
}

fn atomic_replace(
    root: &Dir,
    path: &RelativeArtifactPath,
    bytes: &[u8],
    executable: bool,
    temporary: &str,
    created_directories: &mut Vec<String>,
) -> Result<(), ApplyError> {
    let (parent, filename) =
        open_parent(root, path, true, created_directories)?.ok_or(ApplyError::InvalidJournal)?;
    match parent.symlink_metadata(&filename) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(ApplyError::Symlink),
        Ok(metadata) if !metadata.is_file() => return Err(ApplyError::NotRegularFile),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ApplyError::Io(error.kind())),
    }
    if parent.symlink_metadata(temporary).is_ok() {
        return Err(ApplyError::Conflict);
    }
    write_new_file(&parent, temporary, bytes, executable)?;
    parent
        .rename(temporary, &parent, &filename)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    sync_directory(&parent)
}

fn remove_target(root: &Dir, path: &RelativeArtifactPath) -> Result<(), ApplyError> {
    let Some((parent, filename)) = open_parent(root, path, false, &mut Vec::new())? else {
        return Ok(());
    };
    match parent.symlink_metadata(&filename) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ApplyError::Symlink),
        Ok(metadata) if !metadata.is_file() => Err(ApplyError::NotRegularFile),
        Ok(_) => {
            parent
                .remove_file(&filename)
                .map_err(|error| ApplyError::Io(error.kind()))?;
            sync_directory(&parent)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ApplyError::Io(error.kind())),
    }
}

fn open_parent(
    root: &Dir,
    path: &RelativeArtifactPath,
    create: bool,
    created_directories: &mut Vec<String>,
) -> Result<Option<(Dir, String)>, ApplyError> {
    let mut components: Vec<&str> = path.as_str().split('/').collect();
    let filename = components
        .pop()
        .ok_or(ApplyError::InvalidJournal)?
        .to_string();
    let mut current = root
        .try_clone()
        .map_err(|error| ApplyError::Io(error.kind()))?;
    let mut accumulated = String::new();
    for component in components {
        if !accumulated.is_empty() {
            accumulated.push('/');
        }
        accumulated.push_str(component);
        match current.symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(ApplyError::Symlink),
            Ok(metadata) if !metadata.is_dir() => return Err(ApplyError::NotRegularFile),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                current
                    .create_dir(component)
                    .map_err(|error| ApplyError::Io(error.kind()))?;
                sync_directory(&current)?;
                created_directories.push(accumulated.clone());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ApplyError::Io(error.kind())),
        }
        current = current
            .open_dir_nofollow(component)
            .map_err(|error| ApplyError::Io(error.kind()))?;
    }
    Ok(Some((current, filename)))
}

fn write_new_file(
    directory: &Dir,
    path: &str,
    bytes: &[u8],
    executable: bool,
) -> Result<(), ApplyError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = directory
        .open_with(path, &options)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    file.write_all(bytes)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    set_executable(&file, executable)?;
    file.sync_all()
        .map_err(|error| ApplyError::Io(error.kind()))
}

fn verify_file(directory: &Dir, path: &str, expected: &Digest32) -> Result<(), ApplyError> {
    let bytes = directory
        .read(path)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    if digest_matches(expected, &file_digest(&bytes)) {
        Ok(())
    } else {
        Err(ApplyError::Integrity)
    }
}

fn persist_journal(transaction: &Dir, journal: &Journal) -> Result<(), ApplyError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| ApplyError::InvalidJournal)?;
    let length = u64::try_from(bytes.len()).map_err(|_| ApplyError::LengthOverflow)?;
    if length > MAX_JOURNAL_BYTES {
        return Err(ApplyError::InvalidJournal);
    }
    if transaction.symlink_metadata(JOURNAL_TEMP_FILE).is_ok() {
        transaction
            .remove_file(JOURNAL_TEMP_FILE)
            .map_err(|error| ApplyError::Io(error.kind()))?;
    }
    write_new_file(transaction, JOURNAL_TEMP_FILE, &bytes, false)?;
    transaction
        .rename(JOURNAL_TEMP_FILE, transaction, JOURNAL_FILE)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    sync_directory(transaction)
}

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> Result<(), ApplyError> {
    directory
        .open(".")
        .map_err(|error| ApplyError::Io(error.kind()))?
        .sync_all()
        .map_err(|error| ApplyError::Io(error.kind()))
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Dir) -> Result<(), ApplyError> {
    // Windows does not expose a portable Rust operation for fsyncing an open
    // directory. File contents and the journal are still synced before every
    // rename; attempting `open(".").sync_all()` fails with PermissionDenied.
    Ok(())
}

fn load_journal(transaction: &Dir) -> Result<Journal, ApplyError> {
    let metadata = transaction
        .symlink_metadata(JOURNAL_FILE)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(ApplyError::InvalidJournal);
    }
    let bytes = transaction
        .read(JOURNAL_FILE)
        .map_err(|error| ApplyError::Io(error.kind()))?;
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|_| ApplyError::InvalidJournal)?;
    validate_journal(&journal)?;
    Ok(journal)
}

fn validate_journal(journal: &Journal) -> Result<(), ApplyError> {
    if journal.schema_version != 1
        || Uuid::parse_str(&journal.id).is_err()
        || journal.committed > journal.operations.len()
    {
        return Err(ApplyError::InvalidJournal);
    }
    for (index, operation) in journal.operations.iter().enumerate() {
        RelativeArtifactPath::new(&operation.target).map_err(|_| ApplyError::InvalidJournal)?;
        let expected_staged = format!("staged/{index:08}.bin");
        let expected_backup = format!("backups/{index:08}.bin");
        if operation.staged != expected_staged
            || operation
                .backup
                .as_ref()
                .is_some_and(|path| path != &expected_backup)
            || operation.backup.is_some() != operation.original_digest.is_some()
        {
            return Err(ApplyError::InvalidJournal);
        }
    }
    for directory in &journal.created_directories {
        RelativeArtifactPath::new(directory).map_err(|_| ApplyError::InvalidJournal)?;
    }
    let mut previous: Option<&str> = None;
    for directory in &journal.required_directories {
        RelativeArtifactPath::new(&directory.path).map_err(|_| ApplyError::InvalidJournal)?;
        if previous.is_some_and(|value| value >= directory.path.as_str())
            || journal
                .operations
                .iter()
                .any(|operation| operation.target == directory.path)
        {
            return Err(ApplyError::InvalidJournal);
        }
        previous = Some(&directory.path);
    }
    Ok(())
}

fn cleanup_transaction(transactions: &Dir, id: &str) -> Result<(), ApplyError> {
    match transactions.remove_dir_all(id) {
        Ok(()) => {}
        // Cleanup is intentionally idempotent. On Windows, recursive removal
        // can report NotFound after the last directory entry disappeared.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ApplyError::Io(error.kind())),
    }
    sync_directory(transactions)
}

fn remove_created_directories(root: &Dir, directories: &[String]) {
    for directory in directories.iter().rev() {
        let _result = root.remove_dir(directory);
    }
}

fn remove_required_directories(root: &Dir, directories: &[JournalDirectory]) {
    for directory in directories.iter().rev().filter(|value| !value.existed) {
        let _result = root.remove_dir(&directory.path);
    }
}

fn validate_transaction_id(id: &str) -> Result<(), ApplyError> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| ApplyError::InvalidTransactionId)
}

fn map_not_found(error: &io::Error, not_found: ApplyError) -> ApplyError {
    if error.kind() == io::ErrorKind::NotFound {
        not_found
    } else {
        ApplyError::Io(error.kind())
    }
}

#[cfg(unix)]
fn set_executable(file: &cap_std::fs::File, executable: bool) -> Result<(), ApplyError> {
    use cap_std::fs::PermissionsExt as _;

    let mode = if executable { 0o755 } else { 0o644 };
    file.set_permissions(cap_std::fs::Permissions::from_mode(mode))
        .map_err(|error| ApplyError::Io(error.kind()))
}

#[cfg(not(unix))]
fn set_executable(_file: &cap_std::fs::File, _executable: bool) -> Result<(), ApplyError> {
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::PermissionsExt as _;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
const fn is_executable(_metadata: &cap_std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;
    use std::fs;

    use ed25519_dalek::SigningKey;
    use rebyte_format::{CompressionAlgorithm, RelativeArtifactPath};
    use rebyte_pack::{ArtifactFile, PackOptions, pack};
    use rebyte_signature::{
        KeyStatus, Signer, TrustChannel, TrustedKeyring, TrustedPublicKey, VerificationPolicy,
    };
    use rebyte_verify::{CapsuleInput, FullyVerifiedCapsule, sign_capsule, verify_capsule};
    use tempfile::tempdir;

    use super::{
        ApplyError, ApplyOptions, TransactionState, apply_transaction, apply_verified_tree,
        list_transactions, resume_transaction, rollback_transaction,
    };

    struct TestSigner(SigningKey);

    impl Signer for TestSigner {
        type Error = Infallible;

        fn public_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }

        fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            Ok(ed25519_dalek::Signer::sign(&self.0, message).to_bytes())
        }
    }

    fn verified_fixture() -> Result<FullyVerifiedCapsule, Box<dyn std::error::Error>> {
        let signing_key = TestSigner(SigningKey::from_bytes(&[0x33; 32]));
        let trusted = TrustedPublicKey::new(
            "recovery-test-only",
            signing_key.public_key(),
            TrustChannel::Development,
            KeyStatus::Active,
        )?;
        let keyring = TrustedKeyring::new(vec![trusted])?;
        let mut options = PackOptions::new("recovery-tests")?;
        options.compression = CompressionAlgorithm::None;
        let unsigned = pack(
            &[
                ArtifactFile::new("existing.txt", b"after\n".to_vec())?,
                ArtifactFile::new("nested/created.bin", vec![3, 2, 1])?,
            ],
            &options,
        )?;
        let capsule = sign_capsule(&unsigned, &signing_key)?;
        let policy = VerificationPolicy {
            allow_staging: false,
            allow_development: true,
        };
        verify_capsule(CapsuleInput::Binary(capsule.as_bytes()), &policy, &keyring)
            .map_err(Into::into)
    }

    fn rewind_journal(journal_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut journal: serde_json::Value = serde_json::from_slice(&fs::read(journal_path)?)?;
        journal["state"] = serde_json::json!("staged");
        journal["committed"] = serde_json::json!(0);
        fs::write(journal_path, serde_json::to_vec(&journal)?)?;
        Ok(())
    }

    #[test]
    fn retained_transactions_list_resume_and_roll_back() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        let capsule = verified_fixture()?;
        let options = ApplyOptions {
            retain_backup: true,
        };
        let report = apply_transaction(&capsule, directory.path(), &options)?;
        assert_eq!(fs::read(directory.path().join("existing.txt"))?, b"after\n");

        let summaries = list_transactions(directory.path())?;
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].state, TransactionState::Committed);
        assert!(summaries[0].retained);

        assert!(matches!(
            resume_transaction(directory.path(), &report.transaction_id),
            Err(ApplyError::TransactionFinished)
        ));

        let journal_path = directory
            .path()
            .join(".rebyte/transactions")
            .join(&report.transaction_id)
            .join("journal.json");
        rewind_journal(&journal_path)?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        fs::remove_file(directory.path().join("nested/created.bin"))?;
        let resumed = resume_transaction(directory.path(), &report.transaction_id)?;
        assert_eq!(resumed.files_written, 2);
        assert_eq!(fs::read(directory.path().join("existing.txt"))?, b"after\n");

        rollback_transaction(directory.path(), &report.transaction_id)?;
        assert_eq!(
            fs::read(directory.path().join("existing.txt"))?,
            b"before\n"
        );
        assert!(list_transactions(directory.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn resume_with_a_changed_target_conflicts() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        let capsule = verified_fixture()?;
        let options = ApplyOptions {
            retain_backup: true,
        };
        let report = apply_transaction(&capsule, directory.path(), &options)?;
        let journal_path = directory
            .path()
            .join(".rebyte/transactions")
            .join(&report.transaction_id)
            .join("journal.json");
        rewind_journal(&journal_path)?;
        fs::write(
            directory.path().join("existing.txt"),
            b"someone edited this\n",
        )?;
        assert!(matches!(
            resume_transaction(directory.path(), &report.transaction_id),
            Err(ApplyError::Conflict)
        ));
        Ok(())
    }

    #[test]
    fn an_incomplete_transaction_blocks_new_applications() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        let capsule = verified_fixture()?;
        let options = ApplyOptions {
            retain_backup: true,
        };
        let report = apply_transaction(&capsule, directory.path(), &options)?;
        let journal_path = directory
            .path()
            .join(".rebyte/transactions")
            .join(&report.transaction_id)
            .join("journal.json");
        rewind_journal(&journal_path)?;
        assert!(matches!(
            apply_transaction(&capsule, directory.path(), &ApplyOptions::default()),
            Err(ApplyError::IncompleteTransaction)
        ));
        Ok(())
    }

    #[test]
    fn a_corrupted_journal_is_rejected_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        let capsule = verified_fixture()?;
        let options = ApplyOptions {
            retain_backup: true,
        };
        let report = apply_transaction(&capsule, directory.path(), &options)?;
        let journal_path = directory
            .path()
            .join(".rebyte/transactions")
            .join(&report.transaction_id)
            .join("journal.json");
        fs::write(&journal_path, b"{ not json")?;
        assert!(matches!(
            list_transactions(directory.path()),
            Err(ApplyError::InvalidJournal)
        ));
        assert!(matches!(
            resume_transaction(directory.path(), &report.transaction_id),
            Err(ApplyError::InvalidJournal)
        ));
        Ok(())
    }

    #[test]
    fn invalid_and_missing_transaction_ids_are_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        assert!(list_transactions(directory.path())?.is_empty());
        assert!(matches!(
            resume_transaction(directory.path(), "not-a-uuid"),
            Err(ApplyError::InvalidTransactionId)
        ));
        assert!(matches!(
            rollback_transaction(directory.path(), "not-a-uuid"),
            Err(ApplyError::InvalidTransactionId)
        ));
        assert!(matches!(
            resume_transaction(directory.path(), "0193b6a0-0000-7000-8000-000000000000"),
            Err(ApplyError::TransactionNotFound)
        ));
        assert!(matches!(
            rollback_transaction(directory.path(), "0193b6a0-0000-7000-8000-000000000000"),
            Err(ApplyError::TransactionNotFound)
        ));
        Ok(())
    }

    #[test]
    fn every_transaction_error_renders_a_distinct_message() {
        let errors = [
            ApplyError::Root(std::io::ErrorKind::NotFound),
            ApplyError::Io(std::io::ErrorKind::PermissionDenied),
            ApplyError::IncompleteTransaction,
            ApplyError::TransactionNotFound,
            ApplyError::TransactionFinished,
            ApplyError::InvalidTransactionId,
            ApplyError::InvalidJournal,
            ApplyError::Symlink,
            ApplyError::NotRegularFile,
            ApplyError::Conflict,
            ApplyError::Integrity,
            ApplyError::RollbackFailed,
            ApplyError::LengthOverflow,
        ];
        let mut messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
        assert!(messages.iter().all(|message| !message.is_empty()));
        messages.sort();
        messages.dedup();
        assert_eq!(messages.len(), 13);
    }

    #[test]
    fn creates_and_replaces_files_exactly() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::create_dir_all(directory.path().join("src"))?;
        fs::write(directory.path().join("src/existing.txt"), b"old\n")?;
        let signer = TestSigner(SigningKey::from_bytes(&[0x31; 32]));
        let trusted = TrustedPublicKey::new(
            "test-only",
            signer.public_key(),
            TrustChannel::Development,
            KeyStatus::Active,
        )?;
        let keyring = TrustedKeyring::new(vec![trusted])?;
        let mut options = PackOptions::new("tests")?;
        options.compression = CompressionAlgorithm::None;
        let unsigned = pack(
            &[
                ArtifactFile::new("src/existing.txt", b"new\n".to_vec())?,
                ArtifactFile::new("nested/new.bin", vec![0, 1, 0xff])?,
            ],
            &options,
        )?;
        let capsule = sign_capsule(&unsigned, &signer)?;
        let policy = VerificationPolicy {
            allow_staging: false,
            allow_development: true,
        };
        let verified = verify_capsule(CapsuleInput::Binary(capsule.as_bytes()), &policy, &keyring)?;
        let report = apply_transaction(&verified, directory.path(), &ApplyOptions::default())?;
        assert_eq!(report.files_written, 2);
        assert_eq!(
            fs::read(directory.path().join("src/existing.txt"))?,
            b"new\n"
        );
        assert_eq!(
            fs::read(directory.path().join("nested/new.bin"))?,
            [0, 1, 0xff]
        );
        assert!(list_transactions(directory.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn creates_explicit_empty_directories_transactionally() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let verified = verified_fixture()?;
        let directories = [
            RelativeArtifactPath::new("empty")?,
            RelativeArtifactPath::new("nested/also-empty")?,
        ];
        let report = apply_verified_tree(
            verified.capsule_digest(),
            verified.files(),
            &directories,
            directory.path(),
            &ApplyOptions::default(),
        )?;
        assert_eq!(report.directories_ensured, 2);
        assert!(directory.path().join("empty").is_dir());
        assert!(directory.path().join("nested/also-empty").is_dir());
        assert!(list_transactions(directory.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn retained_transaction_rolls_back_to_exact_original_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        let signing_key = TestSigner(SigningKey::from_bytes(&[0x42; 32]));
        let trusted = TrustedPublicKey::new(
            "rollback-test-only",
            signing_key.public_key(),
            TrustChannel::Development,
            KeyStatus::Active,
        )?;
        let keyring = TrustedKeyring::new(vec![trusted])?;
        let mut pack_options = PackOptions::new("rollback-tests")?;
        pack_options.compression = CompressionAlgorithm::None;
        let unsigned = pack(
            &[
                ArtifactFile::new("existing.txt", b"after\n".to_vec())?,
                ArtifactFile::new("nested/created.bin", vec![1, 2, 3])?,
            ],
            &pack_options,
        )?;
        let capsule = sign_capsule(&unsigned, &signing_key)?;
        let policy = VerificationPolicy {
            allow_staging: false,
            allow_development: true,
        };
        let verified = verify_capsule(CapsuleInput::Binary(capsule.as_bytes()), &policy, &keyring)?;
        let report = apply_transaction(
            &verified,
            directory.path(),
            &ApplyOptions {
                retain_backup: true,
            },
        )?;

        assert_eq!(fs::read(directory.path().join("existing.txt"))?, b"after\n");
        assert_eq!(list_transactions(directory.path())?.len(), 1);
        rollback_transaction(directory.path(), &report.transaction_id)?;
        assert_eq!(
            fs::read(directory.path().join("existing.txt"))?,
            b"before\n"
        );
        assert!(!directory.path().join("nested/created.bin").exists());
        assert!(list_transactions(directory.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn resumes_from_the_staged_journal_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        let verified = verified_fixture()?;
        let root = super::open_root(directory.path())?;
        let (_transactions, transaction_id, transaction) = super::create_transaction(&root)?;
        let mut journal = super::prepare(
            verified.capsule_digest(),
            verified.files(),
            &[],
            &root,
            &transaction_id,
            true,
        )?;
        super::persist_journal(&transaction, &journal)?;
        super::stage(verified.files(), &root, &transaction, &mut journal)?;
        super::persist_journal(&transaction, &journal)?;
        drop(transaction);
        drop(root);

        super::resume_transaction(directory.path(), &transaction_id)?;
        assert_eq!(fs::read(directory.path().join("existing.txt"))?, b"after\n");
        assert_eq!(
            fs::read(directory.path().join("nested/created.bin"))?,
            [3, 2, 1]
        );
        Ok(())
    }

    #[test]
    fn detects_mutation_after_staging_before_any_rename() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        fs::write(directory.path().join("existing.txt"), b"before\n")?;
        let verified = verified_fixture()?;
        let root = super::open_root(directory.path())?;
        let (_transactions, transaction_id, transaction) = super::create_transaction(&root)?;
        let required_directories = [RelativeArtifactPath::new("empty-before-conflict")?];
        let mut journal = super::prepare(
            verified.capsule_digest(),
            verified.files(),
            &required_directories,
            &root,
            &transaction_id,
            true,
        )?;
        super::persist_journal(&transaction, &journal)?;
        super::stage(verified.files(), &root, &transaction, &mut journal)?;
        super::persist_journal(&transaction, &journal)?;
        fs::write(
            directory.path().join("existing.txt"),
            b"concurrent change\n",
        )?;

        assert!(matches!(
            super::commit(&root, &transaction, &mut journal),
            Err(ApplyError::Conflict)
        ));
        assert_eq!(
            fs::read(directory.path().join("existing.txt"))?,
            b"concurrent change\n"
        );
        assert!(!directory.path().join("nested/created.bin").exists());
        assert!(directory.path().join("empty-before-conflict").is_dir());
        super::rollback(&root, &transaction, &mut journal)?;
        assert!(!directory.path().join("empty-before-conflict").exists());
        Ok(())
    }

    #[test]
    fn transaction_cleanup_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = super::open_root(directory.path())?;
        let Some(transactions) = super::open_transactions(&root, true)? else {
            return Err("transaction directory was not created".into());
        };
        let transaction_id = uuid::Uuid::new_v4().to_string();

        super::cleanup_transaction(&transactions, &transaction_id)?;
        super::cleanup_transaction(&transactions, &transaction_id)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_target() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        fs::write(directory.path().join("outside"), b"outside")?;
        symlink(
            directory.path().join("outside"),
            directory.path().join("target"),
        )?;
        let root = super::open_root(directory.path())?;
        let path = rebyte_format::RelativeArtifactPath::new("target")?;
        assert!(matches!(
            super::read_target(&root, &path),
            Err(ApplyError::Symlink)
        ));
        Ok(())
    }
}
