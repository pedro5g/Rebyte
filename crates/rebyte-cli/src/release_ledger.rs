//! Append-only cooperative witness ledger for Chain release sessions.

#![allow(clippy::redundant_pub_crate)]

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use rebyte_chain::{ChainError, IdentityId, ReleaseAuthorization, ReleaseLedger};

const MAGIC: &[u8; 4] = b"RBRL";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 4 + 2 + 32;
const RECORD_BODY_BYTES: usize = 32 + 32 + 32 + 4;
const RECORD_BYTES: usize = RECORD_BODY_BYTES + 32;
const MAX_RECORDS: usize = 65_536;
const RECORD_CONTEXT: &str = "Rebyte cooperative release ledger record v1 2026-07-18";

#[derive(Clone, Copy)]
struct LedgerRecord {
    contract_id: [u8; 32],
    proposal_id: [u8; 32],
    request_id: [u8; 32],
    ordinal: u32,
}

struct ParsedLedger {
    records: Vec<LedgerRecord>,
    previous_digest: [u8; 32],
    complete_length: usize,
}

pub(super) struct FileReleaseLedger {
    file: File,
    witness_id: [u8; 32],
    records: Vec<LedgerRecord>,
    previous_digest: [u8; 32],
}

impl FileReleaseLedger {
    pub(super) fn open(path: &Path, witness_id: IdentityId) -> Result<Self, ChainError> {
        let filename = path
            .file_name()
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = Dir::open_ambient_dir(parent, ambient_authority())
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        let mut file = directory
            .open_with(filename, &options)
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?
            .into_std();
        file.lock()
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        set_private_permissions(&file)?;
        let metadata = file
            .metadata()
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        if !metadata.is_file() {
            return Err(ChainError::ReleaseAuthorityUnavailable);
        }
        let length = metadata.len();
        if length == 0 {
            file.write_all(MAGIC)
                .and_then(|()| file.write_all(&VERSION.to_be_bytes()))
                .and_then(|()| file.write_all(witness_id.as_bytes()))
                .and_then(|()| file.sync_all())
                .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
            super::security_io::sync_parent(path)
                .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        let maximum_bytes = HEADER_BYTES
            .checked_add(
                RECORD_BYTES
                    .checked_mul(MAX_RECORDS)
                    .ok_or(ChainError::ReleaseAuthorityUnavailable)?,
            )
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(
                u64::try_from(maximum_bytes.saturating_add(1))
                    .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?,
            )
            .read_to_end(&mut bytes)
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        if bytes.len() > maximum_bytes {
            return Err(ChainError::ReleaseAuthorityUnavailable);
        }
        let parsed = parse_ledger(&bytes, witness_id.as_bytes())?;
        if parsed.complete_length != bytes.len() {
            file.set_len(
                u64::try_from(parsed.complete_length)
                    .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?,
            )
            .and_then(|()| file.sync_all())
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        }
        Ok(Self {
            file,
            witness_id: *witness_id.as_bytes(),
            records: parsed.records,
            previous_digest: parsed.previous_digest,
        })
    }
}

impl ReleaseLedger for FileReleaseLedger {
    fn authorize(&mut self, authorization: &ReleaseAuthorization) -> Result<u32, ChainError> {
        if let Some(record) = self.records.iter().find(|record| {
            record.contract_id == *authorization.contract_id()
                && record.proposal_id == *authorization.proposal_id()
                && record.request_id == *authorization.request_id()
        }) {
            return Ok(record.ordinal);
        }
        if self.records.len() >= MAX_RECORDS {
            return Err(ChainError::ReleaseAuthorityUnavailable);
        }
        let count = self
            .records
            .iter()
            .filter(|record| {
                record.contract_id == *authorization.contract_id()
                    && record.proposal_id == *authorization.proposal_id()
            })
            .count();
        let current = u32::try_from(count).map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        if authorization
            .maximum_successful_releases()
            .is_some_and(|maximum| current >= maximum)
        {
            return Err(ChainError::ReleaseLimitReached);
        }
        let ordinal = current
            .checked_add(1)
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        let mut body = Vec::with_capacity(RECORD_BODY_BYTES);
        body.extend_from_slice(authorization.contract_id());
        body.extend_from_slice(authorization.proposal_id());
        body.extend_from_slice(authorization.request_id());
        body.extend_from_slice(&ordinal.to_be_bytes());
        let digest = record_digest(&self.witness_id, &self.previous_digest, &body);
        self.file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&body))
            .and_then(|()| self.file.write_all(&digest))
            .and_then(|()| self.file.sync_all())
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        self.records.push(LedgerRecord {
            contract_id: *authorization.contract_id(),
            proposal_id: *authorization.proposal_id(),
            request_id: *authorization.request_id(),
            ordinal,
        });
        self.previous_digest = digest;
        Ok(ordinal)
    }
}

fn parse_ledger(bytes: &[u8], expected_witness: &[u8; 32]) -> Result<ParsedLedger, ChainError> {
    if bytes.len() < HEADER_BYTES
        || bytes.get(..4) != Some(MAGIC)
        || bytes.get(4..6) != Some(VERSION.to_be_bytes().as_slice())
        || bytes.get(6..HEADER_BYTES) != Some(expected_witness.as_slice())
    {
        return Err(ChainError::ReleaseAuthorityUnavailable);
    }
    let complete_records = bytes.len().saturating_sub(HEADER_BYTES) / RECORD_BYTES;
    if complete_records > MAX_RECORDS {
        return Err(ChainError::ReleaseAuthorityUnavailable);
    }
    let mut records: Vec<LedgerRecord> = Vec::with_capacity(complete_records);
    let mut previous_digest = [0_u8; 32];
    for index in 0..complete_records {
        let start = HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(RECORD_BYTES)
                    .ok_or(ChainError::ReleaseAuthorityUnavailable)?,
            )
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        let body_end = start
            .checked_add(RECORD_BODY_BYTES)
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        let end = body_end
            .checked_add(32)
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        let body = bytes
            .get(start..body_end)
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        let digest: [u8; 32] = bytes
            .get(body_end..end)
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?
            .try_into()
            .map_err(|_| ChainError::ReleaseAuthorityUnavailable)?;
        if record_digest(expected_witness, &previous_digest, body) != digest {
            return Err(ChainError::ReleaseAuthorityUnavailable);
        }
        let record = LedgerRecord {
            contract_id: array_at(body, 0)?,
            proposal_id: array_at(body, 32)?,
            request_id: array_at(body, 64)?,
            ordinal: u32::from_be_bytes(array_at(body, 96)?),
        };
        let expected_ordinal = records
            .iter()
            .filter(|candidate| {
                candidate.contract_id == record.contract_id
                    && candidate.proposal_id == record.proposal_id
            })
            .count()
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
        if record.ordinal != expected_ordinal
            || records.iter().any(|candidate| {
                candidate.contract_id == record.contract_id
                    && candidate.proposal_id == record.proposal_id
                    && candidate.request_id == record.request_id
            })
        {
            return Err(ChainError::ReleaseAuthorityUnavailable);
        }
        records.push(record);
        previous_digest = digest;
    }
    let complete_length = HEADER_BYTES
        .checked_add(
            complete_records
                .checked_mul(RECORD_BYTES)
                .ok_or(ChainError::ReleaseAuthorityUnavailable)?,
        )
        .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
    Ok(ParsedLedger {
        records,
        previous_digest,
        complete_length,
    })
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ChainError> {
    let end = offset
        .checked_add(N)
        .ok_or(ChainError::ReleaseAuthorityUnavailable)?;
    bytes
        .get(offset..end)
        .ok_or(ChainError::ReleaseAuthorityUnavailable)?
        .try_into()
        .map_err(|_| ChainError::ReleaseAuthorityUnavailable)
}

fn record_digest(witness_id: &[u8; 32], previous: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(RECORD_CONTEXT);
    hasher.update(witness_id);
    hasher.update(previous);
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

#[cfg(unix)]
fn set_private_permissions(file: &File) -> Result<(), ChainError> {
    use std::os::unix::fs::PermissionsExt as _;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| ChainError::ReleaseAuthorityUnavailable)
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &File) -> Result<(), ChainError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use rebyte_chain::{IdentityId, ReleaseAuthorization, ReleaseLedger};

    use super::FileReleaseLedger;

    #[test]
    fn ledger_reopens_idempotently_and_rejects_another_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("witness.ledger");
        let authorization = ReleaseAuthorization::from_parts([1; 32], [2; 32], [3; 32], Some(1));
        {
            let mut ledger = FileReleaseLedger::open(&path, IdentityId::from_bytes([4; 32]))?;
            assert_eq!(ledger.authorize(&authorization)?, 1);
        }
        let mut ledger = FileReleaseLedger::open(&path, IdentityId::from_bytes([4; 32]))?;
        assert_eq!(ledger.authorize(&authorization)?, 1);
        assert!(
            ledger
                .authorize(&ReleaseAuthorization::from_parts(
                    [1; 32],
                    [2; 32],
                    [5; 32],
                    Some(1)
                ))
                .is_err()
        );
        Ok(())
    }
}
