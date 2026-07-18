//! Bounded no-follow reads and exclusive output creation.

#![allow(clippy::redundant_pub_crate)]

use std::fs::{self, OpenOptions as StdOpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

pub(super) fn read_bounded_nofollow(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = open_nofollow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input is not a bounded regular file",
        ));
    }
    read_bounded(file, metadata.len(), maximum)
}

pub(super) fn read_private_bounded_nofollow(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = open_nofollow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret input is not a bounded regular file",
        ));
    }
    validate_private_mode(&metadata)?;
    read_bounded(file, metadata.len(), maximum)
}

fn open_nofollow(path: &Path) -> io::Result<cap_std::fs::File> {
    let (parent, filename) = split_file_path(path)?;
    let directory = Dir::open_ambient_dir(parent, ambient_authority())?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory.open_with(filename, &options)
}

fn read_bounded(
    file: cap_std::fs::File,
    declared_length: u64,
    maximum: u64,
) -> io::Result<Vec<u8>> {
    let capacity = usize::try_from(declared_length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input length overflow"))?;
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input exceeds its size limit",
        ));
    }
    Ok(bytes)
}

pub(super) fn write_new(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let mut options = StdOpenOptions::new();
    options.write(true).create_new(true);
    configure_creation_mode(&mut options, private);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

fn split_file_path(path: &Path) -> io::Result<(&Path, &std::ffi::OsStr)> {
    let filename = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok((parent, filename))
}

#[cfg(unix)]
fn configure_creation_mode(options: &mut StdOpenOptions, private: bool) {
    use std::os::unix::fs::OpenOptionsExt as _;

    options.mode(if private { 0o600 } else { 0o644 });
}

#[cfg(not(unix))]
fn configure_creation_mode(_options: &mut StdOpenOptions, _private: bool) {}

#[cfg(unix)]
fn validate_private_mode(metadata: &cap_std::fs::Metadata) -> io::Result<()> {
    use cap_std::fs::PermissionsExt as _;

    if metadata.permissions().mode().trailing_zeros() >= 6 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret file permissions must be 0600 or stricter",
        ))
    }
}

#[cfg(not(unix))]
fn validate_private_mode(_metadata: &cap_std::fs::Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
pub(super) fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_private_bounded_nofollow, write_new};

    #[cfg(unix)]
    #[test]
    fn private_reader_rejects_symlinks_and_shared_permissions()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let temporary = tempfile::tempdir()?;
        let private = temporary.path().join("private");
        write_new(&private, b"secret", true)?;
        assert_eq!(read_private_bounded_nofollow(&private, 64)?, b"secret");

        let link = temporary.path().join("link");
        symlink(&private, &link)?;
        assert!(read_private_bounded_nofollow(&link, 64).is_err());

        fs::set_permissions(&private, fs::Permissions::from_mode(0o640))?;
        assert!(read_private_bounded_nofollow(&private, 64).is_err());
        Ok(())
    }
}
