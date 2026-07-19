// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical portable path validation.

use alloc::string::{String, ToString};
use core::fmt;

use crate::SecurityLimits;

/// A normalized protocol path that is safe to interpret below a chosen root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativeArtifactPath(String);

impl RelativeArtifactPath {
    /// Validates a portable path using the default RAP v1 path limit.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when the path is empty, non-portable, unsafe or
    /// longer than the RAP v1 limit.
    pub fn new(path: &str) -> Result<Self, PathError> {
        Self::with_max_bytes(path, SecurityLimits::V1.max_path_bytes)
    }

    /// Validates a portable path with a caller-supplied maximum byte length.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when the path is empty, non-portable, unsafe or
    /// longer than `max_bytes`.
    pub fn with_max_bytes(path: &str, max_bytes: usize) -> Result<Self, PathError> {
        validate(path, max_bytes)?;
        Ok(Self(path.to_string()))
    }

    /// Returns the canonical protocol representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the path and returns its canonical UTF-8 representation.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for RelativeArtifactPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RelativeArtifactPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for RelativeArtifactPath {
    type Error = PathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Reason a protocol path was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PathError {
    /// The path was empty.
    Empty,
    /// The UTF-8 representation exceeded the configured limit.
    TooLong {
        /// Configured maximum.
        max: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// The path began at a filesystem root.
    Absolute,
    /// A backslash was present.
    Backslash,
    /// A colon was present.
    Colon,
    /// A NUL or ASCII control byte was present.
    Control,
    /// The path contained an empty component.
    EmptyComponent,
    /// The path contained a current-directory component.
    CurrentDirectory,
    /// The path contained a parent-directory component.
    ParentDirectory,
    /// The path used a home-directory shorthand.
    HomePrefix,
    /// The path attempted to use Rebyte's transaction namespace.
    ReservedRoot,
    /// A component ended in a dot or space.
    TrailingDotOrSpace,
    /// A component was a reserved Windows device name.
    WindowsDeviceName,
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("path is empty"),
            Self::TooLong { max, actual } => {
                write!(formatter, "path has {actual} bytes; maximum is {max}")
            }
            Self::Absolute => formatter.write_str("absolute path is forbidden"),
            Self::Backslash => formatter.write_str("backslash is forbidden in protocol paths"),
            Self::Colon => formatter.write_str("colon is forbidden in protocol paths"),
            Self::Control => formatter.write_str("control byte is forbidden in protocol paths"),
            Self::EmptyComponent => formatter.write_str("empty path component is forbidden"),
            Self::CurrentDirectory => {
                formatter.write_str("current-directory component is forbidden")
            }
            Self::ParentDirectory => formatter.write_str("parent-directory component is forbidden"),
            Self::HomePrefix => formatter.write_str("home-directory shorthand is forbidden"),
            Self::ReservedRoot => formatter.write_str("the .rebyte root is reserved"),
            Self::TrailingDotOrSpace => {
                formatter.write_str("path component cannot end in dot or space")
            }
            Self::WindowsDeviceName => formatter.write_str("reserved Windows device name"),
        }
    }
}

impl core::error::Error for PathError {}

fn validate(path: &str, max_bytes: usize) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.len() > max_bytes {
        return Err(PathError::TooLong {
            max: max_bytes,
            actual: path.len(),
        });
    }
    if path.starts_with('/') {
        return Err(PathError::Absolute);
    }
    if path.as_bytes().contains(&b'\\') {
        return Err(PathError::Backslash);
    }
    if path.as_bytes().contains(&b':') {
        return Err(PathError::Colon);
    }
    if path.bytes().any(|byte| byte <= 0x1f || byte == 0x7f) {
        return Err(PathError::Control);
    }

    for (index, component) in path.split('/').enumerate() {
        validate_component(component, index)?;
    }
    Ok(())
}

fn validate_component(component: &str, index: usize) -> Result<(), PathError> {
    if component.is_empty() {
        return Err(PathError::EmptyComponent);
    }
    if component == "." {
        return Err(PathError::CurrentDirectory);
    }
    if component == ".." {
        return Err(PathError::ParentDirectory);
    }
    if index == 0 && component == "~" {
        return Err(PathError::HomePrefix);
    }
    if index == 0 && component.eq_ignore_ascii_case(".rebyte") {
        return Err(PathError::ReservedRoot);
    }
    if component.ends_with(['.', ' ']) {
        return Err(PathError::TrailingDotOrSpace);
    }
    if is_windows_device_name(component) {
        return Err(PathError::WindowsDeviceName);
    }
    Ok(())
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    if stem.eq_ignore_ascii_case("CON")
        || stem.eq_ignore_ascii_case("PRN")
        || stem.eq_ignore_ascii_case("AUX")
        || stem.eq_ignore_ascii_case("NUL")
        || stem.eq_ignore_ascii_case("CONIN$")
        || stem.eq_ignore_ascii_case("CONOUT$")
    {
        return true;
    }

    let bytes = stem.as_bytes();
    bytes.len() == 4
        && ((bytes[0].eq_ignore_ascii_case(&b'C')
            && bytes[1].eq_ignore_ascii_case(&b'O')
            && bytes[2].eq_ignore_ascii_case(&b'M'))
            || (bytes[0].eq_ignore_ascii_case(&b'L')
                && bytes[1].eq_ignore_ascii_case(&b'P')
                && bytes[2].eq_ignore_ascii_case(&b'T')))
        && matches!(bytes[3], b'1'..=b'9')
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString as _;
    use alloc::vec::Vec;

    use super::{PathError, RelativeArtifactPath};

    #[test]
    fn conversions_expose_the_same_canonical_text() -> Result<(), PathError> {
        let path = RelativeArtifactPath::new("docs/guide.md")?;
        assert_eq!(path.as_str(), "docs/guide.md");
        assert_eq!(AsRef::<str>::as_ref(&path), "docs/guide.md");
        assert_eq!(path.to_string(), "docs/guide.md");
        assert_eq!(RelativeArtifactPath::try_from("docs/guide.md")?, path);
        assert_eq!(path.into_string(), "docs/guide.md");
        Ok(())
    }

    #[test]
    fn every_rejection_reason_renders_a_distinct_message() -> Result<(), &'static str> {
        let rejected = [
            RelativeArtifactPath::new(""),
            RelativeArtifactPath::new(&"a".repeat(5_000)),
            RelativeArtifactPath::new("/abs"),
            RelativeArtifactPath::new("a\\b"),
            RelativeArtifactPath::new("a:b"),
            RelativeArtifactPath::new("a\u{1}b"),
            RelativeArtifactPath::new("a//b"),
            RelativeArtifactPath::new("a/./b"),
            RelativeArtifactPath::new("a/../b"),
            RelativeArtifactPath::new("~/b"),
            RelativeArtifactPath::new(".rebyte/state"),
            RelativeArtifactPath::new("a./b"),
            RelativeArtifactPath::new("COM1"),
        ];
        let mut messages = Vec::new();
        for result in rejected {
            let Err(error) = result else {
                return Err("path must be rejected");
            };
            let message = error.to_string();
            assert!(!message.is_empty());
            messages.push(message);
        }
        messages.sort();
        messages.dedup();
        assert_eq!(messages.len(), 13, "every reason needs its own message");
        Ok(())
    }

    #[test]
    fn windows_device_names_are_rejected_in_any_case() {
        for name in ["conin$", "CONOUT$", "lpt9", "com1.txt", "AUX", "nul"] {
            assert_eq!(
                RelativeArtifactPath::new(name),
                Err(PathError::WindowsDeviceName),
                "{name}"
            );
        }
        assert!(RelativeArtifactPath::new("com0").is_ok());
        assert!(RelativeArtifactPath::new("competitive").is_ok());
        assert!(RelativeArtifactPath::new("lptx").is_ok());
    }

    #[test]
    fn accepts_portable_unicode_path() {
        let result = RelativeArtifactPath::new("dados/ação.txt");
        assert!(result.is_ok());
        assert_eq!(
            result.as_ref().map(RelativeArtifactPath::as_str),
            Ok("dados/ação.txt")
        );
    }

    #[test]
    fn rejects_traversal_and_platform_prefixes() {
        assert_eq!(
            RelativeArtifactPath::new("../a"),
            Err(PathError::ParentDirectory)
        );
        assert_eq!(
            RelativeArtifactPath::new("/etc/passwd"),
            Err(PathError::Absolute)
        );
        assert_eq!(
            RelativeArtifactPath::new("C:\\file"),
            Err(PathError::Backslash)
        );
        assert_eq!(RelativeArtifactPath::new("C:/file"), Err(PathError::Colon));
        assert_eq!(
            RelativeArtifactPath::new("~/file"),
            Err(PathError::HomePrefix)
        );
    }

    #[test]
    fn rejects_non_portable_components() {
        assert_eq!(
            RelativeArtifactPath::new("a//b"),
            Err(PathError::EmptyComponent)
        );
        assert_eq!(
            RelativeArtifactPath::new("a/."),
            Err(PathError::CurrentDirectory)
        );
        assert_eq!(
            RelativeArtifactPath::new("con.txt"),
            Err(PathError::WindowsDeviceName)
        );
        assert_eq!(
            RelativeArtifactPath::new("LPT9"),
            Err(PathError::WindowsDeviceName)
        );
        assert_eq!(
            RelativeArtifactPath::new("name."),
            Err(PathError::TrailingDotOrSpace)
        );
        assert_eq!(
            RelativeArtifactPath::new(".REBYTE/journal"),
            Err(PathError::ReservedRoot)
        );
    }

    #[test]
    fn applies_byte_limit() {
        assert_eq!(
            RelativeArtifactPath::with_max_bytes("abcd", 3),
            Err(PathError::TooLong { max: 3, actual: 4 })
        );
    }
}
