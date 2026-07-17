//! Bounded, platform-independent types for the Rebyte Artifact Protocol.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod limits;
mod path;
mod types;

pub use limits::SecurityLimits;
pub use path::{PathError, RelativeArtifactPath};
pub use types::{
    BoundedString, CapsuleHeaderV1, CapsuleManifestV1, CompressionAlgorithm, ContentKind, Digest32,
    FileEntryV1, FileOperation, FormatError, KeyId, ProducerMetadata, ProtocolVersion,
    SignatureAlgorithm,
};

/// Magic bytes at the start of every binary RAP capsule.
pub const MAGIC: [u8; 4] = *b"RBAP";

/// RAP protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// Fixed byte length of a RAP v1 header.
pub const HEADER_SIZE_V1: u16 = 80;

/// Maximum byte length of a capsule name.
pub const MAX_CAPSULE_NAME_BYTES: usize = 256;

/// Maximum byte length of a capsule description.
pub const MAX_DESCRIPTION_BYTES: usize = 4_096;

/// Maximum byte length of a producer name.
pub const MAX_PRODUCER_NAME_BYTES: usize = 256;

/// Maximum byte length of a producer version.
pub const MAX_PRODUCER_VERSION_BYTES: usize = 128;
