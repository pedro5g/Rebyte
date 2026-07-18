// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical unsigned artifact tokens for one file or a portable directory.
//!
//! An `ra1_` token and an `.rba` binary contain the same envelope bytes. They
//! provide bounded, byte-exact reconstruction and mutation detection, but do
//! not authenticate who created the artifact.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod model;

pub use codec::{
    ARTIFACT_HEADER_SIZE, ARTIFACT_TOKEN_PREFIX, ArtifactIoError, ArtifactPathMetadata,
    StreamArtifactReport, decode_artifact, decode_artifact_file, decode_artifact_file_expected,
    decode_artifact_token, encode_artifact, encode_artifact_binary_token, encode_artifact_path,
    encode_artifact_token,
};
pub use error::ArtifactTokenError;
pub use model::{
    Artifact, ArtifactCompression, ArtifactDictionary, ArtifactEntry, ArtifactEntryKind,
    ArtifactKind, ArtifactOptions, DecodedArtifact, EncodedArtifact,
};
pub use rebyte_compression::CompressionProfile;
