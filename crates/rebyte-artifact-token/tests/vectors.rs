// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frozen artifact-token vectors guarding decoder compatibility.
//!
//! The stored token was produced by Rebyte 1.2 for a deterministic input. It
//! must keep decoding to the exact original artifact in every future release;
//! a failure here means previously distributed tokens would stop opening.

use rebyte_artifact_token::{Artifact, ArtifactOptions, decode_artifact_token, encode_artifact};
use rebyte_format::SecurityLimits;

const VECTOR_CONTENT: &[u8] = b"Rebyte canonical vector 2026-07-18\n";
const VECTOR_NAME: &str = "vector.txt";
const FROZEN_TOKEN: &str = "ra1_UkJBVAEAAAEAAQAAAAAAAQAAAAAAAABKAAAAAAAAACMAAAAAAAAAI9B6YbZ4NSQdXoj3S1TfuksbE5pJw2CirCEiMEPEUb8fGzTg8Aprkp6q62SOKsA1obh4Mp1M-aVFy9JnckiHHX8ACnZlY3Rvci50eHQAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACNegXudLNK_d72p738Afw4tjOZFhdtzkFpUARf46VB9X1JlYnl0ZSBjYW5vbmljYWwgdmVjdG9yIDIwMjYtMDctMTgK";

fn vector_artifact() -> Result<Artifact, Box<dyn std::error::Error>> {
    Ok(Artifact::file(VECTOR_CONTENT.to_vec(), false).with_suggested_name(VECTOR_NAME)?)
}

#[test]
fn frozen_token_decodes_to_the_exact_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let decoded = decode_artifact_token(FROZEN_TOKEN, &SecurityLimits::SIMPLE_ARTIFACT)?;
    assert_eq!(
        decoded.into_artifact(),
        vector_artifact()?,
        "frozen ra1_ token no longer reconstructs its original artifact"
    );
    Ok(())
}

#[test]
fn encoding_the_vector_input_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = vector_artifact()?;
    let first = encode_artifact(&artifact, &ArtifactOptions::default())?;
    let second = encode_artifact(&artifact, &ArtifactOptions::default())?;
    assert_eq!(first.binary(), second.binary());
    assert_eq!(
        first.to_token(&SecurityLimits::SIMPLE_ARTIFACT)?,
        second.to_token(&SecurityLimits::SIMPLE_ARTIFACT)?
    );
    Ok(())
}
