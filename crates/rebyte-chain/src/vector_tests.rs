// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frozen canonical-encoding vectors for Chain control documents.
//!
//! These constants freeze the exact canonical bytes produced for
//! deterministic inputs. A failing vector means the canonical encoding
//! changed and previously stored documents would stop validating. Never
//! update an expected value without an explicit document-version bump and a
//! re-encode plan for existing files.

use crate::group::deterministic_group;
use crate::identity::deterministic_identity;
use crate::{accept_group, finalize_group};

const TEST_PASSPHRASE: &[u8] = b"test-only-passphrase";

const ALICE_PUBLIC_JSON: &str = r#"{
  "schemaVersion": 1,
  "kind": "rebyte-chain-identity-public",
  "displayName": "Vector Alice",
  "signingPublicKey": "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc",
  "encryptionPublicKey": "7zGBAt7OA7DyWlP1E2Uq00nPAafUE0u0TxC4d0umWjQ",
  "packageNonce": "ExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExM",
  "identityId": "ylI99DK0GuVyCXeLOGHROXKdd_rs7b9LeupRinH1Mrg",
  "proofSignature": "7WpTLj5WD-h7fGgTIGxp_vsIuYVboW3lTnlKTCn_BF06WPJPPtRrC15ykhX_18xerSdrtd2OzfNP1XONGJDIBQ"
}
"#;

const ALICE_IDENTITY_ID: &str = "ylI99DK0GuVyCXeLOGHROXKdd_rs7b9LeupRinH1Mrg";
const BOB_IDENTITY_ID: &str = "qdhpkoe0CRsfENwlWlOZ2LKBsKnmD-oWADvisFDJmYw";
const GROUP_ID: &str = "JslAT_T7PWkU0q8wlxhJlw2Szn2HzS2p2bE1X6K7CsI";
const PROPOSAL_JSON_BLAKE3: &str =
    "0cd32884d41ea292e0a225697decd1a1fe93a25bfdb5e8c7303262828516acac";
const CERTIFICATE_JSON_BLAKE3: &str =
    "d9ef0f4bba53ad2d75552726885b1a50c82e36d8a5f1a959b3182fefdfa10a3f";

const ALICE_ACCEPTANCE_JSON: &str = r#"{
  "schemaVersion": 1,
  "kind": "rebyte-chain-group-acceptance",
  "groupId": "JslAT_T7PWkU0q8wlxhJlw2Szn2HzS2p2bE1X6K7CsI",
  "memberId": "ylI99DK0GuVyCXeLOGHROXKdd_rs7b9LeupRinH1Mrg",
  "signature": "SVo0Rczn5j4Xdh3Jm4uaK0DX_Semfrzter8IZc4iE_w7_ZKP_zmjmdJiU0HvWh-s3iN-tek_BgPmu_6qtpoyBw"
}
"#;

#[test]
fn public_identity_document_bytes_are_frozen() -> Result<(), Box<dyn std::error::Error>> {
    let (_, alice_public) = deterministic_identity(0x11, "Vector Alice")?;
    assert_eq!(
        String::from_utf8(alice_public.to_json()?)?,
        ALICE_PUBLIC_JSON,
        "canonical identity JSON changed; stored documents would stop validating"
    );
    assert_eq!(alice_public.identity_id()?.to_base64(), ALICE_IDENTITY_ID);
    Ok(())
}

#[test]
fn group_formation_documents_are_frozen() -> Result<(), Box<dyn std::error::Error>> {
    let (alice_private, alice_public) = deterministic_identity(0x11, "Vector Alice")?;
    let (bob_private, bob_public) = deterministic_identity(0x22, "Vector Bob")?;
    assert_eq!(bob_public.identity_id()?.to_base64(), BOB_IDENTITY_ID);
    let proposal = deterministic_group("Vector group", 2, vec![alice_public, bob_public])?;
    assert_eq!(
        blake3::hash(&proposal.to_json()?).to_hex().to_string(),
        PROPOSAL_JSON_BLAKE3,
        "canonical group-proposal bytes changed"
    );
    assert_eq!(proposal.group_id()?.to_base64(), GROUP_ID);
    let alice = alice_private.unlock(TEST_PASSPHRASE)?;
    let bob = bob_private.unlock(TEST_PASSPHRASE)?;
    let alice_acceptance = accept_group(&proposal, &alice)?;
    let bob_acceptance = accept_group(&proposal, &bob)?;
    assert_eq!(
        String::from_utf8(alice_acceptance.to_json()?)?,
        ALICE_ACCEPTANCE_JSON,
        "canonical group-acceptance JSON changed"
    );
    let certificate = finalize_group(proposal, vec![alice_acceptance, bob_acceptance])?;
    assert_eq!(
        blake3::hash(&certificate.to_json()?).to_hex().to_string(),
        CERTIFICATE_JSON_BLAKE3,
        "canonical group-certificate bytes changed"
    );
    Ok(())
}

const CHALLENGE_SOLUTION: &[u8] = b"vector challenge solution";
const CHALLENGE_SALT: [u8; 16] = [0x5A; 16];
const CHALLENGE_SOLUTION_KEY: &str =
    "fea63fbda6df4722b0cc41342524077286fde096f3949982aa295a84532c573a";
const CHALLENGE_COMMITMENT: &str =
    "a936298ff8f55ec7affa508680a50aaa241f561d679501acfc5a1a49cb82db88";
const CHALLENGE_PRIZE: &[u8] = b"vector prize\n";

/// One finalized challenge envelope, generated once from the deterministic
/// Alice identity and frozen. The same bytes seed the
/// `decode_chain_envelope` fuzz corpus (`fuzz/corpus/.../challenge-slot`).
const CHALLENGE_ENVELOPE_TOKEN: &str = include_str!("vectors/challenge-envelope-v1.token");

#[test]
fn challenge_kdf_and_commitment_are_frozen() -> Result<(), Box<dyn std::error::Error>> {
    let policy = rebyte_contract::ChallengeRelease::new(
        8 * 1_024,
        1,
        [0; 32],
        CHALLENGE_SALT,
        "vector hint".to_string(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let key = crate::challenge::derive_solution_key(CHALLENGE_SOLUTION, &policy)?;
    assert_eq!(
        hex(key.as_ref()),
        CHALLENGE_SOLUTION_KEY,
        "Argon2id solution derivation changed; every stored challenge would stop opening"
    );
    assert_eq!(
        hex(&crate::challenge::solution_commitment(&key)),
        CHALLENGE_COMMITMENT,
        "commitment derivation changed; every stored challenge would stop opening"
    );
    Ok(())
}

#[test]
fn frozen_challenge_envelope_still_solves() -> Result<(), Box<dyn std::error::Error>> {
    use crate::{CapsuleEnvelope, ChainError, ChainLimits, OpenedContent, open_challenge_content};

    let limits = ChainLimits::STANDARD;
    let token = CHALLENGE_ENVELOPE_TOKEN.trim_end();
    let envelope = CapsuleEnvelope::from_token(token, &limits)?;
    assert_eq!(
        envelope.to_token(&limits)?,
        token,
        "challenge envelope encoding changed; stored envelopes would stop round-tripping"
    );
    let OpenedContent::ExactArtifact(opened) =
        open_challenge_content(&envelope, CHALLENGE_SOLUTION, &limits)?
    else {
        return Err("unexpected content kind".into());
    };
    let expected = rebyte_artifact_token::encode_artifact(
        &rebyte_artifact_token::Artifact::file(CHALLENGE_PRIZE.to_vec(), false),
        &rebyte_artifact_token::ArtifactOptions::default(),
    )?
    .into_binary();
    assert_eq!(opened.artifact_binary(), expected);
    assert!(matches!(
        open_challenge_content(&envelope, b"wrong solution", &limits),
        Err(ChainError::AuthenticationFailed)
    ));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _infallible = write!(out, "{byte:02x}");
        out
    })
}

#[test]
fn frozen_documents_still_parse_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let parsed = crate::IdentityPublicDocument::from_json(ALICE_PUBLIC_JSON.as_bytes())?;
    assert_eq!(parsed.identity_id()?.to_base64(), ALICE_IDENTITY_ID);
    let acceptance = crate::GroupAcceptance::from_json(ALICE_ACCEPTANCE_JSON.as_bytes())?;
    assert_eq!(acceptance.member_id()?.to_base64(), ALICE_IDENTITY_ID);
    Ok(())
}
