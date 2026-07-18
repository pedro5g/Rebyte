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

#[test]
fn frozen_documents_still_parse_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let parsed = crate::IdentityPublicDocument::from_json(ALICE_PUBLIC_JSON.as_bytes())?;
    assert_eq!(parsed.identity_id()?.to_base64(), ALICE_IDENTITY_ID);
    let acceptance = crate::GroupAcceptance::from_json(ALICE_ACCEPTANCE_JSON.as_bytes())?;
    assert_eq!(acceptance.member_id()?.to_base64(), ALICE_IDENTITY_ID);
    Ok(())
}
