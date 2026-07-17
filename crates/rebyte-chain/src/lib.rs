// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Self-custodied identities, group consensus and encrypted Rebyte artifacts.
//!
//! Chain objects are local, portable and offline. Group certificates require
//! every declared member to prove possession of its signing key. Capsule
//! certificates then require a configurable threshold of those members to sign
//! the same encrypted proposal. Confidentiality is independently granted to
//! explicitly listed recipient encryption keys.

#![forbid(unsafe_code)]

mod codec;
mod envelope;
mod error;
mod group;
mod identity;

pub use envelope::{
    CAPSULE_TOKEN_PREFIX, CapsuleApproval, CapsuleEnvelope, CapsuleProposal, ChainLimits,
    OpenedCapsule, approve_capsule, create_capsule_proposal, finalize_capsule, open_capsule,
};
pub use error::ChainError;
pub use group::{
    GroupAcceptance, GroupCertificate, GroupId, GroupProposal, accept_group, finalize_group,
};
pub use identity::{
    EncryptedIdentityDocument, IdentityId, IdentityPublicDocument, UnlockedIdentity,
    generate_identity,
};

#[cfg(test)]
mod tests {
    use rebyte_artifact_token::{Artifact, ArtifactOptions, encode_artifact};
    use rebyte_format::SecurityLimits;

    use super::{
        CapsuleEnvelope, ChainError, ChainLimits, accept_group, approve_capsule,
        create_capsule_proposal, finalize_capsule, finalize_group, open_capsule,
    };
    use crate::group::{deterministic_group, replace_acceptance_signature};
    use crate::identity::deterministic_identity;

    const TEST_PASSPHRASE: &[u8] = b"test-only-passphrase";

    fn artifact_bytes() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let artifact = Artifact::file(
            b"Rebyte Chain reconstructs these exact bytes.\n".to_vec(),
            false,
        )
        .with_suggested_name("chain-demo.txt")?;
        Ok(encode_artifact(&artifact, &ArtifactOptions::default())?.into_binary())
    }

    #[test]
    fn identity_documents_bind_both_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        let (private, public) = deterministic_identity(0x11, "Alice")?;
        let private_json = private.to_json()?;
        let public_json = public.to_json()?;
        let parsed_private = super::EncryptedIdentityDocument::from_json(&private_json)?;
        let parsed_public = super::IdentityPublicDocument::from_json(&public_json)?;
        let unlocked = parsed_private.unlock(TEST_PASSPHRASE)?;
        assert_eq!(unlocked.identity_id(), parsed_public.identity_id()?);

        let (_, other) = deterministic_identity(0x22, "Mallory")?;
        let mut changed: serde_json::Value = serde_json::from_slice(&public_json)?;
        changed["encryptionPublicKey"] =
            serde_json::Value::String(crate::codec::encode_base64(&other.encryption_public_key()?));
        let mut changed_bytes = serde_json::to_vec_pretty(&changed)?;
        changed_bytes.push(b'\n');
        assert!(matches!(
            super::IdentityPublicDocument::from_json(&changed_bytes),
            Err(ChainError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn wrong_private_key_cannot_accept_another_member_slot()
    -> Result<(), Box<dyn std::error::Error>> {
        let (alice_private, alice_public) = deterministic_identity(0x31, "Alice")?;
        let (bob_private, bob_public) = deterministic_identity(0x41, "Bob")?;
        let alice = alice_private.unlock(TEST_PASSPHRASE)?;
        let bob = bob_private.unlock(TEST_PASSPHRASE)?;
        let proposal = deterministic_group("Release owners", 2, vec![alice_public, bob_public])?;
        let alice_acceptance = accept_group(&proposal, &alice)?;
        let bob_acceptance = accept_group(&proposal, &bob)?;

        let forged_acceptance = replace_acceptance_signature(alice_acceptance, &bob_acceptance);
        assert!(matches!(
            finalize_group(proposal, vec![forged_acceptance, bob_acceptance]),
            Err(ChainError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn threshold_consensus_encrypts_once_for_multiple_recipients()
    -> Result<(), Box<dyn std::error::Error>> {
        let (alice_private, alice_public) = deterministic_identity(0x51, "Alice")?;
        let (bob_private, bob_public) = deterministic_identity(0x61, "Bob")?;
        let (carol_private, carol_public) = deterministic_identity(0x71, "Carol")?;
        let (reader_private, reader_public) = deterministic_identity(0x81, "Reader")?;
        let alice = alice_private.unlock(TEST_PASSPHRASE)?;
        let bob = bob_private.unlock(TEST_PASSPHRASE)?;
        let carol = carol_private.unlock(TEST_PASSPHRASE)?;
        let reader = reader_private.unlock(TEST_PASSPHRASE)?;
        let group_proposal = deterministic_group(
            "Two of three owners",
            2,
            vec![alice_public, bob_public, carol_public],
        )?;
        let group = finalize_group(
            group_proposal.clone(),
            vec![
                accept_group(&group_proposal, &alice)?,
                accept_group(&group_proposal, &bob)?,
                accept_group(&group_proposal, &carol)?,
            ],
        )?;
        let artifact = artifact_bytes()?;
        let limits = ChainLimits::STANDARD;
        let proposal = create_capsule_proposal(
            group,
            &artifact,
            vec![alice.public_identity().clone(), reader_public],
            &limits,
        )?;
        let alice_approval = approve_capsule(&proposal, &alice, &limits)?;
        let bob_approval = approve_capsule(&proposal, &bob, &limits)?;
        assert!(matches!(
            finalize_capsule(proposal.clone(), vec![alice_approval.clone()], &limits),
            Err(ChainError::InsufficientApprovals)
        ));
        assert!(matches!(
            finalize_capsule(
                proposal.clone(),
                vec![alice_approval.clone(), alice_approval.clone()],
                &limits
            ),
            Err(ChainError::DuplicateIdentity)
        ));
        assert!(matches!(
            approve_capsule(&proposal, &reader, &limits),
            Err(ChainError::NotGroupMember)
        ));
        let replay_target = create_capsule_proposal(
            proposal.group().clone(),
            &artifact,
            vec![
                alice.public_identity().clone(),
                reader.public_identity().clone(),
            ],
            &limits,
        )?;
        assert!(matches!(
            finalize_capsule(
                replay_target,
                vec![alice_approval.clone(), bob_approval.clone()],
                &limits
            ),
            Err(ChainError::BindingMismatch)
        ));
        let envelope = finalize_capsule(proposal, vec![alice_approval, bob_approval], &limits)?;
        let token = envelope.to_token(&limits)?;
        let reparsed = CapsuleEnvelope::from_token(&token, &limits)?;
        let alice_opened = open_capsule(&reparsed, &alice, &limits)?;
        assert_eq!(alice_opened.artifact_binary(), artifact);
        assert!(!format!("{alice_opened:?}").contains("reconstructs these exact bytes"));
        assert_eq!(
            open_capsule(&reparsed, &reader, &limits)?.artifact_binary(),
            artifact
        );
        assert!(matches!(
            open_capsule(&reparsed, &carol, &limits),
            Err(ChainError::NotRecipient)
        ));
        Ok(())
    }

    #[test]
    fn envelope_mutation_and_trailing_bytes_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let (private, public) = deterministic_identity(0x91, "Solo")?;
        let identity = private.unlock(TEST_PASSPHRASE)?;
        let group_proposal = deterministic_group("Solo owner", 1, vec![public])?;
        let group = finalize_group(
            group_proposal.clone(),
            vec![accept_group(&group_proposal, &identity)?],
        )?;
        let limits = ChainLimits {
            artifact: SecurityLimits::SIMPLE_ARTIFACT,
            ..ChainLimits::STANDARD
        };
        let proposal = create_capsule_proposal(
            group,
            &artifact_bytes()?,
            vec![identity.public_identity().clone()],
            &limits,
        )?;
        let approval = approve_capsule(&proposal, &identity, &limits)?;
        let envelope = finalize_capsule(proposal, vec![approval], &limits)?;
        let bytes = envelope.to_bytes(&limits)?;
        let truncation_lengths = [
            0,
            1,
            3,
            4,
            5,
            7,
            8,
            bytes.len() / 4,
            bytes.len() / 2,
            bytes.len().saturating_mul(3) / 4,
            bytes.len().saturating_sub(33),
            bytes.len().saturating_sub(32),
            bytes.len().saturating_sub(1),
        ];
        for length in truncation_lengths {
            assert!(
                CapsuleEnvelope::from_bytes(&bytes[..length], &limits).is_err(),
                "truncated envelope unexpectedly passed at length {length}"
            );
        }
        let mut mutated = bytes.clone();
        let index = mutated.len().saturating_sub(40);
        if let Some(byte) = mutated.get_mut(index) {
            *byte ^= 0x80;
        }
        assert!(CapsuleEnvelope::from_bytes(&mutated, &limits).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CapsuleEnvelope::from_bytes(&trailing, &limits).is_err());
        Ok(())
    }
}
