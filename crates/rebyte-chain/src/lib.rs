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

mod backup;
mod ceremony;
mod challenge;
mod codec;
mod envelope;
mod error;
mod group;
mod identity;
mod release;
mod secret_sharing;
mod status;
#[cfg(test)]
mod vector_tests;

pub use backup::{IdentityBackupShare, backup_identity, restore_identity};
pub use ceremony::{
    CeremonyMember, CeremonyStatus, RejectedDocument, capsule_ceremony_status,
    group_ceremony_status,
};
pub use challenge::{
    ChallengeAward, ChallengeClaim, ChallengeProposalOptions, ChallengeShardSolution,
    ShardedChallengeProposalOptions, create_challenge_award, create_challenge_capsule_proposal,
    create_challenge_claim, create_sharded_challenge_capsule_proposal,
    create_sharded_challenge_claim, open_challenge_content, open_sharded_challenge_content,
    verify_challenge_award, verify_challenge_claim, verify_challenge_shard,
    verify_sharded_challenge_claim,
};
pub use envelope::{
    create_challenge_content_proposal_with_contract, create_key_sequence_capsule_proposal,
    create_key_sequence_content_proposal_with_contract,
    create_sharded_challenge_content_proposal_with_contract, open_key_sequence_capsule,
};
pub use status::{
    IdentityStatus, IdentityStatusDocument, deny_statused_identities, issue_identity_status,
};

pub use envelope::{
    CAPSULE_TOKEN_PREFIX, CapsuleApproval, CapsuleEnvelope, CapsuleProposal, ChainLimits,
    OpenedCapsule, OpenedContent, OpenedSemanticPatch, QuorumProposalOptions, approve_capsule,
    create_capsule_proposal, create_capsule_proposal_with_contract,
    create_content_proposal_with_contract, create_quorum_capsule_proposal,
    create_quorum_content_proposal_with_contract, create_quorum_semantic_patch_proposal,
    create_semantic_patch_proposal, finalize_capsule, open_capsule, open_semantic_patch,
};
pub use error::ChainError;
pub use group::{
    GroupAcceptance, GroupCertificate, GroupId, GroupProposal, accept_group, finalize_group,
};
pub use identity::{
    EncryptedIdentityDocument, IdentityId, IdentityPublicDocument, UnlockedIdentity,
    generate_identity, rekey_identity,
};
pub use rebyte_contract::{
    AccessContract, AccessContractBuilder, Capabilities, Capability, ChallengeRelease,
    ChallengeShard, ContentCommitment, ContentKind, ContractError, ContractId, KeySequenceRelease,
    PrincipalId, QuorumRelease, ReleasePolicy, ShardedChallengeRelease,
};
pub use release::{
    MemoryReleaseLedger, ReleaseAuthorization, ReleaseGrant, ReleaseLedger, ReleaseRequest,
    TrustedClock, create_release_request, grant_release, open_quorum_content,
};

#[cfg(test)]
mod tests {
    use rebyte_artifact_token::{Artifact, ArtifactOptions, encode_artifact};
    use rebyte_format::SecurityLimits;
    use rebyte_semantic::{PatchFormat, PatchOperation, SemanticPatch};

    use super::{
        AccessContract, Capabilities, CapsuleEnvelope, ChainError, ChainLimits, ContentCommitment,
        ContentKind, PrincipalId, QuorumRelease, ReleasePolicy, accept_group, approve_capsule,
        create_capsule_proposal, create_capsule_proposal_with_contract,
        create_semantic_patch_proposal, finalize_capsule, finalize_group, open_capsule,
        open_semantic_patch,
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
    #[allow(clippy::too_many_lines)] // One multi-party fixture covers exact and patch content.
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
            group.clone(),
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

        let patch = SemanticPatch::new(
            PatchFormat::Json,
            None,
            vec![PatchOperation::Set {
                path: "/service/port".to_string(),
                value: serde_json::json!(8080),
            }],
        )?;
        let patch_bytes = patch.to_json_bytes()?;
        let compact_patch = serde_json::to_vec(&patch)?;
        assert!(matches!(
            create_semantic_patch_proposal(
                group.clone(),
                &compact_patch,
                vec![reader.public_identity().clone()],
                &limits,
            ),
            Err(ChainError::InvalidContent)
        ));
        let patch_proposal = create_semantic_patch_proposal(
            group,
            &patch_bytes,
            vec![reader.public_identity().clone()],
            &limits,
        )?;
        assert_eq!(
            patch_proposal.contract().content().kind(),
            ContentKind::SemanticPatch
        );
        let patch_envelope = finalize_capsule(
            patch_proposal.clone(),
            vec![
                approve_capsule(&patch_proposal, &alice, &limits)?,
                approve_capsule(&patch_proposal, &bob, &limits)?,
            ],
            &limits,
        )?;
        assert_eq!(
            open_semantic_patch(&patch_envelope, &reader, &limits)?.patch(),
            &patch
        );
        assert!(matches!(
            open_capsule(&patch_envelope, &reader, &limits),
            Err(ChainError::InvalidContent)
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
            group.clone(),
            &artifact_bytes()?,
            vec![identity.public_identity().clone()],
            &limits,
        )?;
        assert!(matches!(
            proposal.contract().release(),
            ReleasePolicy::DirectRecipients
        ));
        assert_eq!(
            proposal.contract().content().digest(),
            proposal.content_digest()
        );
        assert_eq!(
            proposal.contract().content().size(),
            proposal.content_size()
        );
        let quorum = QuorumRelease::new(
            vec![PrincipalId::from_bytes(*identity.identity_id().as_bytes())],
            1,
            Some(1_800_000_000_000),
            Some(1),
        )?;
        let quorum_contract = AccessContract::builder(
            PrincipalId::from_bytes(*group.group_id()?.as_bytes()),
            ContentCommitment::new(
                ContentKind::ExactArtifact,
                *proposal.content_digest(),
                proposal.content_size(),
            ),
        )
        .controllers(
            proposal.contract().controllers().to_vec(),
            group.capsule_threshold(),
        )
        .recipients(proposal.contract().recipients().to_vec())
        .capabilities(Capabilities::RECONSTRUCT)
        .release(ReleasePolicy::Quorum(quorum))
        .build()?;
        assert!(matches!(
            create_capsule_proposal_with_contract(
                group,
                &artifact_bytes()?,
                vec![identity.public_identity().clone()],
                quorum_contract,
                &limits,
            ),
            Err(ChainError::UnsupportedReleasePolicy)
        ));
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

    #[test]
    #[allow(clippy::too_many_lines)] // One fixture covers every sequence abuse case.
    fn key_sequences_open_only_with_every_key_in_order() -> Result<(), Box<dyn std::error::Error>> {
        use super::{create_key_sequence_capsule_proposal, open_key_sequence_capsule};

        let (creator_private, creator_public) = deterministic_identity(0x91, "Creator")?;
        let (a1_private, a1_public) = deterministic_identity(0x92, "Alice laptop")?;
        let (a2_private, a2_public) = deterministic_identity(0x93, "Alice vault")?;
        let (b1_private, b1_public) = deterministic_identity(0x94, "Bob laptop")?;
        let (b2_private, b2_public) = deterministic_identity(0x95, "Bob vault")?;
        let creator = creator_private.unlock(TEST_PASSPHRASE)?;
        let a1 = a1_private.unlock(TEST_PASSPHRASE)?;
        let a2 = a2_private.unlock(TEST_PASSPHRASE)?;
        let b1 = b1_private.unlock(TEST_PASSPHRASE)?;
        let b2 = b2_private.unlock(TEST_PASSPHRASE)?;
        let group_proposal = deterministic_group("Sequence owners", 1, vec![creator_public])?;
        let group = finalize_group(
            group_proposal.clone(),
            vec![accept_group(&group_proposal, &creator)?],
        )?;
        let artifact = artifact_bytes()?;
        let limits = ChainLimits::STANDARD;

        assert!(matches!(
            create_key_sequence_capsule_proposal(
                group.clone(),
                &artifact,
                vec![vec![a1_public.clone(), a1_public.clone()]],
                &limits,
            ),
            Err(ChainError::DuplicateIdentity)
        ));

        let proposal = create_key_sequence_capsule_proposal(
            group,
            &artifact,
            vec![vec![a1_public, a2_public], vec![b1_public, b2_public]],
            &limits,
        )?;
        let envelope = finalize_capsule(
            proposal.clone(),
            vec![approve_capsule(&proposal, &creator, &limits)?],
            &limits,
        )?;
        let bytes = envelope.to_bytes(&limits)?;
        let envelope = CapsuleEnvelope::from_bytes(&bytes, &limits)?;

        let opened = open_key_sequence_capsule(&envelope, &[&a1, &a2], &limits)?;
        assert_eq!(opened.artifact_binary(), artifact);
        let opened = open_key_sequence_capsule(&envelope, &[&b1, &b2], &limits)?;
        assert_eq!(opened.artifact_binary(), artifact);

        assert!(matches!(
            open_key_sequence_capsule(&envelope, &[&a2, &a1], &limits),
            Err(ChainError::NotRecipient)
        ));
        assert!(matches!(
            open_key_sequence_capsule(&envelope, &[&a1, &b2], &limits),
            Err(ChainError::NotRecipient)
        ));
        assert!(matches!(
            open_key_sequence_capsule(&envelope, &[&a2], &limits),
            Err(ChainError::NotRecipient)
        ));
        assert!(matches!(
            open_capsule(&envelope, &a2, &limits),
            Err(ChainError::UnsupportedReleasePolicy)
        ));

        for offset in [bytes.len() - 40, bytes.len() / 2] {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 0x01;
            assert!(CapsuleEnvelope::from_bytes(&mutated, &limits).is_err());
        }
        Ok(())
    }
}
