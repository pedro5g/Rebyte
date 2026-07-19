// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ceremony progress reports: which signatures a coordinator still needs.
//!
//! Both Chain ceremonies collect detached signature documents offline: group
//! formation needs one acceptance from every member, capsule finalization
//! needs the group capsule threshold of approvals. These helpers verify a
//! partial collection without finalizing anything, so a coordinator sees
//! exactly which members are still pending and which supplied documents can
//! never count. A rejected document is reported, never silently dropped.

use crate::envelope::{CapsuleApproval, CapsuleProposal, ChainLimits, verify_capsule_approval};
use crate::group::{GroupAcceptance, GroupProposal, verify_acceptance};
use crate::{ChainError, IdentityId};

/// One group member's progress inside a signature ceremony.
#[derive(Clone, Debug)]
pub struct CeremonyMember {
    identity_id: IdentityId,
    display_name: String,
    signed: bool,
}

impl CeremonyMember {
    /// Returns the member identity.
    #[must_use]
    pub const fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }

    /// Returns the member display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns whether one valid signature document was supplied.
    #[must_use]
    pub const fn signed(&self) -> bool {
        self.signed
    }
}

/// One supplied document that can never count, by input position.
#[derive(Clone, Copy, Debug)]
pub struct RejectedDocument {
    index: usize,
    error: ChainError,
}

impl RejectedDocument {
    /// Returns the zero-based position inside the supplied collection.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Returns why the document was rejected.
    #[must_use]
    pub const fn error(&self) -> ChainError {
        self.error
    }
}

/// Progress of one ceremony toward its signature requirement.
#[derive(Clone, Debug)]
pub struct CeremonyStatus {
    required_signatures: usize,
    members: Vec<CeremonyMember>,
    rejected: Vec<RejectedDocument>,
}

impl CeremonyStatus {
    /// Returns how many distinct valid signatures finalization needs.
    #[must_use]
    pub const fn required_signatures(&self) -> usize {
        self.required_signatures
    }

    /// Returns how many distinct valid signatures were supplied.
    #[must_use]
    pub fn collected_signatures(&self) -> usize {
        self.members.iter().filter(|member| member.signed).count()
    }

    /// Returns whether finalization can proceed with the counted documents.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.collected_signatures() >= self.required_signatures
    }

    /// Returns every group member with its progress, in proposal order.
    #[must_use]
    pub fn members(&self) -> &[CeremonyMember] {
        &self.members
    }

    /// Returns every supplied document that can never count.
    #[must_use]
    pub fn rejected_documents(&self) -> &[RejectedDocument] {
        &self.rejected
    }
}

/// Reports group-formation progress for a partial acceptance collection.
///
/// Group formation is always unanimous: every listed member must accept.
///
/// # Errors
///
/// Returns [`ChainError`] when the proposal itself is invalid; individual
/// unusable acceptances are reported inside the status instead.
pub fn group_ceremony_status(
    proposal: &GroupProposal,
    acceptances: &[GroupAcceptance],
) -> Result<CeremonyStatus, ChainError> {
    let group_id = proposal.group_id()?;
    let mut members = pending_members(proposal.members())?;
    let mut rejected = Vec::new();
    for (index, acceptance) in acceptances.iter().enumerate() {
        let counted = acceptance.member_id().and_then(|member_id| {
            let position = signable_position(&members, &member_id)?;
            let member = proposal
                .member(&member_id)
                .ok_or(ChainError::NotGroupMember)?;
            verify_acceptance(&group_id, member, acceptance)?;
            Ok(position)
        });
        match counted {
            Ok(position) => members[position].signed = true,
            Err(error) => rejected.push(RejectedDocument { index, error }),
        }
    }
    Ok(CeremonyStatus {
        required_signatures: members.len(),
        members,
        rejected,
    })
}

/// Reports capsule-approval progress for a partial approval collection.
///
/// # Errors
///
/// Returns [`ChainError`] when the proposal itself is invalid; individual
/// unusable approvals are reported inside the status instead.
pub fn capsule_ceremony_status(
    proposal: &CapsuleProposal,
    approvals: &[CapsuleApproval],
    limits: &ChainLimits,
) -> Result<CeremonyStatus, ChainError> {
    proposal.validate(limits)?;
    let group_id = proposal.group().group_id()?;
    let mut members = pending_members(proposal.group().proposal().members())?;
    let mut rejected = Vec::new();
    for (index, approval) in approvals.iter().enumerate() {
        let counted = approval.member_id().and_then(|member_id| {
            let position = signable_position(&members, &member_id)?;
            verify_capsule_approval(&group_id, proposal, approval)?;
            Ok(position)
        });
        match counted {
            Ok(position) => members[position].signed = true,
            Err(error) => rejected.push(RejectedDocument { index, error }),
        }
    }
    Ok(CeremonyStatus {
        required_signatures: usize::from(proposal.group().capsule_threshold()),
        members,
        rejected,
    })
}

// Callers must have validated every listed member on the current data.
fn pending_members(
    members: &[crate::IdentityPublicDocument],
) -> Result<Vec<CeremonyMember>, ChainError> {
    members
        .iter()
        .map(|member| {
            Ok(CeremonyMember {
                identity_id: member.identity_id_unchecked()?,
                display_name: member.display_name().to_string(),
                signed: false,
            })
        })
        .collect()
}

fn signable_position(
    members: &[CeremonyMember],
    member_id: &IdentityId,
) -> Result<usize, ChainError> {
    let position = members
        .iter()
        .position(|member| member.identity_id == *member_id)
        .ok_or(ChainError::NotGroupMember)?;
    if members[position].signed {
        return Err(ChainError::DuplicateIdentity);
    }
    Ok(position)
}

#[cfg(test)]
mod tests {
    use super::{capsule_ceremony_status, group_ceremony_status};
    use crate::group::deterministic_group;
    use crate::identity::deterministic_identity;
    use crate::{
        ChainLimits, accept_group, approve_capsule, create_capsule_proposal, finalize_group,
    };

    const TEST_PASSPHRASE: &[u8] = b"test-only-passphrase";

    #[test]
    fn group_progress_counts_only_valid_unique_acceptances()
    -> Result<(), Box<dyn std::error::Error>> {
        let (alice_private, alice_public) = deterministic_identity(0x71, "Alice")?;
        let (bob_private, bob_public) = deterministic_identity(0x72, "Bob")?;
        let (mallory_private, _) = deterministic_identity(0x73, "Mallory")?;
        let alice = alice_private.unlock(TEST_PASSPHRASE)?;
        let bob = bob_private.unlock(TEST_PASSPHRASE)?;
        let mallory = mallory_private.unlock(TEST_PASSPHRASE)?;
        let proposal = deterministic_group("Ceremony", 2, vec![alice_public, bob_public])?;

        let empty = group_ceremony_status(&proposal, &[])?;
        assert_eq!(empty.required_signatures(), 2);
        assert_eq!(empty.collected_signatures(), 0);
        assert!(!empty.ready());

        let alice_acceptance = accept_group(&proposal, &alice)?;
        let foreign = deterministic_group("Other", 1, vec![mallory.public_identity().clone()])?;
        let foreign_acceptance = accept_group(&foreign, &mallory)?;
        let partial = group_ceremony_status(
            &proposal,
            &[
                alice_acceptance.clone(),
                alice_acceptance.clone(),
                foreign_acceptance,
            ],
        )?;
        assert_eq!(partial.collected_signatures(), 1);
        assert_eq!(partial.rejected_documents().len(), 2);
        assert_eq!(partial.rejected_documents()[0].index(), 1);
        assert!(!partial.ready());

        let complete = group_ceremony_status(
            &proposal,
            &[alice_acceptance, accept_group(&proposal, &bob)?],
        )?;
        assert_eq!(complete.collected_signatures(), 2);
        assert!(complete.ready());
        assert!(complete.members().iter().all(super::CeremonyMember::signed));
        Ok(())
    }

    #[test]
    fn capsule_progress_uses_the_group_threshold() -> Result<(), Box<dyn std::error::Error>> {
        let (alice_private, alice_public) = deterministic_identity(0x74, "Alice")?;
        let (bob_private, bob_public) = deterministic_identity(0x75, "Bob")?;
        let alice = alice_private.unlock(TEST_PASSPHRASE)?;
        let bob = bob_private.unlock(TEST_PASSPHRASE)?;
        let group_proposal = deterministic_group("Owners", 1, vec![alice_public, bob_public])?;
        let group = finalize_group(
            group_proposal.clone(),
            vec![
                accept_group(&group_proposal, &alice)?,
                accept_group(&group_proposal, &bob)?,
            ],
        )?;
        let limits = ChainLimits::STANDARD;
        let artifact = rebyte_artifact_token::encode_artifact(
            &rebyte_artifact_token::Artifact::file(b"ceremony content\n".to_vec(), false),
            &rebyte_artifact_token::ArtifactOptions::default(),
        )?
        .into_binary();
        let proposal = create_capsule_proposal(
            group,
            &artifact,
            vec![alice.public_identity().clone()],
            &limits,
        )?;

        let waiting = capsule_ceremony_status(&proposal, &[], &limits)?;
        assert_eq!(waiting.required_signatures(), 1);
        assert!(!waiting.ready());

        let ready = capsule_ceremony_status(
            &proposal,
            &[approve_capsule(&proposal, &bob, &limits)?],
            &limits,
        )?;
        assert_eq!(ready.collected_signatures(), 1);
        assert!(ready.ready());
        assert!(!ready.members()[0].signed());
        assert!(ready.members()[1].signed());
        Ok(())
    }
}
