// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Computational-challenge capsules: solve to open, or open as an auditor.
//!
//! A challenge capsule wraps the content key twice: once for every listed
//! recipient (the creators' audited path) and once under a memory-hard
//! Argon2id derivation of a creator-chosen secret solution. Anyone holding
//! the envelope may search for the solution; each guess costs one full
//! Argon2id evaluation. A challenge is a cost gate, not access control, and
//! must never protect real confidential data. Difficulty adapts to solver
//! understanding of the creator-published hints, never to how many people
//! are solving.

#![allow(clippy::redundant_pub_crate)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, VerifyingKey};
use rebyte_contract::{
    AccessContract, Capabilities, ChallengeRelease, ContentCommitment, ContentKind, PrincipalId,
    ReleasePolicy,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::codec::{decode_array, domain_hash, encode_base64, put_u16};
use crate::envelope::{
    CapsuleEnvelope, ChainLimits, OpenedContent, challenge_aad, decrypt_payload_core,
    opened_content,
};
use crate::{ChainError, GroupCertificate, IdentityId, IdentityPublicDocument, UnlockedIdentity};

const DOCUMENT_VERSION: u16 = 1;
const CLAIM_KIND: &str = "rebyte-chain-challenge-claim";
const AWARD_KIND: &str = "rebyte-chain-challenge-award";
const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"rebyte chain challenge claim v1\0";
const AWARD_SIGNATURE_DOMAIN: &[u8] = b"rebyte chain challenge award v1\0";
const COMMITMENT_CONTEXT: &str = "Rebyte Chain challenge commitment v1 2026-07-18";
const CLAIM_PROOF_CONTEXT: &str = "Rebyte Chain challenge claim proof v1 2026-07-18";
const CLAIM_ID_CONTEXT: &str = "Rebyte Chain challenge claim id v1 2026-07-18";
const MIN_SOLUTION_BYTES: usize = 1;
const MAX_SOLUTION_BYTES: usize = 4_096;
const KDF_LANES: u32 = 1;

/// Creator-selected challenge parameters for one capsule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeProposalOptions {
    /// Argon2id memory cost of one solution guess in `KiB`.
    pub kdf_memory_kib: u32,
    /// Argon2id passes of one solution guess.
    pub kdf_iterations: u32,
    /// Public pointer to the parameter space; insight prunes the search.
    pub hint: String,
}

impl ChallengeProposalOptions {
    /// Creates challenge parameters.
    #[must_use]
    pub const fn new(kdf_memory_kib: u32, kdf_iterations: u32, hint: String) -> Self {
        Self {
            kdf_memory_kib,
            kdf_iterations,
            hint,
        }
    }
}

/// Encrypts one exact artifact behind a computational challenge.
///
/// `recipients` are the audited opening path and must contain at least one
/// identity; `solution` is the exact secret byte string whose canonical
/// reconstruction opens the capsule.
///
/// # Errors
///
/// Returns [`ChainError`] for an empty or oversized solution, invalid
/// parameters, identities or content, or a cryptographic failure.
pub fn create_challenge_capsule_proposal(
    group: GroupCertificate,
    artifact_binary: &[u8],
    recipients: Vec<IdentityPublicDocument>,
    solution: &[u8],
    options: &ChallengeProposalOptions,
    limits: &ChainLimits,
) -> Result<crate::CapsuleProposal, ChainError> {
    group.validate()?;
    let mut challenge_salt = [0_u8; 16];
    getrandom::fill(&mut challenge_salt).map_err(|_| ChainError::EntropyUnavailable)?;
    let policy = ChallengeRelease::new(
        options.kdf_memory_kib,
        options.kdf_iterations,
        [0; 32],
        challenge_salt,
        options.hint.clone(),
    )
    .map_err(|_| ChainError::InvalidContract)?;
    let solution_key = derive_solution_key(solution, &policy)?;
    let commitment = solution_commitment(&solution_key);
    let policy = ChallengeRelease::new(
        options.kdf_memory_kib,
        options.kdf_iterations,
        commitment,
        challenge_salt,
        options.hint.clone(),
    )
    .map_err(|_| ChainError::InvalidContract)?;
    let group_id = group.group_id()?;
    let controllers = group
        .proposal()
        .members()
        .iter()
        .map(|member| member.identity_id().map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let recipient_ids = recipients
        .iter()
        .map(|identity| identity.identity_id().map(principal_id))
        .collect::<Result<Vec<_>, _>>()?;
    let contract = AccessContract::builder(
        PrincipalId::from_bytes(*group_id.as_bytes()),
        ContentCommitment::new(
            ContentKind::ExactArtifact,
            crate::envelope::protected_content_digest(artifact_binary),
            u64::try_from(artifact_binary.len()).map_err(|_| ChainError::LengthOverflow)?,
        ),
    )
    .controllers(controllers, group.capsule_threshold())
    .recipients(recipient_ids)
    .capabilities(Capabilities::APPLY_EXACT)
    .release(ReleasePolicy::Challenge(policy))
    .build()
    .map_err(|_| ChainError::InvalidContract)?;
    crate::envelope::create_challenge_content_proposal_with_contract(
        group,
        artifact_binary,
        recipients,
        contract,
        &solution_key,
        limits,
    )
}

/// Opens a challenge capsule with the exact secret solution.
///
/// The opener is anonymous: the returned content reports the zero identity
/// as its recipient. Listed recipients keep the ordinary `open_capsule` path.
///
/// # Errors
///
/// Returns [`ChainError::AuthenticationFailed`] for a wrong solution, or
/// another [`ChainError`] for an invalid envelope or non-challenge policy.
pub fn open_challenge_content(
    envelope: &CapsuleEnvelope,
    solution: &[u8],
    limits: &ChainLimits,
) -> Result<OpenedContent, ChainError> {
    let cek = release_challenge_cek(envelope, solution, limits)?;
    let decrypted = decrypt_payload_core(
        envelope,
        IdentityId::from_bytes([0; 32]),
        cek.as_ref(),
        limits,
    )?;
    opened_content(decrypted)
}

/// One solver's signed, solution-bound proof for a challenge capsule.
///
/// The proof reveals nothing about the solution; only a party that also
/// knows the solution (normally a creator) can verify it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeClaim {
    schema_version: u16,
    kind: String,
    envelope_id: String,
    contract_id: String,
    solver: IdentityPublicDocument,
    claim_nonce: String,
    solution_proof: String,
    claim_id: String,
    signature: String,
}

impl ChallengeClaim {
    /// Parses and verifies canonical claim JSON and its solver signature.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, non-canonical or invalidly
    /// signed data.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let claim: Self = serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        claim.validate_shape()?;
        if claim.to_json()?.as_slice() != bytes {
            return Err(ChainError::InvalidDocument);
        }
        Ok(claim)
    }

    /// Serializes stable canonical JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::InvalidDocument`] if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, ChainError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| ChainError::InvalidDocument)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns the claiming solver identity.
    #[must_use]
    pub const fn solver(&self) -> &IdentityPublicDocument {
        &self.solver
    }

    /// Returns the stable claim identifier that awards countersign.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] when the claim is invalid.
    pub fn claim_id(&self) -> Result<[u8; 32], ChainError> {
        self.validate_shape()?;
        decode_array(&self.claim_id)
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != CLAIM_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        self.solver.validate()?;
        let _envelope_id: [u8; 32] = decode_array(&self.envelope_id)?;
        let _contract_id: [u8; 32] = decode_array(&self.contract_id)?;
        let _nonce: [u8; 32] = decode_array(&self.claim_nonce)?;
        let _proof: [u8; 32] = decode_array(&self.solution_proof)?;
        let claim_id: [u8; 32] = decode_array(&self.claim_id)?;
        let signature: [u8; 64] = decode_array(&self.signature)?;
        let message = claim_message(self)?;
        if domain_hash(CLAIM_ID_CONTEXT, &[&message, &signature]) != claim_id {
            return Err(ChainError::BindingMismatch);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.solver.signing_public_key()?)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        verifying_key
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| ChainError::InvalidSignature)
    }
}

/// Creates a signed claim proving this solver knows the exact solution.
///
/// # Errors
///
/// Returns [`ChainError::AuthenticationFailed`] when the solution is wrong,
/// or another [`ChainError`] for an invalid envelope.
pub fn create_challenge_claim(
    envelope: &CapsuleEnvelope,
    solver: &UnlockedIdentity,
    solution: &[u8],
    limits: &ChainLimits,
) -> Result<ChallengeClaim, ChainError> {
    let solution_key = verified_solution_key(envelope, solution, limits)?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ChainError::EntropyUnavailable)?;
    let solver_id = solver.identity_id();
    let proof = claim_proof(&solution_key, envelope.envelope_id(), &solver_id, &nonce);
    let mut claim = ChallengeClaim {
        schema_version: DOCUMENT_VERSION,
        kind: CLAIM_KIND.to_string(),
        envelope_id: encode_base64(envelope.envelope_id()),
        contract_id: envelope.proposal().contract().contract_id().to_base64(),
        solver: solver.public_identity().clone(),
        claim_nonce: encode_base64(&nonce),
        solution_proof: encode_base64(&proof),
        claim_id: encode_base64(&[0; 32]),
        signature: encode_base64(&[0; 64]),
    };
    let message = claim_message(&claim)?;
    let signature = solver.sign(&message);
    claim.claim_id = encode_base64(&domain_hash(CLAIM_ID_CONTEXT, &[&message, &signature]));
    claim.signature = encode_base64(&signature);
    claim.validate_shape()?;
    Ok(claim)
}

/// Verifies a claim against the envelope using knowledge of the solution.
///
/// # Errors
///
/// Returns [`ChainError::AuthenticationFailed`] when the claim proof does not
/// match the solution, or another [`ChainError`] for broken bindings.
pub fn verify_challenge_claim(
    envelope: &CapsuleEnvelope,
    claim: &ChallengeClaim,
    solution: &[u8],
    limits: &ChainLimits,
) -> Result<(), ChainError> {
    claim.validate_shape()?;
    let solution_key = verified_solution_key(envelope, solution, limits)?;
    if decode_array::<32>(&claim.envelope_id)? != *envelope.envelope_id()
        || decode_array::<32>(&claim.contract_id)?
            != *envelope.proposal().contract().contract_id().as_bytes()
    {
        return Err(ChainError::BindingMismatch);
    }
    let expected = claim_proof(
        &solution_key,
        envelope.envelope_id(),
        &claim.solver.identity_id()?,
        &decode_array::<32>(&claim.claim_nonce)?,
    );
    if bool::from(expected.ct_eq(&decode_array::<32>(&claim.solution_proof)?)) {
        Ok(())
    } else {
        Err(ChainError::AuthenticationFailed)
    }
}

/// A listed recipient's countersignature naming one claim the winner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeAward {
    schema_version: u16,
    kind: String,
    claim_id: String,
    envelope_id: String,
    judge: IdentityPublicDocument,
    signature: String,
}

impl ChallengeAward {
    /// Parses and verifies canonical award JSON and its judge signature.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] for malformed, non-canonical or invalidly
    /// signed data.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ChainError> {
        let award: Self = serde_json::from_slice(bytes).map_err(|_| ChainError::InvalidDocument)?;
        award.validate_shape()?;
        if award.to_json()?.as_slice() != bytes {
            return Err(ChainError::InvalidDocument);
        }
        Ok(award)
    }

    /// Serializes stable canonical JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::InvalidDocument`] if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, ChainError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| ChainError::InvalidDocument)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn validate_shape(&self) -> Result<(), ChainError> {
        if self.schema_version != DOCUMENT_VERSION || self.kind != AWARD_KIND {
            return Err(ChainError::UnsupportedDocument);
        }
        self.judge.validate()?;
        let claim_id: [u8; 32] = decode_array(&self.claim_id)?;
        let envelope_id: [u8; 32] = decode_array(&self.envelope_id)?;
        let signature: [u8; 64] = decode_array(&self.signature)?;
        let judge_id = self.judge.identity_id()?;
        let verifying_key = VerifyingKey::from_bytes(&self.judge.signing_public_key()?)
            .map_err(|_| ChainError::InvalidPublicKey)?;
        verifying_key
            .verify_strict(
                &award_message(&claim_id, &envelope_id, &judge_id),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| ChainError::InvalidSignature)
    }
}

/// Countersigns one verified claim as a listed challenge recipient.
///
/// # Errors
///
/// Returns [`ChainError::NotRecipient`] when the judge is not a listed
/// recipient, or another [`ChainError`] for invalid documents.
pub fn create_challenge_award(
    envelope: &CapsuleEnvelope,
    claim: &ChallengeClaim,
    judge: &UnlockedIdentity,
    limits: &ChainLimits,
) -> Result<ChallengeAward, ChainError> {
    envelope.validate(limits)?;
    claim.validate_shape()?;
    let judge_id = judge.identity_id();
    if !envelope
        .proposal()
        .contract()
        .recipients()
        .contains(&principal_id(judge_id))
    {
        return Err(ChainError::NotRecipient);
    }
    let claim_id = claim.claim_id()?;
    let award = ChallengeAward {
        schema_version: DOCUMENT_VERSION,
        kind: AWARD_KIND.to_string(),
        claim_id: encode_base64(&claim_id),
        envelope_id: encode_base64(envelope.envelope_id()),
        judge: judge.public_identity().clone(),
        signature: encode_base64(&judge.sign(&award_message(
            &claim_id,
            envelope.envelope_id(),
            &judge_id,
        ))),
    };
    award.validate_shape()?;
    Ok(award)
}

/// Verifies that an award countersigns this exact claim and envelope.
///
/// # Errors
///
/// Returns [`ChainError`] for broken bindings or a judge that is not a
/// listed recipient of the envelope.
pub fn verify_challenge_award(
    envelope: &CapsuleEnvelope,
    claim: &ChallengeClaim,
    award: &ChallengeAward,
    limits: &ChainLimits,
) -> Result<(), ChainError> {
    envelope.validate(limits)?;
    award.validate_shape()?;
    if decode_array::<32>(&award.claim_id)? != claim.claim_id()?
        || decode_array::<32>(&award.envelope_id)? != *envelope.envelope_id()
    {
        return Err(ChainError::BindingMismatch);
    }
    if !envelope
        .proposal()
        .contract()
        .recipients()
        .contains(&principal_id(award.judge.identity_id()?))
    {
        return Err(ChainError::NotRecipient);
    }
    Ok(())
}

fn release_challenge_cek(
    envelope: &CapsuleEnvelope,
    solution: &[u8],
    limits: &ChainLimits,
) -> Result<Zeroizing<[u8; 32]>, ChainError> {
    let solution_key = verified_solution_key(envelope, solution, limits)?;
    let slot = envelope
        .proposal()
        .challenge_slot()
        .ok_or(ChainError::UnsupportedReleasePolicy)?;
    let core = envelope.proposal().core_bytes()?;
    let cipher = XChaCha20Poly1305::new_from_slice(solution_key.as_ref())
        .map_err(|_| ChainError::CryptographicFailure)?;
    let cek = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(slot.nonce),
                Payload {
                    msg: slot.wrapped_key.as_slice(),
                    aad: &challenge_aad(&core),
                },
            )
            .map_err(|_| ChainError::AuthenticationFailed)?,
    );
    let mut bounded = Zeroizing::new([0_u8; 32]);
    if cek.len() != bounded.len() {
        return Err(ChainError::CryptographicFailure);
    }
    bounded.as_mut().copy_from_slice(&cek);
    Ok(bounded)
}

fn verified_solution_key(
    envelope: &CapsuleEnvelope,
    solution: &[u8],
    limits: &ChainLimits,
) -> Result<Zeroizing<[u8; 32]>, ChainError> {
    envelope.validate(limits)?;
    let ReleasePolicy::Challenge(policy) = envelope.proposal().contract().release() else {
        return Err(ChainError::UnsupportedReleasePolicy);
    };
    let solution_key = derive_solution_key(solution, policy)?;
    let commitment = solution_commitment(&solution_key);
    if bool::from(commitment.ct_eq(policy.solution_commitment())) {
        Ok(solution_key)
    } else {
        Err(ChainError::AuthenticationFailed)
    }
}

pub(crate) fn derive_solution_key(
    solution: &[u8],
    policy: &ChallengeRelease,
) -> Result<Zeroizing<[u8; 32]>, ChainError> {
    if !(MIN_SOLUTION_BYTES..=MAX_SOLUTION_BYTES).contains(&solution.len()) {
        return Err(ChainError::InvalidContent);
    }
    let params = Params::new(
        policy.kdf_memory_kib(),
        policy.kdf_iterations(),
        KDF_LANES,
        Some(32),
    )
    .map_err(|_| ChainError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(solution, policy.challenge_salt(), key.as_mut())
        .map_err(|_| ChainError::KeyDerivation)?;
    Ok(key)
}

pub(crate) fn solution_commitment(solution_key: &Zeroizing<[u8; 32]>) -> [u8; 32] {
    domain_hash(COMMITMENT_CONTEXT, &[solution_key.as_ref()])
}

fn claim_proof(
    solution_key: &Zeroizing<[u8; 32]>,
    envelope_id: &[u8; 32],
    solver_id: &IdentityId,
    nonce: &[u8; 32],
) -> [u8; 32] {
    domain_hash(
        CLAIM_PROOF_CONTEXT,
        &[
            solution_key.as_ref(),
            envelope_id,
            solver_id.as_bytes(),
            nonce,
        ],
    )
}

fn claim_message(claim: &ChallengeClaim) -> Result<Vec<u8>, ChainError> {
    let mut message = Vec::new();
    message.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
    put_u16(&mut message, DOCUMENT_VERSION);
    message.extend_from_slice(&decode_array::<32>(&claim.envelope_id)?);
    message.extend_from_slice(&decode_array::<32>(&claim.contract_id)?);
    message.extend_from_slice(&decode_array::<32>(&claim.claim_nonce)?);
    message.extend_from_slice(&decode_array::<32>(&claim.solution_proof)?);
    message.extend_from_slice(&claim.solver.canonical_member_bytes()?);
    Ok(message)
}

fn award_message(claim_id: &[u8; 32], envelope_id: &[u8; 32], judge_id: &IdentityId) -> Vec<u8> {
    let mut message = Vec::with_capacity(AWARD_SIGNATURE_DOMAIN.len().saturating_add(96));
    message.extend_from_slice(AWARD_SIGNATURE_DOMAIN);
    message.extend_from_slice(claim_id);
    message.extend_from_slice(envelope_id);
    message.extend_from_slice(judge_id.as_bytes());
    message
}

const fn principal_id(identity_id: IdentityId) -> PrincipalId {
    PrincipalId::from_bytes(*identity_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use rebyte_artifact_token::{Artifact, ArtifactOptions, encode_artifact};

    use super::{
        ChallengeProposalOptions, create_challenge_award, create_challenge_capsule_proposal,
        create_challenge_claim, open_challenge_content, verify_challenge_award,
        verify_challenge_claim,
    };
    use crate::group::deterministic_group;
    use crate::identity::deterministic_identity;
    use crate::{
        CapsuleEnvelope, ChainError, ChainLimits, OpenedContent, accept_group, approve_capsule,
        finalize_capsule, finalize_group, open_capsule,
    };

    const TEST_PASSPHRASE: &[u8] = b"test-only-passphrase";
    const SOLUTION: &[u8] = b"port=8080;region=sao-paulo";

    fn test_options() -> ChallengeProposalOptions {
        // The 8 MiB minimum keeps the adversarial suite fast; production
        // challenges choose far higher per-guess costs.
        ChallengeProposalOptions::new(8 * 1_024, 1, "service port and region".to_string())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One expensive fixture covers solve, audit, claim and award.
    fn solution_and_audit_paths_open_while_wrong_solutions_fail()
    -> Result<(), Box<dyn std::error::Error>> {
        let (creator_private, creator_public) = deterministic_identity(0x61, "Creator")?;
        let (solver_private, _) = deterministic_identity(0x62, "Solver")?;
        let creator = creator_private.unlock(TEST_PASSPHRASE)?;
        let solver = solver_private.unlock(TEST_PASSPHRASE)?;
        let group_proposal = deterministic_group("Challenge owners", 1, vec![creator_public])?;
        let group = finalize_group(
            group_proposal.clone(),
            vec![accept_group(&group_proposal, &creator)?],
        )?;
        let artifact = encode_artifact(
            &Artifact::file(b"challenge prize bytes\n".to_vec(), false),
            &ArtifactOptions::default(),
        )?
        .into_binary();
        let limits = ChainLimits::STANDARD;
        let proposal = create_challenge_capsule_proposal(
            group,
            &artifact,
            vec![creator.public_identity().clone()],
            SOLUTION,
            &test_options(),
            &limits,
        )?;
        let envelope = finalize_capsule(
            proposal.clone(),
            vec![approve_capsule(&proposal, &creator, &limits)?],
            &limits,
        )?;
        let envelope_bytes = envelope.to_bytes(&limits)?;
        for length in [0, 8, envelope_bytes.len().saturating_sub(1)] {
            assert!(CapsuleEnvelope::from_bytes(&envelope_bytes[..length], &limits).is_err());
        }
        let envelope = CapsuleEnvelope::from_bytes(&envelope_bytes, &limits)?;

        let OpenedContent::ExactArtifact(opened) =
            open_challenge_content(&envelope, SOLUTION, &limits)?
        else {
            return Err("unexpected content kind".into());
        };
        assert_eq!(opened.artifact_binary(), artifact);

        assert!(matches!(
            open_challenge_content(&envelope, b"port=8081;region=sao-paulo", &limits),
            Err(ChainError::AuthenticationFailed)
        ));

        let audited = open_capsule(&envelope, &creator, &limits)?;
        assert_eq!(audited.artifact_binary(), artifact);

        let claim = create_challenge_claim(&envelope, &solver, SOLUTION, &limits)?;
        let claim = super::ChallengeClaim::from_json(&claim.to_json()?)?;
        verify_challenge_claim(&envelope, &claim, SOLUTION, &limits)?;
        assert!(matches!(
            create_challenge_claim(&envelope, &solver, b"wrong", &limits),
            Err(ChainError::AuthenticationFailed)
        ));

        let award = create_challenge_award(&envelope, &claim, &creator, &limits)?;
        let award = super::ChallengeAward::from_json(&award.to_json()?)?;
        verify_challenge_award(&envelope, &claim, &award, &limits)?;
        assert!(matches!(
            create_challenge_award(&envelope, &claim, &solver, &limits),
            Err(ChainError::NotRecipient)
        ));

        let mut mutated: serde_json::Value = serde_json::from_slice(&claim.to_json()?)?;
        mutated["solutionProof"] = serde_json::json!(crate::codec::encode_base64(&[0x41_u8; 32]));
        let mut mutated_bytes = serde_json::to_vec_pretty(&mutated)?;
        mutated_bytes.push(b'\n');
        assert!(super::ChallengeClaim::from_json(&mutated_bytes).is_err());
        Ok(())
    }
}
