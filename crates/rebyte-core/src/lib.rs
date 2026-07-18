//! Stable facade for Rebyte producers and consumers.

#![forbid(unsafe_code)]
#![doc = include_str!("../../../README.md")]

pub use rebyte_apply::{
    ApplyError, ApplyOptions, ApplyReport, TransactionState, TransactionSummary, apply_transaction,
    apply_verified_files, apply_verified_tree, list_transactions, resume_transaction,
    rollback_transaction,
};
pub use rebyte_artifact_token::{
    ARTIFACT_HEADER_SIZE, ARTIFACT_TOKEN_PREFIX, Artifact, ArtifactCompression, ArtifactDictionary,
    ArtifactEntry, ArtifactEntryKind, ArtifactIoError, ArtifactKind, ArtifactOptions,
    ArtifactPathMetadata, ArtifactTokenError, DecodedArtifact, EncodedArtifact,
    StreamArtifactReport, decode_artifact, decode_artifact_file, decode_artifact_file_expected,
    decode_artifact_token, encode_artifact, encode_artifact_binary_token, encode_artifact_path,
    encode_artifact_token,
};
pub use rebyte_chain::{
    AccessContract, AccessContractBuilder, CAPSULE_TOKEN_PREFIX as CHAIN_CAPSULE_TOKEN_PREFIX,
    Capabilities, Capability, CapsuleApproval, CapsuleEnvelope, CapsuleProposal, ChainError,
    ChainLimits, ContentCommitment, ContentKind, ContractError, ContractId,
    EncryptedIdentityDocument, GroupAcceptance, GroupCertificate, GroupId, GroupProposal,
    IdentityId, IdentityPublicDocument, OpenedCapsule, OpenedSemanticPatch, PrincipalId,
    QuorumRelease, ReleasePolicy, UnlockedIdentity, accept_group, approve_capsule,
    create_capsule_proposal, create_capsule_proposal_with_contract,
    create_content_proposal_with_contract, create_semantic_patch_proposal, finalize_capsule,
    finalize_group, generate_identity, open_capsule, open_semantic_patch,
};
pub use rebyte_diff::{
    ChangeKind, DiffEntry, DiffError, DiffReport, DiffSummary, DirectoryChangeKind,
    DirectoryDiffEntry, diff_capsule, diff_verified_directories, diff_verified_files,
};
pub use rebyte_file_token::{
    CompressionProfile, DecodedFileToken, EncodedFileToken, FILE_TOKEN_HEADER_SIZE,
    FILE_TOKEN_PREFIX, FileTokenCompression, FileTokenError, FileTokenOptions, decode_file_token,
    encode_file_token,
};
pub use rebyte_format::{PROTOCOL_VERSION, SecurityLimits};
pub use rebyte_pack::{ArtifactFile, PackError, PackOptions, UnsignedCapsule, pack};
pub use rebyte_semantic::{
    MAX_OPERATIONS as MAX_SEMANTIC_OPERATIONS, MAX_PATCH_BYTES, MAX_POINTER_BYTES,
    MAX_POINTER_DEPTH, PatchFormat, PatchOperation, SemanticError, SemanticPatch,
    SemanticPatchResult, apply_semantic_patch, parse_patch,
};
pub use rebyte_signature::{
    KeyStatus, Signer, TrustChannel, TrustedKeyring, TrustedPublicKey, VerificationPolicy,
    VerifiedPublisher,
};
pub use rebyte_verify::{
    CapsuleInput, FullyVerifiedCapsule, SignCapsuleError, SignedCapsule, VerificationError,
    VerifiedFile, sign_capsule, verify_capsule, verify_capsule_with_limits,
};
