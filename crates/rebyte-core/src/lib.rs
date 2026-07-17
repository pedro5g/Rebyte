//! Stable facade for Rebyte producers and consumers.

#![forbid(unsafe_code)]
#![doc = include_str!("../../../README.md")]

pub use rebyte_apply::{
    ApplyError, ApplyOptions, ApplyReport, TransactionState, TransactionSummary, apply_transaction,
    list_transactions, resume_transaction, rollback_transaction,
};
pub use rebyte_artifact_token::{
    ARTIFACT_HEADER_SIZE, ARTIFACT_TOKEN_PREFIX, Artifact, ArtifactCompression, ArtifactEntry,
    ArtifactEntryKind, ArtifactKind, ArtifactOptions, ArtifactTokenError, DecodedArtifact,
    EncodedArtifact, decode_artifact, decode_artifact_token, encode_artifact,
    encode_artifact_token,
};
pub use rebyte_diff::{ChangeKind, DiffEntry, DiffError, DiffReport, DiffSummary, diff_capsule};
pub use rebyte_file_token::{
    CompressionProfile, DecodedFileToken, EncodedFileToken, FILE_TOKEN_HEADER_SIZE,
    FILE_TOKEN_PREFIX, FileTokenCompression, FileTokenError, FileTokenOptions, decode_file_token,
    encode_file_token,
};
pub use rebyte_format::{PROTOCOL_VERSION, SecurityLimits};
pub use rebyte_pack::{ArtifactFile, PackError, PackOptions, UnsignedCapsule, pack};
pub use rebyte_signature::{
    KeyStatus, Signer, TrustChannel, TrustedKeyring, TrustedPublicKey, VerificationPolicy,
    VerifiedPublisher,
};
pub use rebyte_verify::{
    CapsuleInput, FullyVerifiedCapsule, SignCapsuleError, SignedCapsule, VerificationError,
    VerifiedFile, sign_capsule, verify_capsule, verify_capsule_with_limits,
};
