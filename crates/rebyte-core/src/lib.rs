//! Stable facade for Rebyte producers and consumers.

#![forbid(unsafe_code)]

pub use rebyte_diff::{ChangeKind, DiffEntry, DiffError, DiffReport, DiffSummary, diff_capsule};
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
