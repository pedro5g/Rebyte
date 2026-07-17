// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

/// Identity, consensus, encoding or confidentiality failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChainError {
    /// Operating-system cryptographic randomness was unavailable.
    EntropyUnavailable,
    /// A passphrase was outside the supported bounds.
    InvalidPassphrase,
    /// A JSON control document was malformed or non-canonical.
    InvalidDocument,
    /// A document kind, protocol version or cryptographic suite is unsupported.
    UnsupportedDocument,
    /// A bounded field, group, recipient list or payload exceeded its limit.
    LimitExceeded,
    /// A checked length conversion or addition overflowed.
    LengthOverflow,
    /// Identity display metadata is invalid.
    InvalidName,
    /// Base64URL data was malformed or non-canonical.
    InvalidEncoding,
    /// Public key bytes or their derived identity were invalid.
    InvalidPublicKey,
    /// An encrypted identity could not be derived from its passphrase.
    KeyDerivation,
    /// Identity encryption failed.
    EncryptionFailed,
    /// The passphrase was wrong or protected identity bytes were modified.
    AuthenticationFailed,
    /// Public identity and protected private material do not correspond.
    IdentityMismatch,
    /// A member or recipient occurred more than once.
    DuplicateIdentity,
    /// Members or approvals were not in canonical identity order.
    NonCanonicalOrder,
    /// A threshold was zero or larger than the group.
    InvalidThreshold,
    /// A signing identity is not a member of the selected group.
    NotGroupMember,
    /// Group formation did not contain every required member acceptance.
    IncompleteGroup,
    /// Capsule finalization did not contain enough valid member approvals.
    InsufficientApprovals,
    /// An acceptance or capsule approval signature was invalid.
    InvalidSignature,
    /// An object was bound to another group, member or capsule proposal.
    BindingMismatch,
    /// Binary data ended before a complete field was available.
    UnexpectedEof,
    /// Binary data contained an unknown flag, algorithm or trailing byte.
    NonCanonicalEnvelope,
    /// The embedded unsigned artifact was malformed.
    InvalidArtifact,
    /// HPKE key encapsulation or authenticated encryption failed.
    CryptographicFailure,
    /// The supplied identity is not an authorized capsule recipient.
    NotRecipient,
    /// Decrypted artifact length or digest did not match the signed proposal.
    IntegrityMismatch,
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "operating-system entropy is unavailable",
            Self::InvalidPassphrase => "passphrase must contain 12 to 1024 bytes",
            Self::InvalidDocument => "invalid or non-canonical Chain document",
            Self::UnsupportedDocument => "unsupported Chain document version or algorithm",
            Self::LimitExceeded => "Chain object exceeds its configured limit",
            Self::LengthOverflow => "Chain object length overflow",
            Self::InvalidName => "invalid Chain display name",
            Self::InvalidEncoding => "invalid canonical Base64URL field",
            Self::InvalidPublicKey => "invalid Chain public key",
            Self::KeyDerivation => "Chain identity key derivation failed",
            Self::EncryptionFailed => "Chain identity encryption failed",
            Self::AuthenticationFailed => "wrong passphrase or modified Chain identity",
            Self::IdentityMismatch => "Chain public and private identity material do not match",
            Self::DuplicateIdentity => "duplicate Chain identity",
            Self::NonCanonicalOrder => "Chain identities are not in canonical order",
            Self::InvalidThreshold => "invalid Chain consensus threshold",
            Self::NotGroupMember => "identity is not a member of this Chain group",
            Self::IncompleteGroup => "Chain group is missing a member acceptance",
            Self::InsufficientApprovals => "Chain capsule has insufficient member approvals",
            Self::InvalidSignature => "invalid Chain signature",
            Self::BindingMismatch => "Chain object binding mismatch",
            Self::UnexpectedEof => "truncated Chain envelope",
            Self::NonCanonicalEnvelope => "non-canonical Chain envelope",
            Self::InvalidArtifact => "invalid embedded Rebyte artifact",
            Self::CryptographicFailure => "Chain cryptographic operation failed",
            Self::NotRecipient => "identity is not an authorized capsule recipient",
            Self::IntegrityMismatch => "decrypted Chain artifact failed integrity verification",
        })
    }
}

impl core::error::Error for ChainError {}
