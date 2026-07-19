// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical authorization contracts for protected Rebyte content.
//!
//! Contracts keep content, authorization and release enforcement independent.
//! A direct-recipient contract can grant capabilities immediately to listed
//! encryption identities. Time and usage restrictions are accepted only with
//! quorum release, because a standalone offline decoder cannot securely enforce
//! them against clock rollback or restoration of local state.

#![forbid(unsafe_code)]

use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const MAGIC: &[u8; 4] = b"RBAC";
const VERSION: u16 = 1;
const TOKEN_PREFIX: &str = "rc1_";
const MAX_PRINCIPALS: usize = 64;
const MAX_CONTRACT_BYTES: usize = 16 * 1_024;
const MIN_CHALLENGE_MEMORY_KIB: u32 = 8 * 1_024;
const MAX_CHALLENGE_MEMORY_KIB: u32 = 1_024 * 1_024;
const MAX_CHALLENGE_ITERATIONS: u32 = 16;
const MAX_CHALLENGE_HINT_BYTES: usize = 1_024;
const MAX_TOKEN_BYTES: usize = 22 * 1_024;
const CONTRACT_ID_CONTEXT: &str = "Rebyte access contract id v1 2026-07-18";

/// Stable 32-byte identifier for an identity, group or external authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalId([u8; 32]);

impl PrincipalId {
    /// Creates an identifier from exact protocol bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns canonical unpadded Base64URL.
    #[must_use]
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// Stable identifier of one exact contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContractId([u8; 32]);

impl ContractId {
    /// Returns the exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns canonical unpadded Base64URL.
    #[must_use]
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// Kind of content governed by a contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContentKind {
    /// Canonical byte-exact `.rba` file or directory artifact.
    ExactArtifact,
    /// Canonical structured semantic patch.
    SemanticPatch,
}

impl ContentKind {
    const fn wire(self) -> u8 {
        match self {
            Self::ExactArtifact => 1,
            Self::SemanticPatch => 2,
        }
    }

    const fn from_wire(value: u8) -> Result<Self, ContractError> {
        match value {
            1 => Ok(Self::ExactArtifact),
            2 => Ok(Self::SemanticPatch),
            _ => Err(ContractError::UnsupportedValue),
        }
    }
}

/// Commitment to the exact protected plaintext object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentCommitment {
    kind: ContentKind,
    digest: [u8; 32],
    size: u64,
}

impl ContentCommitment {
    /// Creates a commitment from an externally verified digest and size.
    #[must_use]
    pub const fn new(kind: ContentKind, digest: [u8; 32], size: u64) -> Self {
        Self { kind, digest, size }
    }

    /// Returns the governed content type.
    #[must_use]
    pub const fn kind(&self) -> ContentKind {
        self.kind
    }

    /// Returns the exact content digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the exact plaintext byte length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// One operation that a contract may grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Capability {
    /// View public, non-secret envelope metadata.
    InspectMetadata,
    /// Recover protected plaintext in memory.
    Decrypt,
    /// Reconstruct a new file or directory.
    Reconstruct,
    /// Compare plaintext with a selected destination.
    Diff,
    /// Apply exact artifact bytes through a transaction.
    Apply,
    /// Apply a bounded semantic patch.
    ApplySemanticPatch,
}

impl Capability {
    const fn bit(self) -> u16 {
        match self {
            Self::InspectMetadata => 1 << 0,
            Self::Decrypt => 1 << 1,
            Self::Reconstruct => 1 << 2,
            Self::Diff => 1 << 3,
            Self::Apply => 1 << 4,
            Self::ApplySemanticPatch => 1 << 5,
        }
    }
}

/// Canonical set of capabilities granted by a contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities(u16);

impl Capabilities {
    const KNOWN_MASK: u16 = (1 << 6) - 1;

    /// Read-only reconstruction capabilities.
    pub const RECONSTRUCT: Self = Self(
        Capability::InspectMetadata.bit()
            | Capability::Decrypt.bit()
            | Capability::Reconstruct.bit(),
    );

    /// Exact artifact inspection, diff and transactional application.
    pub const APPLY_EXACT: Self =
        Self(Self::RECONSTRUCT.0 | Capability::Diff.bit() | Capability::Apply.bit());

    /// Semantic-patch decryption, review and application.
    pub const APPLY_PATCH: Self = Self(
        Capability::InspectMetadata.bit()
            | Capability::Decrypt.bit()
            | Capability::Diff.bit()
            | Capability::ApplySemanticPatch.bit(),
    );

    /// Creates a set from explicit capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidCapabilities`] for an empty set.
    pub fn new(values: &[Capability]) -> Result<Self, ContractError> {
        let bits = values.iter().fold(0_u16, |set, value| set | value.bit());
        Self::from_bits(bits)
    }

    /// Returns whether this set grants one capability.
    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Returns the canonical bit representation.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    const fn from_bits(bits: u16) -> Result<Self, ContractError> {
        if bits == 0 || bits & !Self::KNOWN_MASK != 0 {
            Err(ContractError::InvalidCapabilities)
        } else {
            Ok(Self(bits))
        }
    }
}

/// Threshold release conditions enforced by independent witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumRelease {
    witnesses: Vec<PrincipalId>,
    threshold: u16,
    not_before_unix_ms: Option<u64>,
    maximum_successful_releases: Option<u32>,
}

impl QuorumRelease {
    /// Creates a canonical quorum release policy.
    ///
    /// A restriction is meaningful only when a threshold of witnesses
    /// withholds key shares until it decides the condition is satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid, duplicate or oversized witness
    /// sets and invalid thresholds or usage limits.
    pub fn new(
        witnesses: Vec<PrincipalId>,
        threshold: u16,
        not_before_unix_ms: Option<u64>,
        maximum_successful_releases: Option<u32>,
    ) -> Result<Self, ContractError> {
        let witnesses = canonical_principals(witnesses)?;
        let policy = Self {
            witnesses,
            threshold,
            not_before_unix_ms,
            maximum_successful_releases,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Returns canonically ordered release witnesses.
    #[must_use]
    pub fn witnesses(&self) -> &[PrincipalId] {
        &self.witnesses
    }

    /// Returns the number of witness shares required.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Returns the earliest trusted time at which witnesses may release.
    #[must_use]
    pub const fn not_before_unix_ms(&self) -> Option<u64> {
        self.not_before_unix_ms
    }

    /// Returns the maximum successful quorum-authorized key releases.
    ///
    /// This cannot revoke plaintext or key material retained after a release.
    #[must_use]
    pub const fn maximum_successful_releases(&self) -> Option<u32> {
        self.maximum_successful_releases
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_canonical_principals(&self.witnesses)?;
        let count =
            u16::try_from(self.witnesses.len()).map_err(|_| ContractError::LengthOverflow)?;
        if self.threshold == 0 || self.threshold > count {
            return Err(ContractError::InvalidThreshold);
        }
        if self.maximum_successful_releases == Some(0) {
            return Err(ContractError::InvalidUsageLimit);
        }
        // A global usage limit without a consensus ledger is safe only when
        // every witness participates. Otherwise two intersecting quorums can
        // authorize different concurrent requests through a dishonest overlap.
        if self.maximum_successful_releases.is_some() && self.threshold != count {
            return Err(ContractError::InvalidUsageThreshold);
        }
        Ok(())
    }
}

/// Computational-challenge release parameters.
///
/// The content key is additionally wrapped under a memory-hard derivation of
/// a creator-chosen secret solution. Listed recipients keep ordinary direct
/// slots as the audited opening path. A challenge is a cost gate, not access
/// control: anyone holding the envelope may search for the solution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeRelease {
    kdf_memory_kib: u32,
    kdf_iterations: u32,
    solution_commitment: [u8; 32],
    challenge_salt: [u8; 16],
    hint: String,
}

impl ChallengeRelease {
    /// Creates a canonical challenge release policy.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for per-guess costs outside
    /// 8 `MiB`–1 `GiB` / 1–16 passes or an oversized or non-printable hint.
    pub fn new(
        kdf_memory_kib: u32,
        kdf_iterations: u32,
        solution_commitment: [u8; 32],
        challenge_salt: [u8; 16],
        hint: String,
    ) -> Result<Self, ContractError> {
        let policy = Self {
            kdf_memory_kib,
            kdf_iterations,
            solution_commitment,
            challenge_salt,
            hint,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Returns the Argon2id memory cost of one solution guess in `KiB`.
    #[must_use]
    pub const fn kdf_memory_kib(&self) -> u32 {
        self.kdf_memory_kib
    }

    /// Returns the Argon2id pass count of one solution guess.
    #[must_use]
    pub const fn kdf_iterations(&self) -> u32 {
        self.kdf_iterations
    }

    /// Returns the commitment to the derived solution key.
    #[must_use]
    pub const fn solution_commitment(&self) -> &[u8; 32] {
        &self.solution_commitment
    }

    /// Returns the per-capsule derivation salt.
    #[must_use]
    pub const fn challenge_salt(&self) -> &[u8; 16] {
        &self.challenge_salt
    }

    /// Returns the creator-supplied pointer to the parameter space.
    #[must_use]
    pub fn hint(&self) -> &str {
        &self.hint
    }

    fn validate(&self) -> Result<(), ContractError> {
        if !(MIN_CHALLENGE_MEMORY_KIB..=MAX_CHALLENGE_MEMORY_KIB).contains(&self.kdf_memory_kib)
            || !(1..=MAX_CHALLENGE_ITERATIONS).contains(&self.kdf_iterations)
        {
            return Err(ContractError::UnsupportedValue);
        }
        if self.hint.len() > MAX_CHALLENGE_HINT_BYTES
            || self
                .hint
                .chars()
                .any(|character| character.is_control() || character == '\u{7f}')
        {
            return Err(ContractError::LimitExceeded);
        }
        Ok(())
    }
}

/// Cryptographic mechanism controlling release of the content key.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReleasePolicy {
    /// Every listed recipient receives a direct encrypted content-key slot.
    DirectRecipients,
    /// A threshold of witnesses must release independently held key shares.
    Quorum(QuorumRelease),
    /// The content key is also released by solving a computational challenge.
    Challenge(ChallengeRelease),
}

/// Builder for an immutable access contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessContractBuilder {
    group_id: PrincipalId,
    controllers: Vec<PrincipalId>,
    seal_threshold: u16,
    recipients: Vec<PrincipalId>,
    capabilities: Capabilities,
    content: ContentCommitment,
    release: ReleasePolicy,
}

impl AccessContractBuilder {
    /// Starts a direct-recipient exact-artifact contract.
    #[must_use]
    pub const fn new(group_id: PrincipalId, content: ContentCommitment) -> Self {
        Self {
            group_id,
            controllers: Vec::new(),
            seal_threshold: 0,
            recipients: Vec::new(),
            capabilities: Capabilities::RECONSTRUCT,
            content,
            release: ReleasePolicy::DirectRecipients,
        }
    }

    /// Sets the identities that authorize envelope sealing.
    #[must_use]
    pub fn controllers(mut self, controllers: Vec<PrincipalId>, threshold: u16) -> Self {
        self.controllers = controllers;
        self.seal_threshold = threshold;
        self
    }

    /// Sets identities that may receive the protected content.
    #[must_use]
    pub fn recipients(mut self, recipients: Vec<PrincipalId>) -> Self {
        self.recipients = recipients;
        self
    }

    /// Sets operations granted after successful release.
    #[must_use]
    pub const fn capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Sets the cryptographic content-key release mechanism.
    #[must_use]
    pub fn release(mut self, release: ReleasePolicy) -> Self {
        self.release = release;
        self
    }

    /// Validates this definition and creates a contract with fresh entropy.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unavailable entropy or invalid policy.
    pub fn build(self) -> Result<AccessContract, ContractError> {
        AccessContract::new(self)
    }
}

/// Immutable canonical contract governing protected content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessContract {
    contract_nonce: [u8; 32],
    group_id: PrincipalId,
    controllers: Vec<PrincipalId>,
    seal_threshold: u16,
    recipients: Vec<PrincipalId>,
    capabilities: Capabilities,
    content: ContentCommitment,
    release: ReleasePolicy,
    contract_id: ContractId,
}

impl AccessContract {
    /// Creates a contract with a fresh random nonce.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unavailable entropy or invalid policy.
    pub fn new(builder: AccessContractBuilder) -> Result<Self, ContractError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ContractError::EntropyUnavailable)?;
        Self::with_nonce(nonce, builder)
    }

    /// Starts a builder for an exact content commitment and group.
    #[must_use]
    pub const fn builder(
        group_id: PrincipalId,
        content: ContentCommitment,
    ) -> AccessContractBuilder {
        AccessContractBuilder::new(group_id, content)
    }

    /// Decodes and validates canonical contract bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for malformed, unsupported, non-canonical or
    /// cryptographically inconsistent input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_CONTRACT_BYTES {
            return Err(ContractError::LimitExceeded);
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != *MAGIC || reader.u16()? != VERSION {
            return Err(ContractError::UnsupportedValue);
        }
        let contract_nonce = reader.array()?;
        let group_id = PrincipalId(reader.array()?);
        let controllers = read_principals(&mut reader)?;
        let seal_threshold = reader.u16()?;
        let recipients = read_principals(&mut reader)?;
        let capabilities = Capabilities::from_bits(reader.u16()?)?;
        let content = ContentCommitment {
            kind: ContentKind::from_wire(reader.u8()?)?,
            digest: reader.array()?,
            size: reader.u64()?,
        };
        let release = match reader.u8()? {
            1 => ReleasePolicy::DirectRecipients,
            2 => {
                let witnesses = read_principals(&mut reader)?;
                let threshold = reader.u16()?;
                let not_before_unix_ms = read_optional_u64(&mut reader)?;
                let maximum_successful_releases = read_optional_u32(&mut reader)?;
                ReleasePolicy::Quorum(QuorumRelease {
                    witnesses,
                    threshold,
                    not_before_unix_ms,
                    maximum_successful_releases,
                })
            }
            3 => {
                let kdf_memory_kib = reader.u32()?;
                let kdf_iterations = reader.u32()?;
                let solution_commitment = reader.array()?;
                let challenge_salt = reader.array()?;
                let hint_length = usize::from(reader.u16()?);
                if hint_length > MAX_CHALLENGE_HINT_BYTES {
                    return Err(ContractError::LimitExceeded);
                }
                let hint = core::str::from_utf8(reader.take(hint_length)?)
                    .map_err(|_| ContractError::InvalidEncoding)?
                    .to_string();
                ReleasePolicy::Challenge(ChallengeRelease {
                    kdf_memory_kib,
                    kdf_iterations,
                    solution_commitment,
                    challenge_salt,
                    hint,
                })
            }
            _ => return Err(ContractError::UnsupportedValue),
        };
        let contract_id = ContractId(reader.array()?);
        reader.finish()?;
        let contract = Self {
            contract_nonce,
            group_id,
            controllers,
            seal_threshold,
            recipients,
            capabilities,
            content,
            release,
            contract_id,
        };
        contract.validate()?;
        if contract.to_bytes()?.as_slice() != bytes {
            return Err(ContractError::NonCanonical);
        }
        Ok(contract)
    }

    /// Decodes a canonical `rc1_` contract token.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid prefix, Base64URL encoding or
    /// contract body.
    pub fn from_token(token: &str) -> Result<Self, ContractError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(ContractError::LimitExceeded);
        }
        let encoded = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(ContractError::InvalidEncoding)?;
        if encoded.is_empty()
            || encoded
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
        {
            return Err(ContractError::InvalidEncoding);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| ContractError::InvalidEncoding)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(ContractError::InvalidEncoding);
        }
        Self::from_bytes(&bytes)
    }

    /// Encodes canonical contract bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if the in-memory contract is invalid.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        put_u16(&mut output, VERSION);
        output.extend_from_slice(&self.contract_nonce);
        output.extend_from_slice(self.group_id.as_bytes());
        put_principals(&mut output, &self.controllers)?;
        put_u16(&mut output, self.seal_threshold);
        put_principals(&mut output, &self.recipients)?;
        put_u16(&mut output, self.capabilities.bits());
        output.push(self.content.kind.wire());
        output.extend_from_slice(&self.content.digest);
        put_u64(&mut output, self.content.size);
        put_release(&mut output, &self.release)?;
        output.extend_from_slice(self.contract_id.as_bytes());
        if output.len() > MAX_CONTRACT_BYTES {
            return Err(ContractError::LimitExceeded);
        }
        Ok(output)
    }

    /// Encodes a canonical text token.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if contract validation fails.
    pub fn to_token(&self) -> Result<String, ContractError> {
        Ok(format!(
            "{TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.to_bytes()?)
        ))
    }

    /// Returns the stable identifier of this exact contract.
    #[must_use]
    pub const fn contract_id(&self) -> ContractId {
        self.contract_id
    }

    /// Returns the authorizing group identifier.
    #[must_use]
    pub const fn group_id(&self) -> PrincipalId {
        self.group_id
    }

    /// Returns canonically ordered controllers.
    #[must_use]
    pub fn controllers(&self) -> &[PrincipalId] {
        &self.controllers
    }

    /// Returns the proposal-sealing threshold.
    #[must_use]
    pub const fn seal_threshold(&self) -> u16 {
        self.seal_threshold
    }

    /// Returns canonically ordered recipients.
    #[must_use]
    pub fn recipients(&self) -> &[PrincipalId] {
        &self.recipients
    }

    /// Returns the granted capability set.
    #[must_use]
    pub const fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Returns the protected content commitment.
    #[must_use]
    pub const fn content(&self) -> ContentCommitment {
        self.content
    }

    /// Returns the content-key release mechanism.
    #[must_use]
    pub const fn release(&self) -> &ReleasePolicy {
        &self.release
    }

    fn with_nonce(
        contract_nonce: [u8; 32],
        builder: AccessContractBuilder,
    ) -> Result<Self, ContractError> {
        let controllers = canonical_principals(builder.controllers)?;
        let recipients = canonical_principals(builder.recipients)?;
        let mut contract = Self {
            contract_nonce,
            group_id: builder.group_id,
            controllers,
            seal_threshold: builder.seal_threshold,
            recipients,
            capabilities: builder.capabilities,
            content: builder.content,
            release: builder.release,
            contract_id: ContractId([0; 32]),
        };
        contract.validate_shape()?;
        contract.contract_id = ContractId(calculate_contract_id(&contract)?);
        contract.validate()?;
        Ok(contract)
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_canonical_principals(&self.controllers)?;
        validate_canonical_principals(&self.recipients)?;
        let controller_count =
            u16::try_from(self.controllers.len()).map_err(|_| ContractError::LengthOverflow)?;
        if self.seal_threshold == 0 || self.seal_threshold > controller_count {
            return Err(ContractError::InvalidThreshold);
        }
        Capabilities::from_bits(self.capabilities.bits())?;
        match (&self.content.kind, &self.release) {
            (ContentKind::ExactArtifact, _)
                if !self.capabilities.contains(Capability::Decrypt)
                    || (!self.capabilities.contains(Capability::Reconstruct)
                        && !self.capabilities.contains(Capability::Diff)
                        && !self.capabilities.contains(Capability::Apply)) =>
            {
                return Err(ContractError::InvalidCapabilities);
            }
            (ContentKind::SemanticPatch, _)
                if !self.capabilities.contains(Capability::Decrypt)
                    || !self.capabilities.contains(Capability::ApplySemanticPatch) =>
            {
                return Err(ContractError::InvalidCapabilities);
            }
            _ => {}
        }
        match &self.release {
            ReleasePolicy::Quorum(policy) => policy.validate()?,
            ReleasePolicy::Challenge(policy) => policy.validate()?,
            ReleasePolicy::DirectRecipients => {}
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        if calculate_contract_id(self)? != self.contract_id.0 {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

/// Contract parsing, policy or integrity failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContractError {
    /// Cryptographic operating-system entropy was unavailable.
    EntropyUnavailable,
    /// A field or total contract exceeded its bound.
    LimitExceeded,
    /// A checked length conversion or addition overflowed.
    LengthOverflow,
    /// A participant appeared more than once.
    DuplicatePrincipal,
    /// Participants were not in canonical byte order.
    NonCanonicalOrder,
    /// A threshold was zero or exceeded its participant set.
    InvalidThreshold,
    /// A usage limit was zero.
    InvalidUsageLimit,
    /// A usage-limited release did not require every witness.
    InvalidUsageThreshold,
    /// Capabilities were empty, unknown or incompatible with content.
    InvalidCapabilities,
    /// A version, content kind or release mode was unsupported.
    UnsupportedValue,
    /// Input ended before a complete contract was available.
    UnexpectedEof,
    /// Input contained trailing bytes or a non-canonical representation.
    NonCanonical,
    /// The contract identifier did not match its canonical body.
    BindingMismatch,
    /// A text token was malformed or non-canonical.
    InvalidEncoding,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "operating-system entropy is unavailable",
            Self::LimitExceeded => "access contract exceeds its configured limit",
            Self::LengthOverflow => "access contract length overflow",
            Self::DuplicatePrincipal => "duplicate access-contract principal",
            Self::NonCanonicalOrder => "access-contract principals are not canonically ordered",
            Self::InvalidThreshold => "invalid access-contract threshold",
            Self::InvalidUsageLimit => "invalid access-contract usage limit",
            Self::InvalidUsageThreshold => "usage-limited release requires unanimous witnesses",
            Self::InvalidCapabilities => "invalid access-contract capabilities",
            Self::UnsupportedValue => "unsupported access-contract version or value",
            Self::UnexpectedEof => "truncated access contract",
            Self::NonCanonical => "non-canonical access contract",
            Self::BindingMismatch => "access-contract binding mismatch",
            Self::InvalidEncoding => "invalid access-contract token encoding",
        })
    }
}

impl core::error::Error for ContractError {}

fn canonical_principals(
    mut principals: Vec<PrincipalId>,
) -> Result<Vec<PrincipalId>, ContractError> {
    principals.sort_unstable();
    validate_canonical_principals(&principals)?;
    Ok(principals)
}

fn validate_canonical_principals(principals: &[PrincipalId]) -> Result<(), ContractError> {
    if principals.is_empty() || principals.len() > MAX_PRINCIPALS {
        return Err(ContractError::LimitExceeded);
    }
    for pair in principals.windows(2) {
        let Some(left) = pair.first() else {
            return Err(ContractError::NonCanonicalOrder);
        };
        let Some(right) = pair.get(1) else {
            return Err(ContractError::NonCanonicalOrder);
        };
        if left >= right {
            return Err(if left == right {
                ContractError::DuplicatePrincipal
            } else {
                ContractError::NonCanonicalOrder
            });
        }
    }
    Ok(())
}

fn calculate_contract_id(contract: &AccessContract) -> Result<[u8; 32], ContractError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    put_u16(&mut bytes, VERSION);
    bytes.extend_from_slice(&contract.contract_nonce);
    bytes.extend_from_slice(contract.group_id.as_bytes());
    put_principals(&mut bytes, &contract.controllers)?;
    put_u16(&mut bytes, contract.seal_threshold);
    put_principals(&mut bytes, &contract.recipients)?;
    put_u16(&mut bytes, contract.capabilities.bits());
    bytes.push(contract.content.kind.wire());
    bytes.extend_from_slice(&contract.content.digest);
    put_u64(&mut bytes, contract.content.size);
    put_release(&mut bytes, &contract.release)?;
    let mut hasher = blake3::Hasher::new_derive_key(CONTRACT_ID_CONTEXT);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn put_release(output: &mut Vec<u8>, release: &ReleasePolicy) -> Result<(), ContractError> {
    match release {
        ReleasePolicy::DirectRecipients => output.push(1),
        ReleasePolicy::Quorum(policy) => {
            output.push(2);
            put_principals(output, &policy.witnesses)?;
            put_u16(output, policy.threshold);
            put_optional_u64(output, policy.not_before_unix_ms);
            put_optional_u32(output, policy.maximum_successful_releases);
        }
        ReleasePolicy::Challenge(policy) => {
            output.push(3);
            put_u32(output, policy.kdf_memory_kib);
            put_u32(output, policy.kdf_iterations);
            output.extend_from_slice(&policy.solution_commitment);
            output.extend_from_slice(&policy.challenge_salt);
            put_u16(
                output,
                u16::try_from(policy.hint.len()).map_err(|_| ContractError::LengthOverflow)?,
            );
            output.extend_from_slice(policy.hint.as_bytes());
        }
    }
    Ok(())
}

fn put_principals(output: &mut Vec<u8>, principals: &[PrincipalId]) -> Result<(), ContractError> {
    put_u16(
        output,
        u16::try_from(principals.len()).map_err(|_| ContractError::LengthOverflow)?,
    );
    for principal in principals {
        output.extend_from_slice(principal.as_bytes());
    }
    Ok(())
}

fn read_principals(reader: &mut Reader<'_>) -> Result<Vec<PrincipalId>, ContractError> {
    let count = usize::from(reader.u16()?);
    if count == 0 || count > MAX_PRINCIPALS {
        return Err(ContractError::LimitExceeded);
    }
    let mut principals = Vec::with_capacity(count);
    for _ in 0..count {
        principals.push(PrincipalId(reader.array()?));
    }
    Ok(principals)
}

fn put_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            put_u64(output, value);
        }
        None => output.push(0),
    }
}

fn put_optional_u32(output: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn read_optional_u64(reader: &mut Reader<'_>) -> Result<Option<u64>, ContractError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u64()?)),
        _ => Err(ContractError::UnsupportedValue),
    }
}

fn read_optional_u32(reader: &mut Reader<'_>) -> Result<Option<u32>, ContractError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u32()?)),
        _ => Err(ContractError::UnsupportedValue),
    }
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, ContractError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(ContractError::UnexpectedEof)
    }

    fn u16(&mut self) -> Result<u16, ContractError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ContractError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ContractError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ContractError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ContractError::UnexpectedEof)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ContractError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ContractError::LengthOverflow)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(ContractError::UnexpectedEof)?;
        self.offset = end;
        Ok(bytes)
    }

    const fn finish(&self) -> Result<(), ContractError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ContractError::NonCanonical)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccessContract, AccessContractBuilder, Capabilities, ContentCommitment, ContentKind,
        ContractError, PrincipalId, QuorumRelease, ReleasePolicy,
    };

    fn principal(marker: u8) -> PrincipalId {
        PrincipalId::from_bytes([marker; 32])
    }

    fn direct_contract() -> Result<AccessContract, ContractError> {
        AccessContract::with_nonce(
            [0x11; 32],
            AccessContractBuilder::new(
                principal(9),
                ContentCommitment::new(ContentKind::ExactArtifact, [0x22; 32], 42),
            )
            .controllers(vec![principal(2), principal(1)], 2)
            .recipients(vec![principal(4), principal(3)])
            .capabilities(Capabilities::APPLY_EXACT)
            .release(ReleasePolicy::DirectRecipients),
        )
    }

    #[test]
    fn direct_contract_round_trips_canonically() -> Result<(), Box<dyn std::error::Error>> {
        let contract = direct_contract()?;
        let bytes = contract.to_bytes()?;
        let decoded = AccessContract::from_bytes(&bytes)?;
        assert_eq!(decoded, contract);
        assert_eq!(AccessContract::from_token(&contract.to_token()?)?, contract);
        assert_eq!(contract.controllers(), &[principal(1), principal(2)]);
        assert_eq!(contract.recipients(), &[principal(3), principal(4)]);
        Ok(())
    }

    #[test]
    fn quorum_contract_preserves_time_and_usage_conditions()
    -> Result<(), Box<dyn std::error::Error>> {
        let quorum = QuorumRelease::new(
            vec![principal(3), principal(1), principal(2)],
            3,
            Some(1_800_000_000_000),
            Some(1),
        )?;
        let contract = AccessContract::with_nonce(
            [0x33; 32],
            AccessContractBuilder::new(
                principal(8),
                ContentCommitment::new(ContentKind::ExactArtifact, [0x44; 32], 100),
            )
            .controllers(vec![principal(1), principal(2), principal(3)], 2)
            .recipients(vec![principal(7)])
            .capabilities(Capabilities::RECONSTRUCT)
            .release(ReleasePolicy::Quorum(quorum)),
        )?;
        assert_eq!(AccessContract::from_bytes(&contract.to_bytes()?)?, contract);
        assert!(matches!(
            QuorumRelease::new(
                vec![principal(1), principal(2), principal(3)],
                2,
                None,
                Some(1)
            ),
            Err(ContractError::InvalidUsageThreshold)
        ));
        Ok(())
    }

    #[test]
    fn rejects_duplicates_unknown_bits_mutation_and_trailing_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            AccessContract::with_nonce(
                [0; 32],
                AccessContractBuilder::new(
                    principal(1),
                    ContentCommitment::new(ContentKind::ExactArtifact, [0; 32], 0),
                )
                .controllers(vec![principal(2), principal(2)], 1)
                .recipients(vec![principal(3)])
                .capabilities(Capabilities::RECONSTRUCT)
                .release(ReleasePolicy::DirectRecipients),
            ),
            Err(ContractError::DuplicatePrincipal)
        ));
        assert!(matches!(
            Capabilities::from_bits(1 << 15),
            Err(ContractError::InvalidCapabilities)
        ));
        let bytes = direct_contract()?.to_bytes()?;
        let mut mutated = bytes.clone();
        if let Some(byte) = mutated.get_mut(20) {
            *byte ^= 0x80;
        }
        assert!(AccessContract::from_bytes(&mutated).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(AccessContract::from_bytes(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn rejects_every_truncated_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = direct_contract()?.to_bytes()?;
        for length in 0..bytes.len() {
            assert!(AccessContract::from_bytes(&bytes[..length]).is_err());
        }
        Ok(())
    }
}
