//! Offline encrypted and explicitly development-only Ed25519 signing adapters.
//!
//! This crate performs no network access and contains no embedded private key.
//! [`EncryptedPrivateKeyDocument`] supports offline local signing; high-value
//! production deployments should still implement [`Signer`] against a
//! separately reviewed KMS or HSM adapter.

#![forbid(unsafe_code)]

use core::convert::Infallible;
use std::env;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
pub use rebyte_signature::Signer;
use zeroize::Zeroizing;

mod key_file;

pub use key_file::{
    EncryptedPrivateKeyDocument, KeyDocumentError, LocalKeySigner, PublicKeyDocument,
    generate_encrypted_key,
};

const SECRET_BYTES: usize = 32;

/// Deterministic Ed25519 signer whose name makes development scope explicit.
///
/// The signing key is zeroized by `ed25519-dalek` on drop. Callers remain
/// responsible for clearing any seed copies they retain before construction.
pub struct DevelopmentSigner {
    key: SigningKey,
}

impl DevelopmentSigner {
    /// Constructs an explicitly insecure deterministic development signer.
    ///
    /// Never use a seed passed to this constructor as a production publisher
    /// key or commit that seed to source control.
    #[must_use]
    pub fn from_seed(seed: [u8; SECRET_BYTES]) -> Self {
        let seed = Zeroizing::new(seed);
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }
}

impl fmt::Debug for DevelopmentSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevelopmentSigner")
            .field("public_key", &self.public_key())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Signer for DevelopmentSigner {
    type Error = Infallible;

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok(ed25519_dalek::Signer::sign(&self.key, message).to_bytes())
    }
}

/// Loads development seed material from a process environment variable.
///
/// The value must be exactly 32 bytes encoded as Base64URL without padding.
/// The variable is read once; its copied process buffer is zeroized after
/// parsing. Operating-system environment storage itself cannot be cleared
/// portably by this adapter.
pub struct EnvironmentDevelopmentSigner;

impl EnvironmentDevelopmentSigner {
    /// Loads a development signer from `variable`.
    ///
    /// # Errors
    ///
    /// Returns [`SignerLoadError`] without including the variable name or
    /// secret when the value is absent, non-Unicode, non-canonical Base64URL or
    /// not exactly 32 decoded bytes.
    pub fn load(variable: &str) -> Result<DevelopmentSigner, SignerLoadError> {
        let value = env::var_os(variable).ok_or(SignerLoadError::MissingSecret)?;
        let value = value
            .into_string()
            .map_err(|_| SignerLoadError::NonUnicodeSecret)?;
        let value = Zeroizing::new(value);
        parse_environment_secret(&value)
    }
}

/// Development signer loading failure without secret-bearing context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignerLoadError {
    /// The requested environment value was absent.
    MissingSecret,
    /// The environment value was not valid Unicode.
    NonUnicodeSecret,
    /// The value used padding, whitespace or a non-Base64URL alphabet.
    InvalidEncoding,
    /// The decoded seed was not exactly 32 bytes.
    InvalidLength,
}

impl fmt::Display for SignerLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSecret => formatter.write_str("development signing secret is missing"),
            Self::NonUnicodeSecret => {
                formatter.write_str("development signing secret is not Unicode")
            }
            Self::InvalidEncoding => formatter
                .write_str("development signing secret must be unpadded canonical Base64URL"),
            Self::InvalidLength => {
                formatter.write_str("development signing secret must decode to 32 bytes")
            }
        }
    }
}

impl std::error::Error for SignerLoadError {}

fn parse_environment_secret(encoded: &str) -> Result<DevelopmentSigner, SignerLoadError> {
    if encoded.is_empty()
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(SignerLoadError::InvalidEncoding);
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| SignerLoadError::InvalidEncoding)?,
    );
    let seed: [u8; SECRET_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| SignerLoadError::InvalidLength)?;
    Ok(DevelopmentSigner::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rebyte_integrity::key_id;
    use zeroize::Zeroizing;

    use super::{DevelopmentSigner, Signer, SignerLoadError, parse_environment_secret};

    const TEST_ONLY_SEED: [u8; 32] = [0x24; 32];

    #[test]
    fn deterministic_development_signatures_are_stable() -> Result<(), Box<dyn std::error::Error>> {
        let first = DevelopmentSigner::from_seed(TEST_ONLY_SEED);
        let second = DevelopmentSigner::from_seed(TEST_ONLY_SEED);
        let message = b"test-only-domain-separated-message";
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first.sign(message)?, second.sign(message)?);
        assert_eq!(key_id(&first.public_key()), key_id(&second.public_key()));
        assert_ne!(first.public_key(), [0; 32]);
        Ok(())
    }

    #[test]
    fn canonical_environment_seed_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(TEST_ONLY_SEED));
        let signer = parse_environment_secret(&encoded)?;
        assert_eq!(
            signer.public_key(),
            DevelopmentSigner::from_seed(TEST_ONLY_SEED).public_key()
        );
        Ok(())
    }

    #[test]
    fn padded_or_wrong_length_secrets_are_rejected() {
        assert!(matches!(
            parse_environment_secret("YQ=="),
            Err(SignerLoadError::InvalidEncoding)
        ));
        assert!(matches!(
            parse_environment_secret("YQ"),
            Err(SignerLoadError::InvalidLength)
        ));
    }
}
