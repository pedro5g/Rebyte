//! `rb1_` Base64URL token adapter.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rebyte_format::SecurityLimits;

use crate::CodecError;

const PREFIX: &str = "rb1_";

/// Encodes complete capsule bytes as an unpadded RAP v1 token.
#[must_use]
pub fn encode_token(capsule: &[u8]) -> String {
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(capsule))
}

/// Decodes a RAP v1 token after enforcing its textual limit and alphabet.
///
/// # Errors
///
/// Returns [`CodecError`] for an invalid prefix, internal whitespace, padding,
/// non-Base64URL characters, oversized input or invalid Base64URL data.
pub fn decode_token(token: &str, limits: &SecurityLimits) -> Result<Vec<u8>, CodecError> {
    let token_len = u64::try_from(token.len()).map_err(|_| CodecError::LengthOverflow)?;
    if token_len > limits.max_token_bytes {
        return Err(CodecError::InputTooLarge {
            max: limits.max_token_bytes,
            actual: token_len,
        });
    }
    let payload = token
        .strip_prefix(PREFIX)
        .ok_or(CodecError::InvalidTokenPrefix)?;
    if payload.is_empty()
        || payload
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(CodecError::InvalidTokenAlphabet);
    }
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CodecError::InvalidBase64)
}

#[cfg(test)]
mod tests {
    use super::{decode_token, encode_token};
    use crate::CodecError;
    use rebyte_format::SecurityLimits;

    #[test]
    fn token_round_trip() -> Result<(), CodecError> {
        let bytes = b"rap-v1";
        let token = encode_token(bytes);
        assert!(token.starts_with("rb1_"));
        assert!(!token.contains('='));
        assert_eq!(decode_token(&token, &SecurityLimits::V1)?, bytes);
        Ok(())
    }

    #[test]
    fn rejects_padding_and_whitespace() {
        assert_eq!(
            decode_token("rb1_YQ==", &SecurityLimits::V1),
            Err(CodecError::InvalidTokenAlphabet)
        );
        assert_eq!(
            decode_token("rb1_Y Q", &SecurityLimits::V1),
            Err(CodecError::InvalidTokenAlphabet)
        );
    }
}
