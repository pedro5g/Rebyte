//! Canonical codec properties over adversarial byte and token inputs.

#![forbid(unsafe_code)]

use proptest::prelude::*;
use rebyte_codec::{decode_capsule, decode_token, encode_capsule, encode_token};
use rebyte_format::SecurityLimits;

proptest! {
    #[test]
    fn any_decodable_capsule_has_one_canonical_encoding(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(decoded) = decode_capsule(&bytes, &SecurityLimits::V1) {
            prop_assert_eq!(encode_capsule(&decoded), Ok(bytes));
        }
    }

    #[test]
    fn arbitrary_text_never_bypasses_token_canonicalization(value in ".{0,4096}") {
        if let Ok(bytes) = decode_token(&value, &SecurityLimits::V1) {
            prop_assert_eq!(encode_token(&bytes), value);
        }
    }

    #[test]
    fn token_round_trip_is_exact(bytes in prop::collection::vec(any::<u8>(), 1..4096)) {
        let token = encode_token(&bytes);
        prop_assert_eq!(decode_token(&token, &SecurityLimits::V1), Ok(bytes));
    }
}
