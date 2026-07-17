#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_codec::{decode_token, encode_token};
use rebyte_format::SecurityLimits;

fuzz_target!(|data: &str| {
    if let Ok(bytes) = decode_token(data, &SecurityLimits::V1) {
        assert_eq!(encode_token(&bytes), data);
    }
});
