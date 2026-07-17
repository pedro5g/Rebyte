#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_codec::{decode_capsule, encode_capsule};
use rebyte_format::SecurityLimits;

fuzz_target!(|data: &[u8]| {
    if let Ok(capsule) = decode_capsule(data, &SecurityLimits::V1) {
        assert_eq!(encode_capsule(&capsule).as_deref(), Ok(data));
    }
});
