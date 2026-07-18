#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_artifact_token::{decode_artifact, decode_artifact_token};
use rebyte_format::SecurityLimits;

fuzz_target!(|data: &[u8]| {
    let limits = SecurityLimits::SIMPLE_ARTIFACT;
    let _ = decode_artifact(data, &limits);
    if let Ok(token) = core::str::from_utf8(data) {
        let _ = decode_artifact_token(token, &limits);
    }
});
