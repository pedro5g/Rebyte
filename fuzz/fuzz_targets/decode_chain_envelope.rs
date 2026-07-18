#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_chain::{CapsuleEnvelope, ChainLimits};

fuzz_target!(|data: &[u8]| {
    let limits = ChainLimits::STANDARD;
    if let Ok(envelope) = CapsuleEnvelope::from_bytes(data, &limits) {
        assert_eq!(envelope.to_bytes(&limits).as_deref(), Ok(data));
    }
    if let Ok(token) = core::str::from_utf8(data) {
        let _ = CapsuleEnvelope::from_token(token, &limits);
    }
});
