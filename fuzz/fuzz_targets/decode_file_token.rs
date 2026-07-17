#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_file_token::decode_file_token;
use rebyte_format::SecurityLimits;

fuzz_target!(|data: &str| {
    let _ = decode_file_token(data, &SecurityLimits::V1);
});
