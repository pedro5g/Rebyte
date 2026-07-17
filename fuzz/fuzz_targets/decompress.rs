#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_compression::decompress;
use rebyte_format::{CompressionAlgorithm, SecurityLimits};

fuzz_target!(|data: &[u8]| {
    let declared = u64::try_from(data.len()).unwrap_or(u64::MAX).min(1_048_576);
    let _ = decompress(
        data,
        CompressionAlgorithm::Zstd,
        declared,
        &SecurityLimits::V1,
    );
});
