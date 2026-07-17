//! Defensive resource limits used before parsing or allocation.

/// Defensive bounds for untrusted capsule data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityLimits {
    /// Maximum number of bytes in the textual token.
    pub max_token_bytes: u64,
    /// Maximum number of bytes in a decoded binary capsule.
    pub max_capsule_bytes: u64,
    /// Maximum number of bytes in a canonical manifest.
    pub max_manifest_bytes: u64,
    /// Maximum compressed payload length.
    pub max_compressed_payload_bytes: u64,
    /// Maximum reconstructed payload length.
    pub max_uncompressed_payload_bytes: u64,
    /// Maximum reconstructed length of one file.
    pub max_single_file_bytes: u64,
    /// Maximum number of file entries.
    pub max_file_count: u32,
    /// Maximum UTF-8 byte length of one protocol path.
    pub max_path_bytes: usize,
    /// Maximum uncompressed-to-compressed ratio.
    pub max_compression_ratio: u64,
}

impl SecurityLimits {
    /// Conservative RAP v1 defaults.
    pub const V1: Self = Self {
        max_token_bytes: 48 * 1_024 * 1_024,
        max_capsule_bytes: 34 * 1_024 * 1_024,
        max_manifest_bytes: 2 * 1_024 * 1_024,
        max_compressed_payload_bytes: 32 * 1_024 * 1_024,
        max_uncompressed_payload_bytes: 128 * 1_024 * 1_024,
        max_single_file_bytes: 64 * 1_024 * 1_024,
        max_file_count: 512,
        max_path_bytes: 1_024,
        max_compression_ratio: 200,
    };

    /// Conservative limits for unsigned, self-contained local artifacts.
    ///
    /// Unlike RAP v1, the simple artifact format permits legitimate inputs
    /// with an extreme compression ratio. The absolute reconstructed-size
    /// bound remains mandatory and is the primary decompression-bomb defense.
    pub const SIMPLE_ARTIFACT: Self = Self {
        max_compression_ratio: u64::MAX,
        ..Self::V1
    };
}

impl Default for SecurityLimits {
    fn default() -> Self {
        Self::V1
    }
}

#[cfg(test)]
mod tests {
    use super::SecurityLimits;

    #[test]
    fn defaults_are_conservative_and_internally_ordered() {
        let limits = SecurityLimits::default();
        assert!(limits.max_manifest_bytes < limits.max_capsule_bytes);
        assert!(limits.max_compressed_payload_bytes < limits.max_token_bytes);
        assert!(limits.max_single_file_bytes <= limits.max_uncompressed_payload_bytes);
        assert!(limits.max_file_count > 0);
    }

    #[test]
    fn simple_artifacts_rely_on_the_absolute_output_bound() {
        let limits = SecurityLimits::SIMPLE_ARTIFACT;
        assert_eq!(
            limits.max_uncompressed_payload_bytes,
            SecurityLimits::V1.max_uncompressed_payload_bytes
        );
        assert_eq!(limits.max_compression_ratio, u64::MAX);
    }
}
