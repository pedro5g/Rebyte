#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_format::RelativeArtifactPath;

fuzz_target!(|data: &str| {
    if let Ok(path) = RelativeArtifactPath::new(data) {
        assert_eq!(RelativeArtifactPath::new(path.as_str()), Ok(path));
    }
});
