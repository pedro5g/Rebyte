//! Portable path properties over generated safe and arbitrary UTF-8 values.

#![forbid(unsafe_code)]

use proptest::prelude::*;
use rebyte_format::RelativeArtifactPath;

proptest! {
    #[test]
    fn accepted_paths_are_stable(value in ".{0,2048}") {
        if let Ok(path) = RelativeArtifactPath::new(&value) {
            prop_assert_eq!(RelativeArtifactPath::new(path.as_str()), Ok(path));
        }
    }

    #[test]
    fn generated_portable_paths_round_trip(
        components in prop::collection::vec("[a-z0-9_-]{1,20}", 1..12)
    ) {
        let value = components
            .iter()
            .map(|component| format!("x{component}"))
            .collect::<Vec<_>>()
            .join("/");
        let path = RelativeArtifactPath::new(&value)?;
        prop_assert_eq!(path.as_str(), value);
    }
}
