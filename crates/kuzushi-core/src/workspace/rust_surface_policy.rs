//! Extraction-policy identity is distinct from target content identity.
//! A catalog can still match the source tree while containing old test surfaces.

use serde_json::Value;

pub(crate) const RUST_SURFACE_POLICY: &str = "rust-test-scopes-v1";
pub(crate) const REBUILD_RUST_SURFACES: &str =
    "Rust surfaces lack a supported test-scope filtering policy; run `context:build` then `entry-points:extract`";

pub(crate) fn has_legacy_rust_surface(language: &str, path: &str, metadata: &Value) -> bool {
    let is_rust = language == "Rust" || path.ends_with(".rs");
    is_rust && metadata["sourcePolicy"].as_str() != Some(RUST_SURFACE_POLICY)
}

pub(crate) fn is_legacy_rust_row(row: &Value) -> bool {
    has_legacy_rust_surface(
        row["language"].as_str().unwrap_or_default(),
        row["path"].as_str().unwrap_or_default(),
        &row["metadata"],
    )
}

pub(crate) fn snapshot_policy_disclosure(snapshot: &Value) -> Option<&'static str> {
    let rows = snapshot
        .pointer("/attackSurfaceMap/surfaces")
        .or_else(|| snapshot.pointer("/attackSurfaceMap/nodes"))?
        .as_array()?;
    rows.iter()
        .any(is_legacy_rust_row)
        .then_some(REBUILD_RUST_SURFACES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rust_policy_is_checked_separately_from_target_freshness() {
        let mut snapshot = json!({"attackSurfaceMap":{"surfaces":[{
            "language":"Rust", "path":"lib.rs", "metadata":{}
        }]}});
        assert_eq!(
            snapshot_policy_disclosure(&snapshot),
            Some(REBUILD_RUST_SURFACES)
        );
        snapshot["attackSurfaceMap"]["surfaces"][0]["metadata"]["sourcePolicy"] =
            json!(RUST_SURFACE_POLICY);
        assert_eq!(snapshot_policy_disclosure(&snapshot), None);
    }

    #[test]
    fn other_languages_and_empty_maps_do_not_require_rust_reextraction() {
        for snapshot in [
            json!({}),
            json!({"attackSurfaceMap":{"surfaces":[]}}),
            json!({"attackSurfaceMap":{"surfaces":[{"language":"Go","path":"main.go"}]}}),
        ] {
            assert_eq!(snapshot_policy_disclosure(&snapshot), None);
        }
    }
}
