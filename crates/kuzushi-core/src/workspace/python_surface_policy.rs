//! Python HTTP extraction identity, independent of unchanged source bytes.
use serde_json::Value;

pub(crate) const PYTHON_HTTP_SURFACE_POLICY: &str = "python-http-receivers-v1";
pub(crate) const REBUILD_PYTHON_SURFACES: &str =
    "Python HTTP surfaces use an older framework extraction policy; run `context:build` then `entry-points:extract`";

pub(crate) fn is_legacy_python_http_row(row: &Value) -> bool {
    has_legacy_python_http_surface(
        row["language"].as_str().unwrap_or_default(),
        row["path"].as_str().unwrap_or_default(),
        row["kind"].as_str() == Some("http_route"),
        &row["metadata"],
    )
}

pub(crate) fn has_legacy_python_http_surface(
    language: &str,
    path: &str,
    is_http: bool,
    metadata: &Value,
) -> bool {
    is_http
        && is_python_surface(language, path)
        && metadata["sourcePolicy"].as_str() != Some(PYTHON_HTTP_SURFACE_POLICY)
}

fn is_python_surface(language: &str, path: &str) -> bool {
    language == "Python" || path.ends_with(".py")
}

pub(crate) fn snapshot_policy_disclosure(snapshot: &Value) -> Option<&'static str> {
    let rows = snapshot
        .pointer("/attackSurfaceMap/surfaces")
        .or_else(|| snapshot.pointer("/attackSurfaceMap/nodes"))?
        .as_array()?;
    rows.iter()
        .any(is_legacy_python_http_row)
        .then_some(REBUILD_PYTHON_SURFACES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn old_python_http_rows_require_new_extraction_even_without_source_drift() {
        let mut value = json!({"attackSurfaceMap":{"surfaces":[{"language":"Python","path":"app.py","kind":"http_route","metadata":{}}]}});
        assert_eq!(
            snapshot_policy_disclosure(&value),
            Some(REBUILD_PYTHON_SURFACES)
        );
        value["attackSurfaceMap"]["surfaces"][0]["metadata"]["sourcePolicy"] =
            json!(PYTHON_HTTP_SURFACE_POLICY);
        assert_eq!(snapshot_policy_disclosure(&value), None);
    }

    #[test]
    fn non_http_python_and_other_languages_keep_existing_policy_semantics() {
        for value in [
            json!({}),
            json!({"attackSurfaceMap":{"surfaces":[{"path":"app.py","kind":"cli_entrypoint"}]}}),
            json!({"attackSurfaceMap":{"surfaces":[{"path":"app.js","kind":"http_route"}]}}),
        ] {
            assert_eq!(snapshot_policy_disclosure(&value), None);
        }
    }
}
