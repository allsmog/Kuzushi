use super::*;

const MODERN_LOCK: &str = r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      outer:
        specifier: ^1.0.0
        version: 1.0.0(peer@2.0.0)
packages:
  outer@1.0.0: {}
  inner@2.0.0: {}
  '@scope/plugin@3.0.0': {}
  optional@4.0.0: {}
snapshots:
  outer@1.0.0(peer@2.0.0):
    dependencies:
      inner: 2.0.0
    optionalDependencies:
      optional: 4.0.0
    transitivePeerDependencies:
      - peer
  '@scope/plugin@3.0.0(@scope/peer@5.0.0)':
    dependencies:
      outer: 1.0.0(peer@2.0.0)
"#;

#[test]
fn pnpm_snapshots_preserve_transitive_optional_and_scoped_parent_links() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("pnpm-lock.yaml"), MODERN_LOCK).unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "completed");
    let report: SbomScanReport = serde_json::from_value(result["data"].clone()).unwrap();
    let edges = report
        .dependencies
        .iter()
        .map(|edge| (edge.from.as_str(), edge.to.as_str(), edge.source.as_str()))
        .collect::<std::collections::BTreeSet<_>>();
    let expected = std::collections::BTreeSet::from([
        ("root", "outer", "pnpm-lock.yaml"),
        ("outer", "inner", "pnpm-lock.yaml"),
        ("outer", "optional", "pnpm-lock.yaml"),
        ("@scope/plugin", "outer", "pnpm-lock.yaml"),
    ]);
    assert_eq!(edges, expected);
    assert!(report
        .components
        .iter()
        .all(|item| !item.name.contains('(')));
    assert_eq!(result["data"]["inspection"]["capturedFiles"], 1);
    assert_eq!(
        std::fs::read_to_string(root.path().join("pnpm-lock.yaml")).unwrap(),
        MODERN_LOCK
    );
}

#[test]
fn pnpm_snapshots_reject_unsupported_shapes_without_publishing_package_claims() {
    let invalid = [
        "snapshots: []",
        "snapshots:\n  outer@1.0.0: null",
        "snapshots:\n  outer@1.0.0:\n    dependencies: []",
        "snapshots:\n  outer@1.0.0:\n    optionalDependencies: null",
        "snapshots:\n  outer@1.0.0:\n    dependencies:\n      inner: 2",
        "snapshots:\n  outer@1.0.0:\n    dependencies:\n      inner: ''",
        "snapshots:\n  outer@1.0.0:\n    dependencies:\n      '': 2.0.0",
    ];
    for suffix in invalid {
        let root = tempfile::tempdir().unwrap();
        let text = format!("lockfileVersion: '9.0'\npackages:\n  outer@1.0.0: {{}}\n{suffix}\n");
        std::fs::write(root.path().join("pnpm-lock.yaml"), &text).unwrap();
        let result = dispatch(root.path(), json!({}), None).unwrap();
        assert_eq!(result["status"], "failed", "{suffix}: {result}");
        assert!(result["errors"].to_string().contains("pnpm-lock.yaml"));
        for field in ["components", "dependencies", "cycloneDx", "spdx"] {
            assert!(result["data"].get(field).is_none(), "{field}: {result}");
        }
        assert_eq!(result["data"]["inspection"]["capturedFiles"], 1);
        assert_eq!(
            std::fs::read_to_string(root.path().join("pnpm-lock.yaml")).unwrap(),
            text
        );
    }
}

#[test]
fn pnpm_snapshots_keep_legacy_package_edges_and_deduplicate_matching_links() {
    let root = tempfile::tempdir().unwrap();
    let lock = MODERN_LOCK.replace(
        "outer@1.0.0: {}",
        "outer@1.0.0:\n    dependencies:\n      inner: 2.0.0",
    );
    std::fs::write(root.path().join("pnpm-lock.yaml"), lock).unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    let edges = result["data"]["dependencies"].as_array().unwrap();
    assert_eq!(
        edges
            .iter()
            .filter(|edge| edge["from"] == "outer" && edge["to"] == "inner")
            .count(),
        1
    );
}
