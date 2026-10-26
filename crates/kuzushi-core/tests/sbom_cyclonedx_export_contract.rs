use serde_json::{json, Value};
use std::collections::BTreeSet;

#[path = "sbom_export_support/mod.rs"]
mod support;
use support::{component, dispatch, edge, report};

fn document(output: &Value) -> &Value {
    &output["data"]["cycloneDx"]
}

fn component_ref(output: &Value, source: &str, version: &str) -> String {
    document(output)["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["version"] == version
                && item["properties"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|property| {
                        property["name"] == "kuzushi:manifestPath" && property["value"] == source
                    })
        })
        .unwrap()["bom-ref"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn identical_package_urls_in_different_sources_have_distinct_references() {
    let output = report(
        vec![
            component("library", "1", "a/package.json"),
            component("library", "1", "b/package.json"),
        ],
        vec![],
    )
    .to_tool_json();
    let first = component_ref(&output, "a/package.json", "1");
    let second = component_ref(&output, "b/package.json", "1");
    assert_ne!(first, second);
    let packages = document(&output)["components"].as_array().unwrap();
    assert!(packages
        .iter()
        .all(|item| item["purl"] == "pkg:npm/library@1"));
}

#[test]
fn a_foreign_lockfile_cannot_redirect_a_declared_dependency() {
    let mut declared = component("library", "^1", "package.json");
    declared.package_url = Some("pkg:npm/library".into());
    let output = report(
        vec![declared, component("library", "2", "pnpm-lock.yaml")],
        vec![edge("root", "library", "package.json")],
    )
    .to_tool_json();
    let expected = component_ref(&output, "package.json", "^1");
    let foreign = component_ref(&output, "pnpm-lock.yaml", "2");
    let root = document(&output)["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["ref"] == "kuzushi:root")
        .unwrap();
    assert_eq!(root["dependsOn"], json!([expected]));
    assert!(!root["dependsOn"]
        .as_array()
        .unwrap()
        .contains(&json!(foreign)));
}

#[test]
fn unresolved_edges_are_disclosed_without_invented_dependency_nodes() {
    let input = report(
        vec![
            component("library", "1", "pnpm-lock.yaml"),
            component("library", "2", "pnpm-lock.yaml"),
        ],
        vec![
            edge("root", "library", "pnpm-lock.yaml"),
            edge("ghost", "library", "pnpm-lock.yaml"),
            edge("library", "missing", "pnpm-lock.yaml"),
        ],
    );
    let output = input.to_tool_json();
    assert_eq!(output["data"]["dependencies"], json!(input.dependencies));
    assert_eq!(
        output["data"]["cycloneDxExport"]["omittedRelationshipCount"],
        3
    );
    assert_eq!(
        output["data"]["cycloneDxExport"]["dependencyRelationshipCount"],
        0
    );
    assert_eq!(document(&output)["dependencies"], json!([]));
    assert_eq!(
        document(&output)["compositions"][0]["aggregate"],
        "incomplete"
    );
    assert_eq!(
        output["data"]["cycloneDxExport"]["omittedRelationships"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn every_dependency_and_composition_reference_resolves_to_a_declared_record() {
    let output = report(
        vec![
            component("app", "1", "pnpm-lock.yaml"),
            component("library", "1", "pnpm-lock.yaml"),
        ],
        vec![
            edge("app", "library", "pnpm-lock.yaml"),
            edge("ghost", "library", "pnpm-lock.yaml"),
        ],
    )
    .to_tool_json();
    let mut known: BTreeSet<String> = document(&output)["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["bom-ref"].as_str().unwrap().into())
        .collect();
    known.insert("kuzushi:root".into());
    let nodes = document(&output)["dependencies"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    for node in nodes {
        assert!(known.contains(node["ref"].as_str().unwrap()));
        assert!(node["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .all(|id| known.contains(id.as_str().unwrap())));
    }
    let composition = &document(&output)["compositions"][0];
    assert_eq!(composition["aggregate"], "incomplete");
    assert!(composition["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .all(|id| known.contains(id.as_str().unwrap())));
}

#[test]
fn absent_outgoing_evidence_stays_unknown_and_exports_have_separate_serials() {
    for components in [vec![], vec![component("library", "1", "package.json")]] {
        let input = report(components, vec![]);
        let first = input.to_tool_json();
        let second = input.to_tool_json();
        assert_eq!(document(&first)["dependencies"], json!([]));
        assert_eq!(document(&first)["compositions"][0]["aggregate"], "unknown");
        let serial = document(&first)["serialNumber"].as_str().unwrap();
        uuid::Uuid::parse_str(serial.strip_prefix("urn:uuid:").unwrap()).unwrap();
        assert_ne!(
            document(&first)["serialNumber"],
            document(&second)["serialNumber"]
        );
    }
}

#[test]
fn duplicate_records_export_once_and_reference_identity_survives_reordering() {
    let item = component("library", "1", "package.json");
    let mut input = report(
        vec![item.clone(), item, component("other", "1", "package.json")],
        vec![edge("root", "library", "package.json")],
    );
    let first = input.to_tool_json();
    input.components.reverse();
    let second = input.to_tool_json();
    let refs = |output: &Value| {
        document(output)["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["bom-ref"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(document(&first)["components"].as_array().unwrap().len(), 2);
    assert_eq!(refs(&first), refs(&second));
    assert_eq!(first["data"]["components"].as_array().unwrap().len(), 3);
    assert_eq!(first["data"]["cycloneDxExport"]["componentCount"], 2);
}

#[test]
fn prepared_dispatch_keeps_one_combined_warning_and_its_inspection_receipt() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("Cargo.lock"),
        r#"version = 3
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["library 1.0.0", "missing 1.0.0"]
[[package]]
name = "library"
version = "1.0.0"
[[package]]
name = "library"
version = "2.0.0"
"#,
    )
    .unwrap();
    let output = dispatch(root.path(), json!({}));
    assert_eq!(
        output["data"]["cycloneDxExport"]["omittedRelationshipCount"],
        2
    );
    let text = output["output"].as_str().unwrap();
    assert!(
        text.contains("SPDX and CycloneDX omitted 2 dependency relationships"),
        "{text}"
    );
    assert_eq!(text.matches("omitted").count(), 1);
    assert!(
        text.contains("Captured dependency inputs: 1 file;"),
        "{text}"
    );
}
