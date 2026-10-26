use serde_json::{json, Value};
use std::collections::BTreeSet;

#[path = "sbom_export_support/mod.rs"]
mod support;
use support::{component, edge, report};

#[path = "sbom_spdx_export_contract/shared_dispatch.rs"]
mod shared_dispatch;

fn packages(output: &Value) -> &Vec<Value> {
    output["data"]["spdx"]["packages"].as_array().unwrap()
}

fn package_id(output: &Value, source: &str, version: &str) -> String {
    packages(output)
        .iter()
        .find(|package| {
            package["versionInfo"] == version
                && package["annotations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item["comment"] == format!("manifestPath={source}"))
        })
        .unwrap()["SPDXID"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn package_ids_distinguish_versions_sources_scopes_and_sanitized_names() {
    let mut scoped = component("library", "1", "a/package-lock.json");
    scoped.scope = "development".into();
    let mut ecosystem = component("library", "1", "a/package-lock.json");
    ecosystem.ecosystem = "cargo".into();
    let mut purl = component("library", "1", "a/package-lock.json");
    purl.package_url = None;
    let mut unversioned = component("library", "1", "a/package-lock.json");
    unversioned.version = None;
    let value = report(
        vec![
            component("library", "1", "a/package-lock.json"),
            component("library", "2", "a/package-lock.json"),
            component("library", "1", "b/package-lock.json"),
            scoped,
            ecosystem,
            purl,
            unversioned,
            component("@owned/library", "1", "a/package-lock.json"),
            component("-owned-library", "1", "a/package-lock.json"),
        ],
        vec![],
    )
    .to_tool_json();
    let ids: BTreeSet<_> = packages(&value)
        .iter()
        .map(|package| package["SPDXID"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 9);
    assert!(ids.iter().all(|id| id.starts_with("SPDXRef-")
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.')));
}

#[test]
fn same_name_in_other_manifests_cannot_redirect_relationships() {
    let value = report(
        vec![
            component("library", "1", "a/package.json"),
            component("library", "2", "b/package.json"),
        ],
        vec![
            edge("root", "library", "a/package.json"),
            edge("root", "library", "b/package.json"),
        ],
    )
    .to_tool_json();
    assert_ne!(
        package_id(&value, "a/package.json", "1"),
        package_id(&value, "b/package.json", "2")
    );
    let relationships = value["data"]["spdx"]["relationships"].as_array().unwrap();
    for (source, version) in [("a/package.json", "1"), ("b/package.json", "2")] {
        let id = package_id(&value, source, version);
        assert!(relationships.iter().any(|relationship| {
            relationship["relationshipType"] == "DEPENDS_ON"
                && relationship["relatedSpdxElement"] == id
                && relationship["comment"] == format!("source={source}")
        }));
    }
}

#[test]
fn ambiguous_and_missing_endpoints_are_disclosed_without_guessed_relationships() {
    let input = report(
        vec![
            component("library", "1", "pnpm-lock.yaml"),
            component("library", "2", "pnpm-lock.yaml"),
        ],
        vec![
            edge("root", "library", "pnpm-lock.yaml"),
            edge("root", "missing", "pnpm-lock.yaml"),
        ],
    );
    let output = input.to_tool_json();
    assert_eq!(output["data"]["spdxExport"]["omittedRelationshipCount"], 2);
    assert_eq!(
        output["data"]["spdxExport"]["dependencyRelationshipCount"],
        0
    );
    assert_eq!(output["data"]["dependencies"], json!(input.dependencies));
    assert!(output["output"]
        .as_str()
        .unwrap()
        .contains("SPDX and CycloneDX omitted 2 dependency relationships"));
    let omissions = output["data"]["spdxExport"]["omittedRelationships"]
        .as_array()
        .unwrap();
    assert_eq!(omissions[0]["toCandidates"].as_array().unwrap().len(), 2);
    assert_eq!(omissions[1]["toCandidates"], json!([]));
    assert!(output["data"]["spdx"]["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["relationshipType"] != "DEPENDS_ON"));
}

#[test]
fn a_package_named_root_is_never_the_document_as_a_dependency() {
    let output = report(
        vec![component("root", "1", "package.json")],
        vec![edge("root", "root", "package.json")],
    )
    .to_tool_json();
    assert_eq!(output["data"]["spdxExport"]["omittedRelationshipCount"], 1);
    let relations = output["data"]["spdx"]["relationships"].as_array().unwrap();
    assert!(relations
        .iter()
        .all(|item| item["relatedSpdxElement"] != "SPDXRef-DOCUMENT"));
}

#[test]
fn every_exported_reference_resolves_and_every_package_is_described() {
    let output = report(
        vec![component("library", "1", "package.json")],
        vec![
            edge("root", "library", "package.json"),
            edge("ghost", "library", "other.json"),
        ],
    )
    .to_tool_json();
    let mut ids: BTreeSet<String> = packages(&output)
        .iter()
        .map(|item| item["SPDXID"].as_str().unwrap().into())
        .collect();
    ids.insert("SPDXRef-DOCUMENT".into());
    let relations = output["data"]["spdx"]["relationships"].as_array().unwrap();
    for relation in relations {
        assert!(ids.contains(relation["spdxElementId"].as_str().unwrap()));
        assert!(ids.contains(relation["relatedSpdxElement"].as_str().unwrap()));
    }
    assert_eq!(
        relations
            .iter()
            .filter(|item| item["relationshipType"] == "DESCRIBES")
            .count(),
        1
    );
}

#[test]
fn identifiers_are_stable_across_order_and_document_metadata_is_complete() {
    let mut input = report(
        vec![
            component("library", "1", "package.json"),
            component("other", "2", "package.json"),
        ],
        vec![],
    );
    let first = input.to_tool_json();
    input.components.reverse();
    let second = input.to_tool_json();
    let ids = |output: &Value| {
        packages(output)
            .iter()
            .map(|package| package["SPDXID"].as_str().unwrap().to_string())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(ids(&first), ids(&second));
    assert_ne!(
        first["data"]["spdx"]["documentNamespace"],
        second["data"]["spdx"]["documentNamespace"]
    );
    let created = first["data"]["spdx"]["creationInfo"]["created"]
        .as_str()
        .unwrap();
    assert_eq!(created.len(), 20);
    assert!(created.ends_with('Z'));
    for package in packages(&first) {
        assert!(package["annotations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["annotationDate"] == created));
    }
}

#[test]
fn identical_records_share_a_package_without_changing_the_canonical_inventory() {
    let item = component("library", "1", "package.json");
    let input = report(
        vec![item.clone(), item],
        vec![edge("root", "library", "package.json")],
    );
    let output = input.to_tool_json();
    assert_eq!(output["data"]["components"], json!(input.components));
    assert_eq!(packages(&output).len(), 1);
    assert_eq!(output["data"]["spdxExport"]["componentRecordCount"], 2);
    assert_eq!(output["data"]["spdxExport"]["packageCount"], 1);
    assert_eq!(output["data"]["spdxExport"]["omittedRelationshipCount"], 0);
    assert_eq!(
        output["data"]["spdxExport"]["dependencyRelationshipCount"],
        1
    );
    assert!(!output["output"]
        .as_str()
        .unwrap()
        .contains("SPDX and CycloneDX omitted"));
}

#[test]
fn an_empty_inventory_has_no_invented_packages_dependencies_or_omissions() {
    let output = report(vec![], vec![]).to_tool_json();
    assert_eq!(output["status"], "completed");
    assert!(packages(&output).is_empty());
    assert_eq!(output["data"]["spdx"]["relationships"], json!([]));
    assert_eq!(
        output["data"]["spdxExport"]["omittedRelationships"],
        json!([])
    );
}
