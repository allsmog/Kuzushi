use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) fn spdx_document(report: &SbomScanReport) -> Value {
    let package_ids = package_id_lookup(&report.components);
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("Kuzushi SBOM {}", report.target),
        "documentNamespace": document_namespace(report),
        "creationInfo": {
            "creators": ["Tool: Kuzushi sbom-scan"],
        },
        "packages": report
            .components
            .iter()
            .map(spdx_package)
            .collect::<Vec<_>>(),
        "relationships": report
            .dependencies
            .iter()
            .map(|edge| spdx_relationship(edge, &package_ids))
            .collect::<Vec<_>>(),
        "annotations": lockfile_annotations(&report.lockfiles),
    })
}

fn package_id_lookup(components: &[SbomComponent]) -> BTreeMap<String, String> {
    components
        .iter()
        .map(|component| (component.name.clone(), package_spdx_id(component)))
        .collect()
}

fn spdx_package(component: &SbomComponent) -> Value {
    json!({
        "name": component.name,
        "SPDXID": package_spdx_id(component),
        "versionInfo": component.version.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "externalRefs": package_external_refs(component),
        "annotations": [
            annotation("OTHER", format!("ecosystem={}", component.ecosystem)),
            annotation("OTHER", format!("manifestPath={}", component.manifest_path)),
            annotation("OTHER", format!("manifestScope={}", component.scope)),
        ],
    })
}

fn package_external_refs(component: &SbomComponent) -> Vec<Value> {
    component
        .package_url
        .as_ref()
        .map(|purl| {
            vec![json!({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            })]
        })
        .unwrap_or_default()
}

fn lockfile_annotations(lockfiles: &[SbomLockfile]) -> Vec<Value> {
    lockfiles
        .iter()
        .map(|lockfile| annotation("OTHER", format!("{} {}", lockfile.path, lockfile.sha256)))
        .collect()
}

fn spdx_relationship(edge: &SbomDependencyEdge, package_ids: &BTreeMap<String, String>) -> Value {
    json!({
        "spdxElementId": relationship_spdx_id(&edge.from, package_ids),
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": relationship_spdx_id(&edge.to, package_ids),
        "comment": format!("source={}", edge.source),
    })
}

fn relationship_spdx_id(name: &str, package_ids: &BTreeMap<String, String>) -> String {
    if name == "root" {
        return "SPDXRef-DOCUMENT".to_string();
    }
    package_ids
        .get(name)
        .cloned()
        .unwrap_or_else(|| format!("SPDXRef-Package-unknown-{}", sanitize_spdx_id(name)))
}

fn annotation(kind: &str, comment: String) -> Value {
    json!({
        "annotationType": kind,
        "annotator": "Tool: Kuzushi sbom-scan",
        "comment": comment,
    })
}

fn package_spdx_id(component: &SbomComponent) -> String {
    format!(
        "SPDXRef-Package-{}-{}",
        sanitize_spdx_id(&component.ecosystem),
        sanitize_spdx_id(&component.name)
    )
}

fn document_namespace(report: &SbomScanReport) -> String {
    format!(
        "https://kuzushi.local/spdx/{}",
        sanitize_spdx_id(&report.target)
    )
}

fn sanitize_spdx_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}
