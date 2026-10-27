use super::export_graph::{ExportGraph, ResolvedDependency, ROOT_RECORD};
use super::*;
use serde_json::{json, Value};
mod metadata;

use metadata::ExportMetadata;

pub(super) struct SpdxExport {
    pub(super) document: Value,
    pub(super) diagnostics: Value,
}

pub(super) fn spdx_export(report: &SbomScanReport, graph: &ExportGraph<'_>) -> SpdxExport {
    let metadata = ExportMetadata::now();
    let mut diagnostics = graph.diagnostics(spdx_ref);
    diagnostics["packageCount"] = json!(graph.packages.len());
    SpdxExport {
        document: spdx_document(report, graph, &metadata),
        diagnostics,
    }
}

fn spdx_document(
    report: &SbomScanReport,
    graph: &ExportGraph<'_>,
    metadata: &ExportMetadata,
) -> Value {
    let mut relationships = package_descriptions(graph);
    relationships.extend(graph.resolved.iter().map(spdx_relationship));
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("Kuzushi SBOM {}", report.target),
        "documentNamespace": metadata.namespace,
        "creationInfo": {
            "creators": ["Tool: Kuzushi sbom-scan"],
            "created": metadata.created,
        },
        "packages": graph.packages.iter().map(|(id, component)| spdx_package(component, &spdx_ref(id), metadata)).collect::<Vec<_>>(),
        "relationships": relationships,
        "annotations": document_annotations(report, graph, metadata),
    })
}

fn spdx_package(component: &SbomComponent, id: &str, metadata: &ExportMetadata) -> Value {
    json!({
        "name": component.name,
        "SPDXID": id,
        "versionInfo": component.version.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "externalRefs": package_external_refs(component),
        "annotations": [
            metadata.annotation(format!("ecosystem={}", component.ecosystem)),
            metadata.annotation(format!("manifestPath={}", component.manifest_path)),
            metadata.annotation(format!("manifestScope={}", component.scope)),
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

fn document_annotations(
    report: &SbomScanReport,
    graph: &ExportGraph<'_>,
    metadata: &ExportMetadata,
) -> Vec<Value> {
    let mut annotations = report
        .lockfiles
        .iter()
        .map(|lockfile| metadata.annotation(format!("{} {}", lockfile.path, lockfile.sha256)))
        .collect::<Vec<_>>();
    annotations.extend(
        graph
            .omitted_json(spdx_ref)
            .into_iter()
            .map(|omission| metadata.annotation(format!("omittedDependency={omission}"))),
    );
    annotations
}

fn spdx_ref(id: &str) -> String {
    if id == ROOT_RECORD {
        return "SPDXRef-DOCUMENT".into();
    }
    format!("SPDXRef-Package-{id}")
}

fn package_descriptions(graph: &ExportGraph<'_>) -> Vec<Value> {
    graph
        .packages
        .keys()
        .map(|id| {
            json!({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdx_ref(id),
            })
        })
        .collect()
}

fn spdx_relationship(edge: &ResolvedDependency) -> Value {
    json!({
        "spdxElementId": spdx_ref(&edge.from),
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": spdx_ref(&edge.to),
        "comment": format!("source={}", edge.source),
    })
}
