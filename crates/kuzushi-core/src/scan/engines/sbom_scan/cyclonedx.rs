use super::export_graph::{ExportGraph, ResolvedDependency, ROOT_RECORD};
use super::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const ROOT_BOM_REF: &str = "kuzushi:root";

pub(super) struct CycloneDxExport {
    pub(super) document: Value,
    pub(super) diagnostics: Value,
}

pub(super) fn cyclonedx_export(
    report: &SbomScanReport,
    graph: &ExportGraph<'_>,
) -> CycloneDxExport {
    let mut diagnostics = graph.diagnostics(component_bom_ref);
    diagnostics["componentCount"] = json!(graph.packages.len());
    CycloneDxExport {
        document: cyclonedx_document(report, graph),
        diagnostics,
    }
}

fn cyclonedx_document(report: &SbomScanReport, graph: &ExportGraph<'_>) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "metadata": {
            "component": {
                "type": "application",
                "name": report.target,
                "bom-ref": ROOT_BOM_REF,
            },
            "properties": export_properties(report, graph),
        },
        "components": graph.packages
            .iter()
            .map(|(id, component)| cyclonedx_component(component, id))
            .collect::<Vec<_>>(),
        "dependencies": cyclonedx_dependencies(&graph.resolved),
        "compositions": dependency_compositions(graph),
    })
}

fn cyclonedx_component(component: &SbomComponent, id: &str) -> Value {
    let purl = component.package_url.clone();
    let mut value = json!({
        "type": "library",
        "name": component.name,
        "bom-ref": component_bom_ref(id),
        "scope": cyclonedx_scope(&component.scope),
        "properties": [
            {"name": "kuzushi:ecosystem", "value": component.ecosystem},
            {"name": "kuzushi:manifestPath", "value": component.manifest_path},
            {"name": "kuzushi:manifestScope", "value": component.scope},
        ],
    });
    set_optional_string(&mut value, "version", component.version.clone());
    set_optional_string(&mut value, "purl", purl);
    value
}

fn component_bom_ref(id: &str) -> String {
    if id == ROOT_RECORD {
        return ROOT_BOM_REF.into();
    }
    format!("kuzushi:component:{id}")
}

fn cyclonedx_scope(scope: &str) -> &'static str {
    if scope.contains("dev") || scope.contains("optional") {
        return "optional";
    }
    "required"
}

fn lockfile_properties(lockfiles: &[SbomLockfile]) -> Vec<Value> {
    lockfiles
        .iter()
        .map(|lockfile| {
            json!({
                "name": "kuzushi:lockfileSha256",
                "value": format!("{} {}", lockfile.path, lockfile.sha256),
            })
        })
        .collect()
}

fn cyclonedx_dependencies(edges: &[ResolvedDependency]) -> Vec<Value> {
    let mut grouped = BTreeMap::<String, BTreeSet<String>>::new();
    for edge in edges {
        grouped
            .entry(component_bom_ref(&edge.from))
            .or_default()
            .insert(component_bom_ref(&edge.to));
    }
    let mut nodes = Vec::new();
    if let Some(root) = grouped.remove(ROOT_BOM_REF) {
        nodes.push(dependency_node(ROOT_BOM_REF.into(), root));
    }
    nodes.extend(
        grouped
            .into_iter()
            .map(|(from, to)| dependency_node(from, to)),
    );
    nodes
}

fn dependency_node(from: String, dependencies: BTreeSet<String>) -> Value {
    json!({"ref": from, "dependsOn": dependencies})
}

fn dependency_compositions(graph: &ExportGraph<'_>) -> Vec<Value> {
    let mut references = vec![ROOT_BOM_REF.to_string()];
    references.extend(graph.packages.keys().map(|id| component_bom_ref(id)));
    vec![json!({"aggregate": graph_completeness(graph), "dependencies": references})]
}

fn graph_completeness(graph: &ExportGraph<'_>) -> &'static str {
    if graph.omitted_count() > 0 {
        "incomplete"
    } else {
        "unknown"
    }
}

fn export_properties(report: &SbomScanReport, graph: &ExportGraph<'_>) -> Vec<Value> {
    let mut properties = lockfile_properties(&report.lockfiles);
    properties.push(json!({
        "name": "kuzushi:dependencyGraphCompleteness", "value": graph_completeness(graph),
    }));
    if graph.omitted_count() > 0 {
        properties.push(json!({
            "name": "kuzushi:omittedDependencyRelationships",
            "value": Value::Array(graph.omitted_json(component_bom_ref)).to_string(),
        }));
    }
    properties
}

fn set_optional_string(value: &mut Value, key: &str, field: Option<String>) {
    if let Some(field) = field {
        value[key] = json!(field);
    }
}
