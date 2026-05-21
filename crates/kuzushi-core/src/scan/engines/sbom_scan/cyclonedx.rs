use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const ROOT_BOM_REF: &str = "kuzushi:root";

pub(super) fn cyclonedx_document(report: &SbomScanReport) -> Value {
    let component_refs = component_ref_lookup(&report.components);
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": report.target,
                "bom-ref": ROOT_BOM_REF,
            },
            "properties": lockfile_properties(&report.lockfiles),
        },
        "components": report
            .components
            .iter()
            .map(cyclonedx_component)
            .collect::<Vec<_>>(),
        "dependencies": cyclonedx_dependencies(&report.dependencies, &component_refs),
    })
}

fn component_ref_lookup(components: &[SbomComponent]) -> BTreeMap<String, String> {
    components
        .iter()
        .map(|component| (component.name.clone(), component_bom_ref(component)))
        .collect()
}

fn cyclonedx_component(component: &SbomComponent) -> Value {
    let purl = component.package_url.clone();
    let mut value = json!({
        "type": "library",
        "name": component.name,
        "bom-ref": component_bom_ref(component),
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

fn component_bom_ref(component: &SbomComponent) -> String {
    component
        .package_url
        .clone()
        .unwrap_or_else(|| format!("{}:{}", component.ecosystem, component.name))
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

fn cyclonedx_dependencies(
    edges: &[SbomDependencyEdge],
    component_refs: &BTreeMap<String, String>,
) -> Vec<Value> {
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for edge in edges {
        grouped
            .entry(dependency_ref(&edge.from, component_refs))
            .or_default()
            .push(dependency_ref(&edge.to, component_refs));
    }
    grouped
        .into_iter()
        .map(|(from, mut dependencies)| {
            dependencies.sort();
            dependencies.dedup();
            json!({
                "ref": from,
                "dependsOn": dependencies,
            })
        })
        .collect()
}

fn dependency_ref(name: &str, component_refs: &BTreeMap<String, String>) -> String {
    if name == "root" {
        return ROOT_BOM_REF.to_string();
    }
    component_refs
        .get(name)
        .cloned()
        .unwrap_or_else(|| format!("kuzushi:dependency:{}", name))
}

fn set_optional_string(value: &mut Value, key: &str, field: Option<String>) {
    if let Some(field) = field {
        value[key] = json!(field);
    }
}
