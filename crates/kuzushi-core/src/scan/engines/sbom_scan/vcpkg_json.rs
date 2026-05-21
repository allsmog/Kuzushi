use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(super) fn is_vcpkg_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "vcpkg.json")
}

pub(super) fn vcpkg_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_json::from_str(text).context("sbom-scan: parse vcpkg.json")?;
    Ok(dependency_names(&value)
        .into_iter()
        .map(|name| component(target, path, "vcpkg", "dependencies", &name, None))
        .collect())
}

pub(super) fn vcpkg_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse vcpkg.json")?;
    let source = relative_display(target, path);
    Ok(dependency_names(&value)
        .into_iter()
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn dependency_names(value: &Value) -> Vec<String> {
    value
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(dependency_name)
        .collect()
}

fn dependency_name(value: &Value) -> Option<String> {
    match value {
        Value::String(name) => clean_name(name),
        Value::Object(dependency) => dependency.get("name").and_then(Value::as_str).and_then(clean_name),
        _ => None,
    }
}

fn clean_name(name: &str) -> Option<String> {
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}
