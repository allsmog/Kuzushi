use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(super) fn is_nuget_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "packages.lock.json")
}

pub(super) fn nuget_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&text).context("sbom-scan: parse packages.lock.json")?;
    let source = relative_display(target, path);
    Ok(value
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|frameworks| frameworks.values())
        .flat_map(|packages| framework_edges(packages, &source))
        .collect())
}

pub(super) fn nuget_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&text).context("sbom-scan: parse packages.lock.json")?;
    Ok(value
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|frameworks| frameworks.iter())
        .flat_map(|(framework, packages)| framework_components(target, path, framework, packages))
        .collect())
}

fn framework_edges(packages: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    packages
        .as_object()
        .into_iter()
        .flat_map(|packages| packages.iter())
        .flat_map(|(name, package)| package_edges(name, package, source))
        .collect()
}

fn framework_components(
    target: &Path,
    path: &Path,
    framework: &str,
    packages: &Value,
) -> Vec<SbomComponent> {
    packages
        .as_object()
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|(name, package)| package_component(target, path, framework, name, package))
        .collect()
}

fn package_component(
    target: &Path,
    path: &Path,
    framework: &str,
    name: &str,
    package: &Value,
) -> Option<SbomComponent> {
    Some(component(
        target,
        path,
        "nuget",
        &format!("packages.lock.json.{framework}"),
        name,
        package_version(package),
    ))
}

fn package_edges(name: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    let mut edges = root_edge(name, package, source);
    edges.extend(child_edges(name, package, source));
    edges
}

fn root_edge(name: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    match package.get("type").and_then(Value::as_str) {
        Some("Direct") => vec![edge("root", name, source)],
        _ => Vec::new(),
    }
}

fn child_edges(name: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    package
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|dependencies| dependencies.keys())
        .map(|dependency| edge(name, dependency, source))
        .collect()
}

fn edge(from: &str, to: &str, source: &str) -> SbomDependencyEdge {
    SbomDependencyEdge {
        from: from.to_string(),
        to: to.to_string(),
        source: source.to_string(),
    }
}

fn package_version(package: &Value) -> Option<&str> {
    package
        .get("resolved")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
}
