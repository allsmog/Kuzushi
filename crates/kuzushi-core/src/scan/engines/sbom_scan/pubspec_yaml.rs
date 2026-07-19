use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

type Mapping = serde_json::Map<String, Value>;

pub(super) fn pubspec_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value = crate::yaml::parse_value(text).context("sbom-scan: parse pubspec.yaml")?;
    let mut components = dependency_components(target, path, &value, "dependencies");
    components.extend(dependency_components(
        target,
        path,
        &value,
        "dev_dependencies",
    ));
    Ok(components)
}

pub(super) fn is_pubspec_yaml(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "pubspec.yaml")
}

pub(super) fn pubspec_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value = crate::yaml::parse_value(&text).context("sbom-scan: parse pubspec.yaml")?;
    let source = relative_display(target, path);
    let mut edges = dependency_edges(&value, "dependencies", &source);
    edges.extend(dependency_edges(&value, "dev_dependencies", &source));
    Ok(edges)
}

fn dependency_components(
    target: &Path,
    path: &Path,
    value: &Value,
    scope: &'static str,
) -> Vec<SbomComponent> {
    mapping_child(value, scope)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, dependency)| {
            dependency_component(target, path, scope, name, dependency)
        })
        .collect()
}

fn dependency_edges(value: &Value, scope: &'static str, source: &str) -> Vec<SbomDependencyEdge> {
    mapping_child(value, scope)
        .into_iter()
        .flat_map(|dependencies| dependencies.keys())
        .filter_map(|name| package_name(name))
        .filter(|name| !is_sdk_dependency(name))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to: to.to_string(),
            source: source.to_string(),
        })
        .collect()
}

fn dependency_component(
    target: &Path,
    path: &Path,
    scope: &str,
    name: &str,
    dependency: &Value,
) -> Option<SbomComponent> {
    let name = package_name(name)?;
    if is_sdk_dependency(name) {
        return None;
    }
    Some(component(
        target,
        path,
        "dart",
        scope,
        name,
        dependency_version(dependency),
    ))
}

fn is_sdk_dependency(name: &str) -> bool {
    matches!(name, "flutter" | "dart")
}

fn package_name(name: &str) -> Option<&str> {
    let name = name.trim();
    (!name.is_empty()).then_some(name)
}

fn dependency_version(dependency: &Value) -> Option<&str> {
    dependency
        .as_str()
        .or_else(|| mapping_value(dependency, "version").and_then(Value::as_str))
        .map(str::trim)
        .filter(|version| !version.is_empty())
}

fn mapping_child<'a>(value: &'a Value, key: &str) -> Option<&'a Mapping> {
    mapping(mapping_value(value, key)?)
}

fn mapping_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    mapping(value)?.get(key)
}

fn mapping(value: &Value) -> Option<&Mapping> {
    value.as_object()
}
