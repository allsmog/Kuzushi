use super::bounded_fs as fs;
use super::python_dependency::python_dependency_name;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

type Mapping = serde_json::Map<String, Value>;

pub(super) fn is_conda_environment_manifest(name: &str) -> bool {
    matches!(name, "environment.yml" | "environment.yaml")
}

pub(super) fn is_conda_environment_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_conda_environment_manifest)
}

pub(super) fn conda_environment_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value = crate::yaml::parse_value(text).context("sbom-scan: parse Conda environment")?;
    let mut components = Vec::new();
    for dependency in dependencies(&value) {
        components.extend(conda_dependency_components(target, path, dependency));
    }
    Ok(components)
}

pub(super) fn conda_environment_edges(
    target: &Path,
    path: &Path,
) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value =
        crate::yaml::parse_value(&text).context("sbom-scan: parse Conda environment")?;
    let source = relative_display(target, path);
    Ok(dependencies(&value)
        .flat_map(conda_dependency_names)
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn conda_dependency_components(
    target: &Path,
    path: &Path,
    dependency: &Value,
) -> Vec<SbomComponent> {
    if let Some(raw) = dependency.as_str() {
        return conda_component(target, path, raw).into_iter().collect();
    }
    mapping_child(dependency, "pip")
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(Value::as_str)
        .map(|raw| pip_component(target, path, raw))
        .collect()
}

fn conda_dependency_names(dependency: &Value) -> Vec<String> {
    if let Some(raw) = dependency.as_str() {
        return conda_name(raw).into_iter().map(str::to_string).collect();
    }
    mapping_child(dependency, "pip")
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(Value::as_str)
        .map(python_dependency_name)
        .map(str::to_string)
        .collect()
}

fn conda_component(target: &Path, path: &Path, raw: &str) -> Option<SbomComponent> {
    let (name, version) = conda_name_and_version(raw)?;
    Some(component(
        target,
        path,
        "conda",
        "dependencies",
        name,
        version,
    ))
}

fn pip_component(target: &Path, path: &Path, raw: &str) -> SbomComponent {
    let name = python_dependency_name(raw);
    component(
        target,
        path,
        "python",
        "dependencies.pip",
        name,
        Some(raw.trim()),
    )
}

fn conda_name_and_version(raw: &str) -> Option<(&str, Option<&str>)> {
    let trimmed = raw.trim();
    let name = conda_name(trimmed)?;
    let version = trimmed
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
        .and_then(|rest| rest.split('=').next())
        .map(str::trim)
        .filter(|version| !version.is_empty());
    Some((name, version))
}

fn conda_name(raw: &str) -> Option<&str> {
    raw.split(['=', '<', '>', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn dependencies(value: &Value) -> impl Iterator<Item = &Value> {
    sequence_child(value, "dependencies").into_iter().flatten()
}

fn sequence_child<'a>(value: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    mapping_value(value, key)?.as_array()
}

fn mapping_child<'a>(value: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    mapping_value(value, key)?.as_array()
}

fn mapping_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    mapping(value)?.get(key)
}

fn mapping(value: &Value) -> Option<&Mapping> {
    value.as_object()
}
