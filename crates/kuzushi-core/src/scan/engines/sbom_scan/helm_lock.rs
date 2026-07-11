use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_yaml::Value;
use std::path::Path;

pub(super) fn is_helm_chart(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Chart.yaml")
}

pub(super) fn is_helm_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Chart.lock")
}

pub(super) fn helm_chart_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_yaml::from_str(text).context("sbom-scan: parse Chart.yaml")?;
    Ok(chart_dependencies(&value)
        .filter_map(|dependency| chart_component(target, path, dependency))
        .collect())
}

pub(super) fn helm_chart_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_yaml::from_str(&text).context("sbom-scan: parse Chart.yaml")?;
    Ok(dependency_edges(target, path, &value))
}

pub(super) fn helm_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_yaml::from_str(&text).context("sbom-scan: parse Chart.lock")?;
    Ok(dependency_edges(target, path, &value))
}

pub(super) fn helm_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_yaml::from_str(&text).context("sbom-scan: parse Chart.lock")?;
    Ok(chart_dependencies(&value)
        .filter_map(|dependency| chart_lock_component(target, path, dependency))
        .collect())
}

fn dependency_edges(target: &Path, path: &Path, value: &Value) -> Vec<SbomDependencyEdge> {
    let source = relative_display(target, path);
    chart_dependencies(value)
        .filter_map(chart_name)
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect()
}

fn chart_lock_component(target: &Path, path: &Path, value: &Value) -> Option<SbomComponent> {
    let name = chart_name(value)?;
    Some(component(
        target,
        path,
        "helm",
        &relative_display(target, path),
        &name,
        chart_version(value),
    ))
}

fn chart_component(target: &Path, path: &Path, value: &Value) -> Option<SbomComponent> {
    let name = chart_name(value)?;
    Some(component(
        target,
        path,
        "helm",
        "dependencies",
        &name,
        chart_version(value),
    ))
}

fn chart_dependencies(value: &Value) -> impl Iterator<Item = &Value> {
    value
        .get("dependencies")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
}

fn chart_name(value: &Value) -> Option<String> {
    value
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn chart_version(value: &Value) -> Option<&str> {
    value
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
}
