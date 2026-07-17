use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(super) use super::dependency_graph::is_package_lock;

pub(super) fn package_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse package lock")?;
    let source = relative_display(target, path);
    let mut components = package_lock_v2_components(target, path, &value, &source);
    components.extend(package_lock_v1_components(target, path, &value, &source));
    Ok(components)
}

fn package_lock_v2_components(
    target: &Path,
    path: &Path,
    value: &Value,
    source: &str,
) -> Vec<SbomComponent> {
    value
        .get("packages")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|(key, package)| package_component(target, path, source, key, package))
        .collect()
}

fn package_lock_v1_components(
    target: &Path,
    path: &Path,
    value: &Value,
    source: &str,
) -> Vec<SbomComponent> {
    value
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|dependencies| nested_dependency_components(target, path, source, dependencies))
        .collect()
}

fn nested_dependency_components(
    target: &Path,
    path: &Path,
    source: &str,
    dependencies: &serde_json::Map<String, Value>,
) -> Vec<SbomComponent> {
    dependencies
        .iter()
        .flat_map(|(name, dependency)| {
            let mut components = vec![component(
                target,
                path,
                "npm",
                source,
                name,
                package_version(dependency),
            )];
            if let Some(children) = dependency.get("dependencies").and_then(Value::as_object) {
                components.extend(nested_dependency_components(target, path, source, children));
            }
            components
        })
        .collect()
}

fn package_component(
    target: &Path,
    path: &Path,
    source: &str,
    key: &str,
    package: &Value,
) -> Option<SbomComponent> {
    let name = package_name_from_lock_key(key)?;
    Some(component(
        target,
        path,
        "npm",
        source,
        &name,
        package_version(package),
    ))
}

fn package_version(package: &Value) -> Option<&str> {
    package
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
}

fn package_name_from_lock_key(key: &str) -> Option<String> {
    let trimmed = key.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let name = trimmed.strip_prefix("node_modules/").unwrap_or(trimmed);
    if let Some(scoped) = name.strip_prefix('@') {
        return Some(scoped_package_name(scoped));
    }
    Some(name.rsplit('/').next().unwrap_or(name).to_string())
}

fn scoped_package_name(value: &str) -> String {
    let mut parts = value.split('/');
    match (parts.next(), parts.next()) {
        (Some(scope), Some(name)) => format!("@{scope}/{name}"),
        _ => format!("@{value}"),
    }
}
