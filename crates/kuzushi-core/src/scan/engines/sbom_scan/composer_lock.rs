use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

const COMPOSER_PACKAGE_SECTIONS: &[&str] = &["packages", "packages-dev"];

pub(super) fn is_composer_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "composer.lock")
}

pub(super) fn composer_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse composer.lock")?;
    let source = relative_display(target, path);
    Ok(COMPOSER_PACKAGE_SECTIONS
        .iter()
        .flat_map(|section| locked_package_edges(value.get(*section), &source))
        .collect())
}

pub(super) fn composer_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse composer.lock")?;
    Ok([
        ("packages", "composer.lock.packages"),
        ("packages-dev", "composer.lock.packages-dev"),
    ]
    .into_iter()
    .flat_map(|(section, scope)| locked_package_components(value.get(section), target, path, scope))
    .collect())
}

fn locked_package_edges(value: Option<&Value>, source: &str) -> Vec<SbomDependencyEdge> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|package| package_edges(package, source))
        .collect()
}

fn locked_package_components(
    value: Option<&Value>,
    target: &Path,
    path: &Path,
    scope: &str,
) -> Vec<SbomComponent> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| package_component(target, path, package, scope))
        .collect()
}

fn package_component(
    target: &Path,
    path: &Path,
    package: &Value,
    scope: &str,
) -> Option<SbomComponent> {
    let name = package_name(package)?;
    Some(component(
        target,
        path,
        "composer",
        scope,
        name,
        package_version(package),
    ))
}

fn package_edges(package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    let Some(name) = package_name(package) else {
        return Vec::new();
    };
    let mut edges = vec![SbomDependencyEdge {
        from: "root".to_string(),
        to: name.to_string(),
        source: source.to_string(),
    }];
    edges.extend(require_edges(name, package.get("require"), source));
    edges
}

fn require_edges(package_name: &str, value: Option<&Value>, source: &str) -> Vec<SbomDependencyEdge> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|requirements| requirements.keys())
        .filter(|name| !is_platform_requirement(name))
        .map(|to| SbomDependencyEdge {
            from: package_name.to_string(),
            to: to.to_string(),
            source: source.to_string(),
        })
        .collect()
}

fn is_platform_requirement(name: &str) -> bool {
    matches!(name, "php" | "hhvm")
        || name.starts_with("ext-")
        || name.starts_with("lib-")
        || name.starts_with("composer-")
}

fn package_name(package: &Value) -> Option<&str> {
    package
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn package_version(package: &Value) -> Option<&str> {
    package
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
}
