use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

type Mapping = serde_json::Map<String, Value>;

pub(super) fn is_pubspec_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "pubspec.lock")
}

pub(super) fn pubspec_lock_edges(
    target: &SbomInputs,
    path: &Path,
) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value = crate::yaml::parse_value(&text).context("sbom-scan: parse pubspec.lock")?;
    let source = relative_display(target, path);
    Ok(mapping_child(&value, "packages")
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|(name, package)| direct_package_name(name, package))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

pub(super) fn pubspec_lock_components(
    target: &SbomInputs,
    path: &Path,
) -> Result<Vec<SbomComponent>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value = crate::yaml::parse_value(&text).context("sbom-scan: parse pubspec.lock")?;
    let source = relative_display(target, path);
    Ok(mapping_child(&value, "packages")
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|(name, package)| package_component(target, path, &source, name, package))
        .collect())
}

fn direct_package_name(name: &str, package: &Value) -> Option<String> {
    if !dependency_kind(package)?.starts_with("direct") {
        return None;
    }
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn package_component(
    target: &Path,
    path: &Path,
    source: &str,
    name: &str,
    package: &Value,
) -> Option<SbomComponent> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some(component(
        target,
        path,
        "dart",
        source,
        name,
        package_version(package),
    ))
}

fn package_version(package: &Value) -> Option<&str> {
    mapping_value(package, "version")?
        .as_str()
        .map(str::trim)
        .filter(|version| !version.is_empty())
}

fn dependency_kind(package: &Value) -> Option<&str> {
    mapping_value(package, "dependency")?.as_str()
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
