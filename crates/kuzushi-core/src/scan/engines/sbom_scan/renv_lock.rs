use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

const R_DEPENDENCY_FIELDS: &[&str] = &["Depends", "Imports", "Suggests", "LinkingTo"];

pub(super) fn is_renv_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "renv.lock")
}

pub(super) fn renv_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse renv.lock")?;
    let source = relative_display(target, path);
    Ok(value
        .get("Packages")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .flat_map(|(name, package)| package_edges(name, package, &source))
        .collect())
}

pub(super) fn renv_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse renv.lock")?;
    let source = relative_display(target, path);
    Ok(value
        .get("Packages")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|(name, package)| package_component(target, path, &source, name, package))
        .collect())
}

fn package_edges(name: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    let mut edges = vec![SbomDependencyEdge {
        from: "root".to_string(),
        to: name.to_string(),
        source: source.to_string(),
    }];
    edges.extend(dependency_edges(name, package, source));
    edges
}

fn package_component(
    target: &Path,
    path: &Path,
    source: &str,
    fallback_name: &str,
    package: &Value,
) -> Option<SbomComponent> {
    let name = package
        .get("Package")
        .and_then(Value::as_str)
        .unwrap_or(fallback_name)
        .trim();
    if name.is_empty() {
        return None;
    }
    Some(component(
        target,
        path,
        "r",
        source,
        name,
        package_version(package),
    ))
}

fn package_version(package: &Value) -> Option<&str> {
    package
        .get("Version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
}

fn dependency_edges(name: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    R_DEPENDENCY_FIELDS
        .iter()
        .filter_map(|field| package.get(*field).and_then(Value::as_str))
        .flat_map(dependency_names)
        .map(|to| SbomDependencyEdge {
            from: name.to_string(),
            to,
            source: source.to_string(),
        })
        .collect()
}

fn dependency_names(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(dependency_name)
        .filter(|name| *name != "R")
        .map(str::to_string)
        .collect()
}

fn dependency_name(raw: &str) -> Option<&str> {
    raw.trim()
        .split([' ', '('])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}
