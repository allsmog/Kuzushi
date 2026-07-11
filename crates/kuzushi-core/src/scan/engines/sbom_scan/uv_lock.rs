use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_uv_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "uv.lock")
}

pub(super) fn uv_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse uv.lock")?;
    Ok(value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| package_component(target, path, package))
        .collect())
}

pub(super) fn uv_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse uv.lock")?;
    let source = relative_display(target, path);
    Ok(value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|package| package_edges(package, &source))
        .collect())
}

fn package_component(target: &Path, path: &Path, package: &toml::Value) -> Option<SbomComponent> {
    let name = package_name(package)?;
    Some(component(
        target,
        path,
        "python",
        "uv.lock",
        &name,
        package_version(package),
    ))
}

fn package_edges(package: &toml::Value, source: &str) -> Vec<SbomDependencyEdge> {
    let Some(name) = package_name(package) else {
        return Vec::new();
    };
    let mut edges = vec![SbomDependencyEdge {
        from: "root".to_string(),
        to: name.clone(),
        source: source.to_string(),
    }];
    edges.extend(dependency_edges(&name, package, source));
    edges
}

fn dependency_edges(
    current_package: &str,
    package: &toml::Value,
    source: &str,
) -> Vec<SbomDependencyEdge> {
    package
        .get("dependencies")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(package_name)
        .map(|to| SbomDependencyEdge {
            from: current_package.to_string(),
            to,
            source: source.to_string(),
        })
        .collect()
}

fn package_name(package: &toml::Value) -> Option<String> {
    package
        .get("name")
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn package_version(package: &toml::Value) -> Option<&str> {
    package
        .get("version")
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
}
