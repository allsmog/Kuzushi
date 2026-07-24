use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_poetry_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "poetry.lock")
}

pub(super) fn poetry_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse poetry.lock")?;
    let source = relative_display(target, path);
    Ok(value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|package| package_edges(package, &source))
        .collect())
}

pub(super) fn poetry_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse poetry.lock")?;
    Ok(value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| package_component(target, path, package))
        .collect())
}

fn package_component(target: &Path, path: &Path, package: &toml::Value) -> Option<SbomComponent> {
    let name = package_name(package)?;
    Some(component(
        target,
        path,
        "python",
        "poetry.lock",
        &name,
        package_version(package),
    ))
}

fn package_edges(package: &toml::Value, source: &str) -> Vec<SbomDependencyEdge> {
    let Some(from) = package_name(package) else {
        return Vec::new();
    };
    package
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|dependencies| dependencies.keys())
        .map(|to| SbomDependencyEdge {
            from: from.clone(),
            to: to.to_string(),
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
