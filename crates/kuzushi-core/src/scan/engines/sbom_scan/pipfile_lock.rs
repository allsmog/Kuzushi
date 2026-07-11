use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(super) fn is_pipfile_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Pipfile.lock")
}

pub(super) fn pipfile_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse Pipfile.lock")?;
    let source = relative_display(target, path);
    Ok(["default", "develop"]
        .into_iter()
        .flat_map(|scope| locked_packages(value.get(scope), &source))
        .collect())
}

pub(super) fn pipfile_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse Pipfile.lock")?;
    Ok([
        ("default", "Pipfile.lock.default"),
        ("develop", "Pipfile.lock.develop"),
    ]
    .into_iter()
    .flat_map(|(section, scope)| locked_components(value.get(section), target, path, scope))
    .collect())
}

fn locked_packages(value: Option<&Value>, source: &str) -> Vec<SbomDependencyEdge> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.keys())
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to: to.to_string(),
            source: source.to_string(),
        })
        .collect()
}

fn locked_components(
    value: Option<&Value>,
    target: &Path,
    path: &Path,
    scope: &str,
) -> Vec<SbomComponent> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .map(|(name, package)| {
            component(
                target,
                path,
                "python",
                scope,
                name,
                locked_package_version(package),
            )
        })
        .collect()
}

fn locked_package_version(package: &Value) -> Option<&str> {
    package
        .get("version")
        .and_then(Value::as_str)
        .and_then(exact_pipfile_version)
}

fn exact_pipfile_version(value: &str) -> Option<&str> {
    value
        .trim()
        .strip_prefix("==")
        .map(str::trim)
        .filter(|version| !version.is_empty())
}
