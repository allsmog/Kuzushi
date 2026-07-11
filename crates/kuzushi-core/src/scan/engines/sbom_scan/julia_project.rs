use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_julia_project(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Project.toml")
}

pub(super) fn julia_project_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: toml::Value = toml::from_str(text).context("sbom-scan: parse Julia Project.toml")?;
    Ok(dependency_names(&value)
        .into_iter()
        .map(|name| component(target, path, "julia", "deps", &name, None))
        .collect())
}

pub(super) fn julia_project_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&text).context("sbom-scan: parse Julia Project.toml")?;
    let source = relative_display(target, path);
    Ok(dependency_names(&value)
        .into_iter()
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn dependency_names(value: &toml::Value) -> Vec<String> {
    value
        .get("deps")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|deps| deps.keys())
        .map(|name| name.to_string())
        .collect()
}
