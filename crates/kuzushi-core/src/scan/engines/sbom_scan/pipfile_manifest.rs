use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use super::toml_manifest::toml_version;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const PIPFILE_SCOPES: &[&str] = &["packages", "dev-packages"];

pub(super) fn is_pipfile(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Pipfile")
}

pub(super) fn pipfile_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: toml::Value = toml::from_str(text).context("sbom-scan: parse Pipfile")?;
    Ok(PIPFILE_SCOPES
        .iter()
        .flat_map(|scope| scoped_components(target, path, &value, scope))
        .collect())
}

pub(super) fn pipfile_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse Pipfile")?;
    let source = relative_display(target, path);
    Ok(PIPFILE_SCOPES
        .iter()
        .flat_map(|scope| scoped_dependency_names(&value, scope))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn scoped_components(
    target: &Path,
    path: &Path,
    value: &toml::Value,
    scope: &str,
) -> Vec<SbomComponent> {
    value
        .get(scope)
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .map(|(name, value)| component(target, path, "python", scope, name, toml_version(value)))
        .collect()
}

fn scoped_dependency_names(value: &toml::Value, scope: &str) -> Vec<String> {
    value
        .get(scope)
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|packages| packages.keys())
        .map(|name| name.to_string())
        .collect()
}
