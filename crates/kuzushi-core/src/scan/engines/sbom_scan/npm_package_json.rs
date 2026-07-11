use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

const NPM_DEPENDENCY_SCOPES: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

pub(super) fn package_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_json::from_str(text).context("sbom-scan: parse package.json")?;
    Ok(NPM_DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| json_dependency_entries(value.get(*scope), target, path, scope))
        .collect())
}

pub(super) fn is_package_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "package.json")
}

pub(super) fn package_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse package.json")?;
    let source = relative_display(target, path);
    Ok(NPM_DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| json_dependency_names(value.get(*scope)))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn json_dependency_entries(
    value: Option<&Value>,
    target: &Path,
    path: &Path,
    scope: &str,
) -> Vec<SbomComponent> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|deps| deps.iter())
        .filter_map(|(name, value)| json_dependency_version(value).map(|version| (name, version)))
        .map(|(name, version)| component(target, path, "npm", scope, name, Some(version)))
        .collect()
}

fn json_dependency_names(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|deps| deps.keys())
        .map(ToString::to_string)
        .collect()
}

fn json_dependency_version(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("version")?.as_str())
}
