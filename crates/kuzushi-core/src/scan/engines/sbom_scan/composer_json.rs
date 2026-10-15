use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

const COMPOSER_DEPENDENCY_SCOPES: &[&str] = &["require", "require-dev"];

pub(super) fn composer_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_json::from_str(text).context("sbom-scan: parse composer.json")?;
    Ok(COMPOSER_DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| dependency_entries(value.get(*scope), target, path, scope))
        .collect())
}

pub(super) fn is_composer_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "composer.json")
}

pub(super) fn composer_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse composer.json")?;
    let source = relative_display(target, path);
    Ok(COMPOSER_DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| dependency_names(value.get(*scope)))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn dependency_entries(
    value: Option<&Value>,
    target: &Path,
    path: &Path,
    scope: &str,
) -> Vec<SbomComponent> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|deps| deps.iter())
        .filter(|(name, _)| name.as_str() != "php")
        .filter_map(|(name, value)| value.as_str().map(|version| (name, version)))
        .map(|(name, version)| component(target, path, "composer", scope, name, Some(version)))
        .collect()
}

fn dependency_names(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|deps| deps.keys())
        .filter(|name| name.as_str() != "php")
        .map(ToString::to_string)
        .collect()
}
