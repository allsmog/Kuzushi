use super::toml_manifest::{toml_value_at, toml_version};
use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const TARGET_DEPENDENCY_SCOPES: &[&str] =
    &["dependencies", "dev-dependencies", "build-dependencies"];

pub(super) fn cargo_target_components(
    target: &Path,
    path: &Path,
    value: &toml::Value,
) -> Vec<SbomComponent> {
    value
        .get("target")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|targets| targets.iter())
        .flat_map(|(target_name, target_value)| {
            target_dependency_components(target, path, target_name, target_value)
        })
        .collect()
}

pub(super) fn is_cargo_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Cargo.toml")
}

pub(super) fn cargo_manifest_edges(
    target: &Path,
    path: &Path,
) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse Cargo.toml")?;
    let source = relative_display(target, path);
    Ok(cargo_dependency_names(&value)
        .into_iter()
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn cargo_dependency_names(value: &toml::Value) -> Vec<String> {
    let mut names = cargo_top_level_dependency_names(value);
    names.extend(cargo_target_dependency_names(value));
    names
}

fn cargo_top_level_dependency_names(value: &toml::Value) -> Vec<String> {
    [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "workspace.dependencies",
    ]
    .into_iter()
    .flat_map(|scope| table_dependency_names(toml_value_at(value, scope)))
    .collect()
}

fn cargo_target_dependency_names(value: &toml::Value) -> Vec<String> {
    value
        .get("target")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|targets| targets.values())
        .flat_map(target_dependency_names)
        .collect()
}

fn target_dependency_names(value: &toml::Value) -> Vec<String> {
    TARGET_DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| table_dependency_names(value.get(scope)))
        .collect()
}

fn table_dependency_names(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|dependencies| dependencies.keys())
        .map(ToString::to_string)
        .collect()
}

fn target_dependency_components(
    target: &Path,
    path: &Path,
    target_name: &str,
    value: &toml::Value,
) -> Vec<SbomComponent> {
    TARGET_DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| target_scope_components(target, path, target_name, value, scope))
        .collect()
}

fn target_scope_components(
    target: &Path,
    path: &Path,
    target_name: &str,
    value: &toml::Value,
    scope: &str,
) -> Vec<SbomComponent> {
    value
        .get(scope)
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|deps| deps.iter())
        .map(|(name, value)| {
            component(
                target,
                path,
                "cargo",
                &format!("target.{target_name}.{scope}"),
                name,
                toml_version(value),
            )
        })
        .collect()
}
