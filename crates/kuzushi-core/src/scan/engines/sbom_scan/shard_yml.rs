use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use serde_yaml::{Mapping, Value};
use std::fs;
use std::path::Path;

const DEPENDENCY_SCOPES: &[&str] = &["dependencies", "development_dependencies"];

pub(super) fn is_shard_yml(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "shard.yml" | "shard.yaml"))
}

pub(super) fn shard_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_yaml::from_str(text).context("sbom-scan: parse shard.yml")?;
    Ok(dependencies(&value)
        .map(|dependency| component(target, path, "crystal", dependency.scope, dependency.name, None))
        .collect())
}

pub(super) fn shard_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_yaml::from_str(&text).context("sbom-scan: parse shard.yml")?;
    let source = relative_display(target, path);
    Ok(dependencies(&value)
        .map(|dependency| SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency.name.to_string(),
            source: source.clone(),
        })
        .collect())
}

fn dependencies(value: &Value) -> impl Iterator<Item = ShardDependency<'_>> {
    DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| dependency_table(value, scope).into_iter().flat_map(move |table| table.keys().filter_map(move |key| dependency_name(scope, key))))
}

fn dependency_table<'a>(value: &'a Value, scope: &str) -> Option<&'a Mapping> {
    value
        .get(scope)
        .and_then(Value::as_mapping)
}

fn dependency_name<'a>(scope: &'a str, key: &'a Value) -> Option<ShardDependency<'a>> {
    key.as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| ShardDependency { scope, name })
}

struct ShardDependency<'a> {
    scope: &'a str,
    name: &'a str,
}
