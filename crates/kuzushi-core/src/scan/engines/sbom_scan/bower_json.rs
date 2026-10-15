use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

const BOWER_DEPENDENCY_SCOPES: &[&str] = &["dependencies", "devDependencies"];

pub(super) fn is_bower_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "bower.json")
}

pub(super) fn bower_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_json::from_str(text).context("sbom-scan: parse bower.json")?;
    Ok(dependencies(&value)
        .map(|dependency| {
            component(
                target,
                path,
                "bower",
                dependency.scope,
                dependency.name,
                dependency.version,
            )
        })
        .collect())
}

pub(super) fn bower_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse bower.json")?;
    let source = relative_display(target, path);
    Ok(dependencies(&value)
        .map(|dependency| SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency.name.to_string(),
            source: source.clone(),
        })
        .collect())
}

fn dependencies(value: &Value) -> impl Iterator<Item = BowerDependency<'_>> {
    BOWER_DEPENDENCY_SCOPES.iter().flat_map(|scope| {
        value
            .get(*scope)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(move |dependencies| {
                dependencies
                    .iter()
                    .filter_map(move |(name, value)| dependency(scope, name, value))
            })
    })
}

fn dependency<'a>(scope: &'a str, name: &'a str, value: &'a Value) -> Option<BowerDependency<'a>> {
    Some(BowerDependency {
        scope,
        name,
        version: dependency_version(value),
    })
}

fn dependency_version(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("version")?.as_str())
}

struct BowerDependency<'a> {
    scope: &'a str,
    name: &'a str,
    version: Option<&'a str>,
}
