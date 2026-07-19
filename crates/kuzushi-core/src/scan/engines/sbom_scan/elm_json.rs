use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(super) fn is_elm_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "elm.json")
}

pub(super) fn elm_components(target: &Path, path: &Path, text: &str) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_json::from_str(text).context("sbom-scan: parse elm.json")?;
    Ok(elm_dependency_scopes(&value)
        .into_iter()
        .flat_map(|(scope, dependencies)| dependency_components(target, path, scope, dependencies))
        .collect())
}

pub(super) fn elm_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse elm.json")?;
    let source = relative_display(target, path);
    Ok(elm_direct_dependency_names(&value)
        .into_iter()
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn dependency_components(
    target: &Path,
    path: &Path,
    scope: &str,
    dependencies: &serde_json::Map<String, Value>,
) -> Vec<SbomComponent> {
    dependencies
        .iter()
        .map(|(name, value)| component(target, path, "elm", scope, name, dependency_version(value)))
        .collect()
}

fn elm_dependency_scopes(value: &Value) -> Vec<(&'static str, &serde_json::Map<String, Value>)> {
    let mut scopes = Vec::new();
    collect_nested_scope(&mut scopes, value, "dependencies", "dependencies");
    collect_nested_scope(&mut scopes, value, "test-dependencies", "test-dependencies");
    scopes
}

fn collect_nested_scope<'a>(
    scopes: &mut Vec<(&'static str, &'a serde_json::Map<String, Value>)>,
    value: &'a Value,
    key: &'static str,
    scope: &'static str,
) {
    let Some(dependencies) = value.get(key).and_then(Value::as_object) else {
        return;
    };
    match (
        dependencies.get("direct").and_then(Value::as_object),
        dependencies.get("indirect").and_then(Value::as_object),
    ) {
        (Some(direct), indirect) => {
            scopes.push((concat_scope(scope, "direct"), direct));
            if let Some(indirect) = indirect {
                scopes.push((concat_scope(scope, "indirect"), indirect));
            }
        }
        _ => scopes.push((scope, dependencies)),
    }
}

fn concat_scope(scope: &'static str, kind: &'static str) -> &'static str {
    match (scope, kind) {
        ("dependencies", "direct") => "dependencies.direct",
        ("dependencies", "indirect") => "dependencies.indirect",
        ("test-dependencies", "direct") => "test-dependencies.direct",
        ("test-dependencies", "indirect") => "test-dependencies.indirect",
        _ => scope,
    }
}

fn elm_direct_dependency_names(value: &Value) -> Vec<String> {
    elm_dependency_scopes(value)
        .into_iter()
        .filter(|(scope, _)| !scope.ends_with(".indirect"))
        .flat_map(|(_, dependencies)| dependencies.keys())
        .map(|name| name.to_string())
        .collect()
}

fn dependency_version(value: &Value) -> Option<&str> {
    value
        .as_str()
        .map(str::trim)
        .filter(|version| !version.is_empty())
}
