use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn is_deno_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "deno.lock")
}

pub(super) fn deno_lock_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse deno.lock")?;
    let source = relative_display(target, path);
    Ok(dependency_edges(&value)
        .into_iter()
        .map(|(from, to)| SbomDependencyEdge {
            from,
            to,
            source: source.clone(),
        })
        .collect())
}

pub(super) fn deno_lock_components(target: &SbomInputs, path: &Path) -> Result<Vec<SbomComponent>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse deno.lock")?;
    let source = relative_display(target, path);
    let mut components = package_components(target, path, "jsr", &source, value.get("jsr"));
    components.extend(package_components(
        target,
        path,
        "npm",
        &source,
        value.get("npm"),
    ));
    Ok(components)
}

fn dependency_edges(value: &Value) -> BTreeSet<(String, String)> {
    let mut edges = BTreeSet::new();
    extend_package_edges(value.get("jsr"), "jsr", &mut edges);
    extend_package_edges(value.get("npm"), "npm", &mut edges);
    edges
}

fn package_components(
    target: &Path,
    path: &Path,
    ecosystem: &str,
    source: &str,
    packages: Option<&Value>,
) -> Vec<SbomComponent> {
    packages
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(raw_name, _)| package_component(target, path, ecosystem, source, raw_name))
        .collect()
}

fn package_component(
    target: &Path,
    path: &Path,
    ecosystem: &str,
    source: &str,
    raw_name: &str,
) -> Option<SbomComponent> {
    let (name, version) = split_version(raw_name)?;
    Some(component(
        target,
        path,
        ecosystem,
        source,
        &name,
        version.as_deref(),
    ))
}

fn extend_package_edges(
    packages: Option<&Value>,
    ecosystem: &str,
    edges: &mut BTreeSet<(String, String)>,
) {
    for (raw_name, metadata) in packages.and_then(Value::as_object).into_iter().flatten() {
        let Some(package_name) = package_name(raw_name) else {
            continue;
        };
        edges.insert(("root".to_string(), package_name.clone()));
        extend_transitive_edges(&package_name, ecosystem, metadata, edges);
    }
}

fn extend_transitive_edges(
    package_name: &str,
    ecosystem: &str,
    metadata: &Value,
    edges: &mut BTreeSet<(String, String)>,
) {
    for dependency in metadata
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|dependency| dependency_name(ecosystem, dependency))
    {
        edges.insert((package_name.to_string(), dependency));
    }
}

fn dependency_name(ecosystem: &str, value: &str) -> Option<String> {
    if let Some(specifier) = value
        .strip_prefix("npm:")
        .or_else(|| value.strip_prefix("jsr:"))
    {
        return specifier_package_name(specifier);
    }
    if ecosystem == "npm" {
        return specifier_package_name(value);
    }
    None
}

fn package_name(value: &str) -> Option<String> {
    let (name, _) = split_version(value)?;
    Some(name)
}

fn specifier_package_name(value: &str) -> Option<String> {
    package_name(&specifier_package(value))
}

fn specifier_package(value: &str) -> String {
    let segment_count = if value.starts_with('@') { 2 } else { 1 };
    value
        .split('/')
        .take(segment_count)
        .collect::<Vec<_>>()
        .join("/")
}

fn split_version(value: &str) -> Option<(String, Option<String>)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (name, version) = trimmed
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or((trimmed, None), |(name, version)| (name, Some(version)));
    Some((name.to_string(), version.map(str::to_string)))
}
