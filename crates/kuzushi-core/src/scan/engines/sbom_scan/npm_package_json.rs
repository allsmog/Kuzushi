use super::bounded_fs as fs;
use super::SbomInputs;
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

struct PackageDependency {
    name: String,
    version: String,
    scope: &'static str,
}

pub(super) fn package_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    Ok(package_dependencies(target, path, text)?
        .into_iter()
        .map(|entry| component(target, path, "npm", entry.scope, &entry.name, Some(&entry.version)))
        .collect())
}

pub(super) fn is_package_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "package.json")
}

pub(super) fn package_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(package_dependencies(target, path, &text)?
        .into_iter()
        .map(|entry| SbomDependencyEdge {
            from: "root".to_string(),
            to: entry.name,
            source: source.clone(),
        })
        .collect())
}

fn package_dependencies(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<PackageDependency>> {
    let path = path.strip_prefix(target).unwrap_or(path);
    let value: Value = serde_json::from_str(text)
        .with_context(|| format!("sbom-scan: parse {}", path.display()))?;
    let document = value.as_object().with_context(|| {
        format!("sbom-scan: {} must contain a JSON object", path.display())
    })?;
    let mut dependencies = Vec::new();
    for &scope in NPM_DEPENDENCY_SCOPES {
        append_scope_dependencies(document.get(scope), path, scope, &mut dependencies)?;
    }
    Ok(dependencies)
}

fn append_scope_dependencies(
    value: Option<&Value>,
    path: &Path,
    scope: &'static str,
    entries: &mut Vec<PackageDependency>,
) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    let dependencies = value.as_object().with_context(|| {
        format!("sbom-scan: {}: {scope} must be an object mapping package names to version specifications", path.display())
    })?;
    for (name, value) in dependencies {
        let version = json_dependency_version(value).with_context(|| {
            format!("sbom-scan: {}: {scope}.{name} needs a string specification or an object with a string version", path.display())
        })?;
        entries.push(PackageDependency {
            name: name.clone(),
            version: version.to_string(),
            scope,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;

fn json_dependency_version(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("version")?.as_str())
}
