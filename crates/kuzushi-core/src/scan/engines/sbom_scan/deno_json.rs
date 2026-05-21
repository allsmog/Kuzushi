use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(super) fn is_deno_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_deno_import_manifest)
}

pub(super) fn deno_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value = parse_import_map(text)?;
    let mut components = dependency_components(target, path, &value);
    for import_map in referenced_import_maps(target, path, &value)? {
        components.extend(dependency_components(target, &import_map.path, &import_map.value));
    }
    Ok(components)
}

pub(super) fn deno_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value = parse_import_map(&text)?;
    let mut edges = dependency_edges(target, path, &value);
    for import_map in referenced_import_maps(target, path, &value)? {
        edges.extend(dependency_edges(target, &import_map.path, &import_map.value));
    }
    Ok(edges)
}

fn is_deno_import_manifest(name: &str) -> bool {
    matches!(name, "deno.json" | "import_map.json")
}

fn parse_import_map(text: &str) -> Result<Value> {
    serde_json::from_str(text).context("sbom-scan: parse Deno import map")
}

fn referenced_import_maps(
    target: &Path,
    config_path: &Path,
    value: &Value,
) -> Result<Vec<ReferencedImportMap>> {
    let Some(path) = local_import_map_path(config_path, value) else {
        return Ok(Vec::new());
    };
    if !is_inside_target(target, &path)? {
        return Ok(Vec::new());
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    Ok(vec![ReferencedImportMap {
        value: parse_import_map(&text)?,
        path,
    }])
}

fn local_import_map_path(config_path: &Path, value: &Value) -> Option<PathBuf> {
    let raw_path = value.get("importMap")?.as_str()?.trim();
    if raw_path.is_empty() || raw_path.contains("://") {
        return None;
    }
    Some(config_path.parent().unwrap_or_else(|| Path::new("")).join(raw_path))
}

fn is_inside_target(target: &Path, path: &Path) -> Result<bool> {
    let normalized_target = normalize_path(target);
    let normalized_path = normalize_path(path);
    if !normalized_path.starts_with(&normalized_target) {
        return Ok(false);
    }
    let canonical_target = target
        .canonicalize()
        .with_context(|| format!("sbom-scan: resolve {}", target.display()))?;
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("sbom-scan: resolve {}", path.display()))?;
    Ok(canonical_path.starts_with(canonical_target))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(_) | Component::Prefix(_) | Component::RootDir => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn dependency_components(target: &Path, path: &Path, value: &Value) -> Vec<SbomComponent> {
    import_dependencies(value)
        .into_iter()
        .map(|dependency| {
            component(
                target,
                path,
                dependency.ecosystem,
                &dependency.scope,
                &dependency.name,
                dependency.version.as_deref(),
            )
        })
        .collect()
}

fn dependency_edges(target: &Path, path: &Path, value: &Value) -> Vec<SbomDependencyEdge> {
    let source = relative_display(target, path);
    import_dependencies(value)
        .into_iter()
        .map(|dependency| SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency.name,
            source: source.clone(),
        })
        .collect()
}

fn import_dependencies(value: &Value) -> Vec<DenoDependency> {
    let mut dependencies = scope_dependencies("imports", value.get("imports"));
    dependencies.extend(scoped_import_dependencies(value));
    dependencies
}

fn scoped_import_dependencies(value: &Value) -> Vec<DenoDependency> {
    value
        .get("scopes")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|scopes| scopes.iter())
        .flat_map(|(scope, imports)| scope_dependencies(&format!("scopes.{scope}"), Some(imports)))
        .collect()
}

fn scope_dependencies(scope: &str, value: Option<&Value>) -> Vec<DenoDependency> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|imports| imports.values())
        .filter_map(Value::as_str)
        .filter_map(|value| import_dependency(scope, value))
        .collect()
}

fn import_dependency(scope: &str, value: &str) -> Option<DenoDependency> {
    let (ecosystem, specifier) = value
        .strip_prefix("npm:")
        .map(|specifier| ("npm", specifier))
        .or_else(|| value.strip_prefix("jsr:").map(|specifier| ("jsr", specifier)))?;
    package_specifier(specifier).map(|(name, version)| DenoDependency {
        ecosystem,
        scope: scope.to_string(),
        name,
        version,
    })
}

fn package_specifier(specifier: &str) -> Option<(String, Option<String>)> {
    if specifier.starts_with('@') {
        return scoped_package_specifier(specifier);
    }
    let package = specifier.split('/').next()?.trim();
    split_version(package)
}

fn scoped_package_specifier(specifier: &str) -> Option<(String, Option<String>)> {
    let mut segments = specifier.split('/');
    let scope = segments.next()?.trim();
    let package = segments.next()?.trim();
    let (package, version) = split_version(package)?;
    Some((format!("{scope}/{package}"), version))
}

fn split_version(value: &str) -> Option<(String, Option<String>)> {
    if value.is_empty() {
        return None;
    }
    let (name, version) = value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or((value, None), |(name, version)| (name, Some(version)));
    Some((name.to_string(), version.map(str::to_string)))
}

struct DenoDependency {
    ecosystem: &'static str,
    scope: String,
    name: String,
    version: Option<String>,
}

struct ReferencedImportMap {
    path: PathBuf,
    value: Value,
}
