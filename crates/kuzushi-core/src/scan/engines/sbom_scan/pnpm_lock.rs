use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

type Mapping = serde_json::Map<String, Value>;

pub(super) use super::dependency_graph::is_pnpm_lock;

const IMPORTER_DEPENDENCY_BLOCKS: &[&str] =
    &["dependencies", "devDependencies", "optionalDependencies"];
const PACKAGE_DEPENDENCY_BLOCKS: &[&str] =
    &["dependencies", "optionalDependencies", "peerDependencies"];

pub(super) fn pnpm_lock_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value = crate::yaml::parse_value(&text).context("sbom-scan: parse pnpm-lock.yaml")?;
    let source = relative_display(target, path);
    let mut edges = importer_edges(&value, &source);
    edges.extend(package_edges(&value, &source));
    Ok(edges)
}

pub(super) fn pnpm_lock_components(target: &SbomInputs, path: &Path) -> Result<Vec<SbomComponent>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value = crate::yaml::parse_value(&text).context("sbom-scan: parse pnpm-lock.yaml")?;
    let source = relative_display(target, path);
    let mut components = importer_components(target, path, &value, &source);
    components.extend(package_components(target, path, &value, &source));
    components.extend(package_dependency_components(target, path, &value, &source));
    Ok(components)
}

fn importer_edges(value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    mapping_child(value, "importers")
        .into_iter()
        .flat_map(|importers| importers.values())
        .flat_map(|importer| importer_dependency_edges(importer, source))
        .collect()
}

fn importer_dependency_edges(importer: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    IMPORTER_DEPENDENCY_BLOCKS
        .iter()
        .filter_map(|block| mapping_child(importer, block))
        .flat_map(|dependencies| dependencies.keys())
        .filter_map(|key| package_key(key))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to: to.to_string(),
            source: source.to_string(),
        })
        .collect()
}

fn importer_components(
    target: &Path,
    path: &Path,
    value: &Value,
    source: &str,
) -> Vec<SbomComponent> {
    mapping_child(value, "importers")
        .into_iter()
        .flat_map(|importers| importers.values())
        .flat_map(|importer| dependency_block_components(target, path, importer, source))
        .collect()
}

fn package_edges(value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    mapping_child(value, "packages")
        .into_iter()
        .flat_map(|packages| packages.iter())
        .flat_map(|(key, package)| package_dependency_edges(key, package, source))
        .collect()
}

fn package_components(
    target: &Path,
    path: &Path,
    value: &Value,
    source: &str,
) -> Vec<SbomComponent> {
    mapping_child(value, "packages")
        .into_iter()
        .flat_map(|packages| packages.keys())
        .filter_map(|key| package_key(key))
        .filter_map(pnpm_component_from_key)
        .map(|locked| locked.to_component(target, path, source))
        .collect()
}

fn package_dependency_components(
    target: &Path,
    path: &Path,
    value: &Value,
    source: &str,
) -> Vec<SbomComponent> {
    mapping_child(value, "packages")
        .into_iter()
        .flat_map(|packages| packages.values())
        .flat_map(|package| dependency_block_components(target, path, package, source))
        .collect()
}

fn package_dependency_edges(key: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    let Some(from) = package_key(key).map(pnpm_package_name) else {
        return Vec::new();
    };
    PACKAGE_DEPENDENCY_BLOCKS
        .iter()
        .filter_map(|block| mapping_child(package, block))
        .flat_map(|dependencies| dependencies.keys())
        .filter_map(|key| package_key(key))
        .map(|to| SbomDependencyEdge {
            from: from.clone(),
            to: to.to_string(),
            source: source.to_string(),
        })
        .collect()
}

fn dependency_block_components(
    target: &Path,
    path: &Path,
    value: &Value,
    source: &str,
) -> Vec<SbomComponent> {
    IMPORTER_DEPENDENCY_BLOCKS
        .iter()
        .filter_map(|block| mapping_child(value, block))
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(key, dependency)| locked_dependency(key, dependency))
        .map(|locked| locked.to_component(target, path, source))
        .collect()
}

fn locked_dependency(key: &str, dependency: &Value) -> Option<LockedPackage> {
    let name = package_key(key)?.to_string();
    let version = dependency_version(dependency)?;
    Some(LockedPackage { name, version })
}

fn dependency_version(dependency: &Value) -> Option<String> {
    dependency
        .as_str()
        .or_else(|| mapping_child_value(dependency, "version")?.as_str())
        .and_then(clean_version)
}

fn mapping_child_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    mapping(value)?.get(key)
}

fn mapping_child<'a>(value: &'a Value, key: &str) -> Option<&'a Mapping> {
    mapping(value)?.get(key).and_then(mapping)
}

fn mapping(value: &Value) -> Option<&Mapping> {
    value.as_object()
}

fn package_key(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn pnpm_package_name(key: &str) -> String {
    let key = key.trim_start_matches('/');
    if key.starts_with('@') {
        return scoped_package_name(key);
    }
    key.split('@').next().unwrap_or(key).to_string()
}

fn pnpm_component_from_key(key: &str) -> Option<LockedPackage> {
    let key = key.trim_start_matches('/');
    let at = key.rfind('@')?;
    let name = key.get(..at)?.to_string();
    let version = key.get(at + 1..).and_then(clean_version)?;
    Some(LockedPackage { name, version })
}

fn clean_version(version: &str) -> Option<String> {
    version
        .split('(')
        .next()
        .map(str::trim)
        .filter(|version| !version.is_empty() && !version.starts_with('^'))
        .map(str::to_string)
}

fn scoped_package_name(key: &str) -> String {
    let at = key.rfind('@').unwrap_or(key.len());
    key.get(..at).unwrap_or(key).to_string()
}

struct LockedPackage {
    name: String,
    version: String,
}

impl LockedPackage {
    fn to_component(&self, target: &Path, path: &Path, source: &str) -> SbomComponent {
        component(target, path, "npm", source, &self.name, Some(&self.version))
    }
}
