use super::{component, relative_display, SbomComponent};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) use super::dependency_graph::is_cargo_lock;

pub(super) fn cargo_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse Cargo.lock")?;
    let source = relative_display(target, path);
    Ok(value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| cargo_package_component(target, path, &source, package))
        .collect())
}

fn cargo_package_component(
    target: &Path,
    path: &Path,
    source: &str,
    package: &toml::Value,
) -> Option<SbomComponent> {
    let name = package.get("name")?.as_str()?;
    let version = package.get("version").and_then(toml::Value::as_str);
    Some(component(target, path, "cargo", source, name, version))
}
