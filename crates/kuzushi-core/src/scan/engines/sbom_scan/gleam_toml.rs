use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const GLEAM_DEPENDENCY_SCOPES: &[&str] = &["dependencies", "dev-dependencies"];

pub(super) fn is_gleam_toml(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "gleam.toml")
}

pub(super) fn gleam_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: toml::Value = toml::from_str(text).context("sbom-scan: parse gleam.toml")?;
    Ok(dependencies(&value)
        .map(|dependency| {
            component(
                target,
                path,
                "hex",
                dependency.scope,
                dependency.name,
                dependency.version,
            )
        })
        .collect())
}

pub(super) fn gleam_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse gleam.toml")?;
    let source = relative_display(target, path);
    Ok(dependencies(&value)
        .map(|dependency| SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency.name.to_string(),
            source: source.clone(),
        })
        .collect())
}

fn dependencies(value: &toml::Value) -> impl Iterator<Item = GleamDependency<'_>> {
    GLEAM_DEPENDENCY_SCOPES.iter().flat_map(|scope| {
        value
            .get(*scope)
            .and_then(toml::Value::as_table)
            .into_iter()
            .flat_map(move |dependencies| {
                dependencies
                    .iter()
                    .map(move |(name, value)| dependency(scope, name, value))
            })
    })
}

fn dependency<'a>(scope: &'a str, name: &'a str, value: &'a toml::Value) -> GleamDependency<'a> {
    GleamDependency {
        scope,
        name,
        version: value.as_str(),
    }
}

struct GleamDependency<'a> {
    scope: &'a str,
    name: &'a str,
    version: Option<&'a str>,
}
