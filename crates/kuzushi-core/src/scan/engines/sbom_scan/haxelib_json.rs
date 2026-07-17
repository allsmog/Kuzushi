use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(super) fn is_haxelib_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "haxelib.json")
}

pub(super) fn haxelib_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let value: Value = serde_json::from_str(text).context("sbom-scan: parse haxelib.json")?;
    Ok(dependencies(&value)
        .map(|dependency| {
            component(
                target,
                path,
                "haxelib",
                "dependencies",
                dependency.name,
                dependency.version,
            )
        })
        .collect())
}

pub(super) fn haxelib_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse haxelib.json")?;
    let source = relative_display(target, path);
    Ok(dependencies(&value)
        .map(|dependency| SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency.name.to_string(),
            source: source.clone(),
        })
        .collect())
}

fn dependencies(value: &Value) -> impl Iterator<Item = HaxelibDependency<'_>> {
    value
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, value)| dependency(name, value))
}

fn dependency<'a>(name: &'a str, value: &'a Value) -> Option<HaxelibDependency<'a>> {
    Some(HaxelibDependency {
        name,
        version: value.as_str(),
    })
}

struct HaxelibDependency<'a> {
    name: &'a str,
    version: Option<&'a str>,
}
