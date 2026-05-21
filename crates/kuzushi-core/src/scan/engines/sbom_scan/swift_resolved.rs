use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(super) fn is_swift_resolved(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Package.resolved")
}

pub(super) fn swift_resolved_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse Package.resolved")?;
    let source = relative_display(target, path);
    Ok(value
        .get("pins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(swift_pin_name)
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

pub(super) fn swift_resolved_components(
    target: &Path,
    path: &Path,
) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse Package.resolved")?;
    let source = relative_display(target, path);
    Ok(value
        .get("pins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|pin| swift_pin_component(target, path, &source, pin))
        .collect())
}

fn swift_pin_name(pin: &Value) -> Option<String> {
    pin.get("identity")
        .or_else(|| pin.get("package"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn swift_pin_component(
    target: &Path,
    path: &Path,
    source: &str,
    pin: &Value,
) -> Option<SbomComponent> {
    let name = swift_pin_name(pin)?;
    Some(component(
        target,
        path,
        "swift",
        source,
        &name,
        swift_pin_version(pin),
    ))
}

fn swift_pin_version(pin: &Value) -> Option<&str> {
    pin.get("state")?
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
}
