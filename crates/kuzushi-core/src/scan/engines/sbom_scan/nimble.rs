use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_nimble_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "nimble")
}

pub(super) fn nimble_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    dependency_names(text)
        .into_iter()
        .map(|name| component(target, path, "nimble", "requires", &name, None))
        .collect()
}

pub(super) fn nimble_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(dependency_names(&text)
        .into_iter()
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn dependency_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(requires_args)
        .flat_map(quoted_values)
        .filter_map(package_name)
        .collect()
}

fn requires_args(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or(line).trim();
    line.strip_prefix("requires")
}

fn quoted_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = text;
    while let Some((value, remaining)) = quoted_value(rest) {
        values.push(value.to_string());
        rest = remaining;
    }
    values
}

fn quoted_value(text: &str) -> Option<(&str, &str)> {
    let quote_start = text.find('"')?;
    let rest = &text[quote_start + 1..];
    let quote_end = rest.find('"')?;
    Some((&rest[..quote_end], &rest[quote_end + 1..]))
}

fn package_name(value: String) -> Option<String> {
    let name = value
        .split([' ', '<', '>', '=', '~', '^'])
        .next()
        .unwrap_or_default()
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}
