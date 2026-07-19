use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

const R_DEPENDENCY_FIELDS: &[&str] = &["Depends", "Imports", "Suggests", "LinkingTo"];

pub(super) fn is_r_description(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "DESCRIPTION")
}

pub(super) fn r_description_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Vec<SbomComponent> {
    parsed_fields(text)
        .into_iter()
        .filter(|(field, _)| R_DEPENDENCY_FIELDS.contains(&field.as_str()))
        .flat_map(|(field, value)| field_components(target, path, &field, &value))
        .collect()
}

pub(super) fn r_description_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(parsed_fields(&text)
        .into_iter()
        .filter(|(field, _)| R_DEPENDENCY_FIELDS.contains(&field.as_str()))
        .flat_map(|(_, value)| dependency_names(&value))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn field_components(target: &Path, path: &Path, field: &str, value: &str) -> Vec<SbomComponent> {
    dependency_names(value)
        .into_iter()
        .map(|name| component(target, path, "r", field, &name, None))
        .collect()
}

fn parsed_fields(text: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    for line in text.lines() {
        apply_description_line(&mut fields, line);
    }
    fields
}

fn apply_description_line(fields: &mut Vec<(String, String)>, line: &str) {
    if line.starts_with([' ', '\t']) {
        append_continuation(fields, line);
    } else if let Some((key, value)) = line.split_once(':') {
        fields.push((key.trim().to_string(), value.trim().to_string()));
    }
}

fn append_continuation(fields: &mut [(String, String)], line: &str) {
    if let Some((_, value)) = fields.last_mut() {
        value.push(' ');
        value.push_str(line.trim());
    }
}

fn dependency_names(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(dependency_name)
        .filter(|name| *name != "R")
        .map(str::to_string)
        .collect()
}

fn dependency_name(raw: &str) -> Option<&str> {
    raw.trim()
        .split([' ', '('])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}
