use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

const GRADLE_DEPENDENCY_SCOPES: &[&str] = &[
    "api",
    "compileOnly",
    "implementation",
    "runtimeOnly",
    "testCompileOnly",
    "testImplementation",
    "testRuntimeOnly",
];

pub(super) fn is_gradle_build(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "build.gradle" | "build.gradle.kts"))
}

pub(super) fn gradle_build_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Vec<SbomComponent> {
    text.lines()
        .filter_map(gradle_dependency)
        .map(|dependency| {
            component(
                target,
                path,
                "maven",
                &dependency.scope,
                &dependency.name,
                dependency.version.as_deref(),
            )
        })
        .collect()
}

pub(super) fn gradle_build_edges(
    target: &SbomInputs,
    path: &Path,
) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(gradle_dependency)
        .map(|dependency| SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency.name,
            source: source.clone(),
        })
        .collect())
}

struct GradleDependency {
    name: String,
    version: Option<String>,
    scope: String,
}

fn gradle_dependency(line: &str) -> Option<GradleDependency> {
    let trimmed = line.trim();
    let scope = gradle_scope(trimmed)?;
    let (name, version) = gradle_coordinate_from_line(trimmed)?;
    Some(GradleDependency {
        name,
        version,
        scope: scope.to_string(),
    })
}

fn gradle_scope(line: &str) -> Option<&'static str> {
    GRADLE_DEPENDENCY_SCOPES
        .iter()
        .copied()
        .find(|scope| line_has_scope(line, scope))
}

fn line_has_scope(line: &str, scope: &str) -> bool {
    line.strip_prefix(scope)
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(|next| next.is_whitespace() || next == '(')
}

fn gradle_coordinate_from_line(line: &str) -> Option<(String, Option<String>)> {
    quoted_coordinate(line)
        .and_then(|coordinate| gradle_coordinate(&coordinate))
        .or_else(|| gradle_map_coordinate(line))
}

fn quoted_coordinate(line: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if let Some(value) = value_between_quotes(line, quote) {
            return Some(value.to_string());
        }
    }
    None
}

fn value_between_quotes(line: &str, quote: char) -> Option<&str> {
    let start = line.find(quote)? + quote.len_utf8();
    let end = line[start..].find(quote)? + start;
    Some(line[start..end].trim()).filter(|value| !value.is_empty())
}

fn gradle_coordinate(value: &str) -> Option<(String, Option<String>)> {
    let parts = value.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [group, artifact, version] => coordinate_parts(group, artifact, Some(*version)),
        [group, artifact] => coordinate_parts(group, artifact, None),
        _ => None,
    }
}

fn gradle_map_coordinate(line: &str) -> Option<(String, Option<String>)> {
    let group = gradle_named_value(line, "group")?;
    let artifact =
        gradle_named_value(line, "name").or_else(|| gradle_named_value(line, "artifact"))?;
    let version = gradle_named_value(line, "version");
    coordinate_parts(&group, &artifact, version.as_deref())
}

fn gradle_named_value(line: &str, key: &str) -> Option<String> {
    let (_, tail) = line.split_once(&format!("{key}:"))?;
    quoted_coordinate(tail)
}

fn coordinate_parts(
    group: &str,
    artifact: &str,
    version: Option<&str>,
) -> Option<(String, Option<String>)> {
    let group = group.trim();
    let artifact = artifact.trim();
    if group.is_empty() || artifact.is_empty() {
        return None;
    }
    Some((
        format!("{group}/{artifact}"),
        version
            .map(str::trim)
            .filter(|version| !version.is_empty())
            .map(str::to_string),
    ))
}
