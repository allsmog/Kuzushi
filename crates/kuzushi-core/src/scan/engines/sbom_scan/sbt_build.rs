use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_sbt_build(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "build.sbt")
}

pub(super) fn sbt_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    let scala_binary = scala_binary_version(text);
    text.lines()
        .filter_map(|line| sbt_dependency(line, scala_binary.as_deref()))
        .map(|dependency| {
            component(
                target,
                path,
                "maven",
                &dependency.scope,
                &dependency.name,
                Some(&dependency.version),
            )
        })
        .collect()
}

pub(super) fn sbt_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let scala_binary = scala_binary_version(&text);
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(|line| sbt_dependency(line, scala_binary.as_deref()))
        .map(|dependency| SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency.name,
            source: source.clone(),
        })
        .collect())
}

struct SbtDependency {
    name: String,
    version: String,
    scope: String,
}

fn sbt_dependency(line: &str, scala_binary: Option<&str>) -> Option<SbtDependency> {
    let trimmed = line.trim();
    if !dependency_candidate(trimmed) {
        return None;
    }
    let values = quoted_values(trimmed);
    let [group, artifact, version, ..] = values.as_slice() else {
        return None;
    };
    let name = sbt_dependency_name(group, artifact, trimmed, scala_binary);
    Some(SbtDependency {
        name,
        version: version.to_string(),
        scope: sbt_scope(trimmed),
    })
}

fn dependency_candidate(line: &str) -> bool {
    line.contains("libraryDependencies") || line.starts_with('"')
}

fn sbt_dependency_name(
    group: &str,
    artifact: &str,
    line: &str,
    scala_binary: Option<&str>,
) -> String {
    let artifact = if line.contains("%%") {
        scala_binary
            .map(|version| format!("{artifact}_{version}"))
            .unwrap_or_else(|| artifact.to_string())
    } else {
        artifact.to_string()
    };
    format!("{group}/{artifact}")
}

fn sbt_scope(line: &str) -> String {
    if line.contains("% Test") || line.contains("% \"test\"") {
        return "libraryDependencies.test".to_string();
    }
    "libraryDependencies".to_string()
}

fn scala_binary_version(text: &str) -> Option<String> {
    text.lines()
        .find(|line| line.trim().starts_with("scalaVersion"))
        .and_then(|line| quoted_values(line).into_iter().next())
        .and_then(|version| {
            let mut parts = version.split('.');
            Some(format!("{}.{}", parts.next()?, parts.next()?))
        })
}

fn quoted_values(line: &str) -> Vec<String> {
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}
