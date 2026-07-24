use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_cpanfile(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "cpanfile")
}

pub(super) fn cpanfile_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    requirements(text)
        .into_iter()
        .map(|requirement| {
            component(
                target,
                path,
                "cpan",
                &requirement.scope,
                &requirement.name,
                requirement.version.as_deref(),
            )
        })
        .collect()
}

pub(super) fn cpanfile_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(requirements(&text)
        .into_iter()
        .map(|requirement| SbomDependencyEdge {
            from: "root".to_string(),
            to: requirement.name,
            source: source.clone(),
        })
        .collect())
}

fn requirements(text: &str) -> Vec<CpanRequirement> {
    text.lines().filter_map(parse_requirement).collect()
}

fn parse_requirement(line: &str) -> Option<CpanRequirement> {
    let line = line.split('#').next().unwrap_or(line).trim();
    let (scope, rest) = line.split_once(char::is_whitespace)?;
    if !scope.ends_with("requires") {
        return None;
    }
    let (name, rest) = quoted_value(rest)?;
    Some(CpanRequirement {
        scope: scope.to_string(),
        name: name.to_string(),
        version: requirement_version(rest),
    })
}

fn requirement_version(text: &str) -> Option<String> {
    quoted_value(text.split_once(',')?.1).map(|(version, _)| version.to_string())
}

fn quoted_value(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    let quote = text
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '"'))?;
    let rest = &text[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some((&rest[..end], &rest[end + quote.len_utf8()..]))
}

struct CpanRequirement {
    scope: String,
    name: String,
    version: Option<String>,
}
