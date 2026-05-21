use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

const DEPENDENCY_BLOCKS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(super) fn is_bun_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "bun.lock")
}

pub(super) fn bun_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&strip_jsonc(&text)).context("sbom-scan: parse bun.lock")?;
    let source = relative_display(target, path);
    let mut edges = workspace_edges(&value, &source);
    edges.extend(package_edges(&value, &source));
    Ok(edges)
}

pub(super) fn bun_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&strip_jsonc(&text)).context("sbom-scan: parse bun.lock")?;
    let source = relative_display(target, path);
    Ok(value
        .get("packages")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.keys())
        .filter_map(|key| package_component(target, path, &source, key))
        .collect())
}

fn workspace_edges(value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    value
        .get("workspaces")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|workspaces| workspaces.values())
        .flat_map(|workspace| dependency_edges("root", workspace, source))
        .collect()
}

fn package_edges(value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    value
        .get("packages")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .flat_map(|(key, package)| package_dependency_edges(key, package, source))
        .collect()
}

fn package_component(target: &Path, path: &Path, source: &str, key: &str) -> Option<SbomComponent> {
    let (name, version) = package_parts(key)?;
    Some(component(target, path, "npm", source, &name, Some(&version)))
}

fn package_parts(key: &str) -> Option<(String, String)> {
    let at = key.rfind('@')?;
    let name = key.get(..at)?.trim();
    let version = key.get(at + 1..)?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn package_dependency_edges(key: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    let from = package_name(key);
    package_dependency_blocks(package)
        .into_iter()
        .flat_map(|block| dependency_edges(&from, block, source))
        .collect()
}

fn package_dependency_blocks(package: &Value) -> Vec<&Value> {
    match package {
        Value::Array(values) => values.iter().filter(|value| value.is_object()).collect(),
        Value::Object(_) => vec![package],
        _ => Vec::new(),
    }
}

fn dependency_edges(from: &str, value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    DEPENDENCY_BLOCKS
        .iter()
        .filter_map(|block| value.get(*block).and_then(Value::as_object))
        .flat_map(|dependencies| dependencies.keys())
        .map(|to| SbomDependencyEdge {
            from: from.to_string(),
            to: to.to_string(),
            source: source.to_string(),
        })
        .collect()
}

fn package_name(key: &str) -> String {
    if key.starts_with('@') {
        let at = key.rfind('@').unwrap_or(key.len());
        return key.get(..at).unwrap_or(key).to_string();
    }
    key.split('@').next().unwrap_or(key).to_string()
}

fn strip_jsonc(text: &str) -> String {
    remove_trailing_commas(&remove_json_comments(text))
}

fn remove_json_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            let was_escaped = escaped;
            escaped = ch == '\\' && !escaped;
            in_string = ch != '"' || was_escaped;
            output.push(ch);
        } else if ch == '"' {
            in_string = true;
            output.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            skip_line_comment(&mut chars);
        } else if ch == '/' && chars.peek() == Some(&'*') {
            skip_block_comment(&mut chars);
        } else {
            output.push(ch);
        }
    }
    output
}

fn skip_line_comment<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    chars.next();
    for ch in chars.by_ref() {
        if ch == '\n' {
            break;
        }
    }
}

fn skip_block_comment<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    chars.next();
    let mut previous = '\0';
    for ch in chars.by_ref() {
        if previous == '*' && ch == '/' {
            break;
        }
        previous = ch;
    }
}

fn remove_trailing_commas(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            let was_escaped = escaped;
            escaped = ch == '\\' && !escaped;
            in_string = ch != '"' || was_escaped;
        } else if ch == '"' {
            in_string = true;
        }
        if !in_string
            && ch == ','
            && next_non_whitespace(&mut chars).is_some_and(|next| matches!(next, ']' | '}'))
        {
            continue;
        }
        output.push(ch);
    }
    output
}

fn next_non_whitespace<I>(chars: &mut std::iter::Peekable<I>) -> Option<char>
where
    I: Iterator<Item = char>,
{
    while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
        chars.next();
    }
    chars.peek().copied()
}
