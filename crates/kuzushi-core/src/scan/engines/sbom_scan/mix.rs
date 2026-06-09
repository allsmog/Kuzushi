use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) fn is_mix_exs(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "mix.exs")
}

pub(super) fn is_mix_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "mix.lock")
}

pub(super) fn mix_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    text.lines()
        .filter_map(mix_manifest_dependency)
        .map(|dependency| {
            component(
                target,
                path,
                "hex",
                &dependency.scope,
                &dependency.name,
                dependency.version.as_deref(),
            )
        })
        .collect()
}

pub(super) fn mix_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(mix_manifest_dependency)
        .map(|dependency| root_edge(dependency.name, &source))
        .collect())
}

pub(super) fn mix_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(mix_lock_entry)
        .flat_map(|entry| mix_lock_entry_edges(entry, &source))
        .collect())
}

pub(super) fn mix_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(mix_lock_entry)
        .map(|entry| entry.to_component(target, path, &source))
        .collect())
}

struct MixDependency {
    name: String,
    version: Option<String>,
    scope: String,
}

fn mix_manifest_dependency(line: &str) -> Option<MixDependency> {
    let trimmed = line.trim();
    let name = atom_after(trimmed, "{:")?;
    Some(MixDependency {
        name,
        version: quoted_values(trimmed).next(),
        scope: mix_scope(trimmed),
    })
}

fn mix_scope(line: &str) -> String {
    match line.split_once("only:") {
        Some((_, tail)) => atom_after(tail, ":")
            .map(|env| format!("deps.{env}"))
            .unwrap_or_else(|| "deps".to_string()),
        None => "deps".to_string(),
    }
}

struct MixLockEntry {
    name: String,
    version: Option<String>,
    dependencies: Vec<String>,
}

fn mix_lock_entry(line: &str) -> Option<MixLockEntry> {
    let mut quoted = quoted_values(line.trim());
    let name = quoted.next()?;
    let version = quoted.next();
    let dependencies = tuple_atoms(line)
        .into_iter()
        .filter(|dependency| dependency != "hex" && dependency != &name)
        .collect();
    Some(MixLockEntry {
        name,
        version,
        dependencies,
    })
}

fn mix_lock_entry_edges(entry: MixLockEntry, source: &str) -> Vec<SbomDependencyEdge> {
    let mut edges = vec![root_edge(entry.name.clone(), source)];
    edges.extend(
        entry
            .dependencies
            .into_iter()
            .map(|dependency| SbomDependencyEdge {
                from: entry.name.clone(),
                to: dependency,
                source: source.to_string(),
            }),
    );
    edges
}

impl MixLockEntry {
    fn to_component(&self, target: &Path, path: &Path, source: &str) -> SbomComponent {
        component(
            target,
            path,
            "hex",
            source,
            &self.name,
            self.version.as_deref(),
        )
    }
}

fn root_edge(to: String, source: &str) -> SbomDependencyEdge {
    SbomDependencyEdge {
        from: "root".to_string(),
        to,
        source: source.to_string(),
    }
}

fn tuple_atoms(line: &str) -> Vec<String> {
    line.split("{:")
        .skip(1)
        .filter_map(atom_name)
        .collect()
}

fn atom_after(line: &str, marker: &str) -> Option<String> {
    line.split_once(marker).and_then(|(_, tail)| atom_name(tail))
}

fn atom_name(value: &str) -> Option<String> {
    let name = value
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

fn quoted_values(line: &str) -> impl Iterator<Item = String> + '_ {
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
