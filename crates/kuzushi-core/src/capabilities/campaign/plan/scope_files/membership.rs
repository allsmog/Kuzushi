//! Literal, inventory-only membership. Scope roots never initiate filesystem IO.
use super::{ensure_active, CampaignShard, InventoryInspection, ToolExecutionContext};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

const MAX_SCOPE_MEMBERSHIPS: usize = 100_000;

pub(super) fn collect(
    inspection: &InventoryInspection,
    shards: &BTreeMap<String, &CampaignShard>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let files = inspection.files.iter().cloned().collect::<BTreeSet<_>>();
    let mut remaining = MAX_SCOPE_MEMBERSHIPS;
    let mut memberships = BTreeMap::new();
    for (name, shard) in shards {
        ensure_active(ctx)?;
        validate_shard_name(name)?;
        let members = shard_members(&files, shard, remaining, ctx)?;
        remaining -= members.len();
        memberships.insert(name.clone(), members);
    }
    Ok(memberships)
}

fn validate_shard_name(name: &str) -> Result<()> {
    let exact_component = matches!(Path::new(name).components().next(),
        Some(Component::Normal(part)) if part == std::ffi::OsStr::new(name));
    anyhow::ensure!(
        !name.chars().any(char::is_control) && exact_component,
        "shard name {name:?} must be one literal filename component"
    );
    Ok(())
}

fn shard_members(
    files: &BTreeSet<String>,
    shard: &CampaignShard,
    remaining: usize,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Vec<String>> {
    let mut selected = BTreeSet::new();
    for path in &shard.paths {
        let prefix = relative_prefix(path)?;
        let mut matches = matching_files(files, &prefix).peekable();
        anyhow::ensure!(matches.peek().is_some(),
            "shard {:?} path {path:?} matched no files in the bounded inventory; check missing or ignored paths", shard.name);
        for file in matches {
            ensure_active(ctx)?;
            anyhow::ensure!(
                !file.chars().any(char::is_control),
                "file {file:?} cannot be represented by a line-delimited scope file"
            );
            selected.insert(file.clone());
            anyhow::ensure!(selected.len() <= remaining,
                "scope-file memberships exceed {MAX_SCOPE_MEMBERSHIPS}; reduce overlapping shards before planning");
        }
    }
    Ok(selected.into_iter().collect())
}

fn relative_prefix(path: &str) -> Result<String> {
    anyhow::ensure!(!path.is_empty() && !path.chars().any(char::is_control),
        "scope path {path:?} must be a nonempty repository-relative path without control characters");
    let mut relative = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(value) => {
                relative.push(value.to_str().context("scope path is not valid UTF-8")?)
            }
            Component::CurDir => {}
            _ => anyhow::bail!(
                "scope path {path:?} must be repository-relative without parent traversal"
            ),
        }
    }
    Ok(relative.join("/"))
}

fn matching_files<'a>(
    files: &'a BTreeSet<String>,
    prefix: &str,
) -> Box<dyn Iterator<Item = &'a String> + 'a> {
    if prefix.is_empty() {
        return Box::new(files.iter());
    }
    if let Some(file) = files.get(prefix) {
        return Box::new(std::iter::once(file));
    }
    let directory = format!("{prefix}/");
    Box::new(
        files
            .range(directory.clone()..)
            .take_while(move |file| file.starts_with(&directory)),
    )
}
