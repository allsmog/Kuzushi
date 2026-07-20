//! Shard-manifest enumeration for campaign planning.
//!
//! Reads every `[shards.<name>]` table from `<root>/.kuzushi/shards.toml`.
//! Unlike the CLI's `--shard` resolution (one named shard into `sast:scan`
//! `paths`), planning needs the whole manifest to build the shard axis; a
//! workspace without a manifest plans one whole-workspace pseudo-shard.

use anyhow::{Context, Result};
use std::path::Path;

pub(super) const SHARD_MANIFEST_RELATIVE_PATH: &str = ".kuzushi/shards.toml";
pub(super) const WHOLE_WORKSPACE_SHARD: &str = "workspace";

#[derive(Debug, Clone, PartialEq)]
pub(super) struct CampaignShard {
    pub(super) name: String,
    /// Workspace-relative scope roots; empty means the whole workspace.
    pub(super) paths: Vec<String>,
}

impl CampaignShard {
    fn whole_workspace() -> Self {
        Self {
            name: WHOLE_WORKSPACE_SHARD.to_string(),
            paths: Vec::new(),
        }
    }
}

/// All manifest shards sorted by name, or the whole-workspace pseudo-shard
/// when no manifest exists. A present-but-malformed manifest is an error —
/// planning over a silently empty axis would misreport coverage.
pub(super) fn load_campaign_shards(root: &Path) -> Result<Vec<CampaignShard>> {
    let manifest_path = root.join(SHARD_MANIFEST_RELATIVE_PATH);
    if !manifest_path.exists() {
        return Ok(vec![CampaignShard::whole_workspace()]);
    }
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("Could not read {}", manifest_path.display()))?;
    let manifest = text
        .parse::<toml::Value>()
        .with_context(|| format!("{} is not valid TOML", manifest_path.display()))?;
    manifest_shards(&manifest, &manifest_path)
}

fn manifest_shards(manifest: &toml::Value, path: &Path) -> Result<Vec<CampaignShard>> {
    let tables = manifest
        .get("shards")
        .and_then(toml::Value::as_table)
        .with_context(|| format!("{} has no [shards.<name>] tables", path.display()))?;
    let mut shards = Vec::new();
    for (name, entry) in tables {
        shards.push(CampaignShard {
            name: name.clone(),
            paths: shard_paths(entry, name)?,
        });
    }
    shards.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(shards)
}

fn shard_paths(entry: &toml::Value, name: &str) -> Result<Vec<String>> {
    let paths = entry
        .get("paths")
        .and_then(toml::Value::as_array)
        .with_context(|| format!("shard {name:?} has no paths = [...] array"))?;
    let collected = paths
        .iter()
        .filter_map(toml::Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    anyhow::ensure!(!collected.is_empty(), "shard {name:?} has empty paths");
    Ok(collected)
}
