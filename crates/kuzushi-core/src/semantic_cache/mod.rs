//! Durable memoization for closed-world model calls.
//!
//! A closed-world call embeds everything the model may consult in the
//! request itself — system prompt, user prompt, and output schema — with no
//! tools, MCPs, or filesystem access. For those calls the response is a
//! function of nothing but the request bytes, so replaying a stored response
//! is semantically equivalent to paying for the call again. The cache key is
//! a Blake3 hash over every request ingredient; an edited source file, a
//! revised prompt, a migrated schema, or a different model each produce a
//! different key and therefore a live call.
//!
//! The cache is strictly best-effort: corruption, permission trouble, or a
//! validator that no longer accepts a stored value all degrade to a live
//! call, never to a failed scan.

use crate::identity::{hash_parts, Blake3Hash};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const SEMANTIC_CACHE_DIR: &str = "semantic-cache";

/// Anti-corruption read bound for one cached response. Structured outputs
/// are already bounded well below this at response time; anything larger
/// here is a damaged or foreign file.
pub const MAX_SEMANTIC_CACHE_ENTRY_BYTES: usize = 16 * 1024 * 1024;

/// Set `KUZUSHI_SEMANTIC_CACHE=off` (or `0`) to force every call live —
/// the escape hatch for debugging a suspected stale replay.
pub const SEMANTIC_CACHE_ENV: &str = "KUZUSHI_SEMANTIC_CACHE";

/// Entries older than this are dropped by the retention pass so the store
/// cannot grow without bound. An entry only replays while its exact prompt
/// (and therefore the file content inside it) is unchanged, so re-paying a
/// call once per retention window is the whole cost of expiry.
pub const SEMANTIC_CACHE_RETENTION_DAYS: u64 = 14;

const MS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

/// Root-level stamp recording when the retention pass last walked the
/// store, so opening a cache is O(1) except at most once a day.
const PRUNE_STAMP_FILE: &str = "last-prune-at-ms";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCacheEntry {
    /// Contract tool name of the producing call (e.g. `full-mode-multi:chunk`).
    pub task: String,
    pub model: String,
    pub created_at_ms: u64,
    /// Observed provider cost of the original live call, so replays can
    /// report what they saved.
    pub source_cost_usd: f64,
    /// The structured JSON value the original call produced, stored before
    /// task-specific parsing so a hit replays through the caller's current
    /// validator.
    pub value: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct SemanticCache {
    root: PathBuf,
}

impl SemanticCache {
    /// Opens the target's cache under `.kuzushi/v3/semantic-cache`. Returns
    /// `None` when disabled via [`SEMANTIC_CACHE_ENV`] or when the directory
    /// cannot be prepared — callers treat `None` as "every call goes live".
    pub fn open_for_target(target_root: impl AsRef<Path>) -> Option<Self> {
        if disabled_by_env() {
            return None;
        }
        let root = crate::workspace::workspace_state_dir(target_root).join(SEMANTIC_CACHE_DIR);
        ensure_cache_directory(&root).ok()?;
        let cache = Self { root };
        cache.prune_if_due(crate::fs_atomic::now_ms());
        Some(cache)
    }

    /// Test/bench constructor bypassing the workspace layout and env gate.
    pub fn open_at(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        ensure_cache_directory(&root)?;
        Ok(Self { root })
    }

    /// Returns the stored entry for `key`, or `None` for a miss. Corrupt or
    /// unreadable entries are misses, not errors: the cache must never make
    /// a scan fail that would have succeeded live.
    pub fn get(&self, key: &Blake3Hash) -> Option<SemanticCacheEntry> {
        let text = crate::bounded_file::read_utf8_text(
            &self.entry_path(key),
            MAX_SEMANTIC_CACHE_ENTRY_BYTES,
        )
        .ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn put(&self, key: &Blake3Hash, entry: &SemanticCacheEntry) -> Result<()> {
        let body = serde_json::to_string(entry).context("Could not serialize cache entry")?;
        let path = self.entry_path(key);
        if let Some(shard) = path.parent() {
            ensure_cache_directory(shard)?;
        }
        crate::fs_atomic::write_atomic(&path, &body)
    }

    fn entry_path(&self, key: &Blake3Hash) -> PathBuf {
        let hex = key.as_str();
        self.root.join(&hex[0..2]).join(format!("{hex}.json"))
    }

    /// Runs the retention pass when the last one is over a day old. Like
    /// every other cache path this is best-effort: prune trouble leaves
    /// entries behind, never fails an open.
    fn prune_if_due(&self, now_ms: u64) {
        if !self.prune_due(now_ms) {
            return;
        }
        let _ =
            crate::fs_atomic::write_atomic(&self.root.join(PRUNE_STAMP_FILE), &now_ms.to_string());
        self.prune_entries_older_than(
            now_ms.saturating_sub(SEMANTIC_CACHE_RETENTION_DAYS * MS_PER_DAY),
        );
    }

    fn prune_due(&self, now_ms: u64) -> bool {
        let Ok(text) = fs::read_to_string(self.root.join(PRUNE_STAMP_FILE)) else {
            return true;
        };
        text.trim()
            .parse::<u64>()
            .map(|last| now_ms.saturating_sub(last) >= MS_PER_DAY)
            .unwrap_or(true)
    }

    fn prune_entries_older_than(&self, cutoff_ms: u64) {
        let Ok(shards) = fs::read_dir(&self.root) else {
            return;
        };
        for shard in shards.flatten() {
            prune_shard(&shard.path(), cutoff_ms);
        }
    }
}

fn prune_shard(shard: &Path, cutoff_ms: u64) {
    let Ok(metadata) = fs::symlink_metadata(shard) else {
        return;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return;
    }
    let Ok(files) = fs::read_dir(shard) else {
        return;
    };
    for file in files.flatten() {
        prune_entry_file(&file.path(), cutoff_ms);
    }
    // Only succeeds once the shard emptied; `put` recreates shards on demand.
    let _ = fs::remove_dir(shard);
}

fn prune_entry_file(path: &Path, cutoff_ms: u64) {
    if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
        return;
    }
    let created_at_ms = crate::bounded_file::read_utf8_text(path, MAX_SEMANTIC_CACHE_ENTRY_BYTES)
        .ok()
        .and_then(|text| serde_json::from_str::<SemanticCacheEntry>(&text).ok())
        .map(|entry| entry.created_at_ms);
    // An unreadable or corrupt entry can never replay; drop it with the stale.
    if created_at_ms.map_or(true, |created| created < cutoff_ms) {
        let _ = fs::remove_file(path);
    }
}

/// Cache key for a one-shot structured query: every ingredient that could
/// change the response participates, so equal keys imply an equivalent call.
pub fn structured_query_cache_key(
    model: &str,
    system_prompt: &str,
    prompt: &str,
    schema_name: &str,
    schema: &serde_json::Value,
) -> Blake3Hash {
    let schema = schema.to_string();
    hash_parts(
        "semantic-cache:structured-query",
        &[
            model.as_bytes(),
            system_prompt.as_bytes(),
            prompt.as_bytes(),
            schema_name.as_bytes(),
            schema.as_bytes(),
        ],
    )
}

pub fn cache_entry_now(
    task: impl Into<String>,
    model: impl Into<String>,
    source_cost_usd: f64,
    value: serde_json::Value,
) -> SemanticCacheEntry {
    SemanticCacheEntry {
        task: task.into(),
        model: model.into(),
        created_at_ms: crate::fs_atomic::now_ms(),
        source_cost_usd,
        value,
    }
}

fn disabled_by_env() -> bool {
    matches!(
        std::env::var(SEMANTIC_CACHE_ENV).ok().as_deref(),
        Some("off") | Some("0") | Some("false")
    )
}

/// The cache root and its shards must be real directories: a symlinked
/// component would let a prepared workspace redirect cache writes outside
/// the state dir.
fn ensure_cache_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
            "semantic cache directory must not be a symlink: {}",
            path.display()
        ),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("semantic cache path is not a directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|parent| *parent != path) {
                ensure_cache_directory(parent)?;
            }
            match fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_cache_directory(path)
                }
                Err(error) => Err(error).with_context(|| {
                    format!("Could not create semantic cache under {}", path.display())
                }),
            }
        }
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

#[cfg(test)]
mod tests;
