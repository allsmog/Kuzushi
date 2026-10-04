//! Durable memoization for closed-world model calls.
//!
//! Only an attested, tool-free execution contract may reuse a response. The
//! indexed store has a hard page/entry quota and bounded incremental eviction.
//! Cache corruption and IO failures remain misses rather than scan failures.

use crate::identity::{hash_parts, Blake3Hash};
use anyhow::{Context, Result};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

mod database;
mod file_links;
mod legacy_cleanup;
mod limits;
mod maintenance;
pub use limits::SemanticCacheLimits;
pub use maintenance::CacheMaintenance;

mod execution_contract;
pub(crate) use execution_contract::execution_query_cache_key;

pub const SEMANTIC_CACHE_DIR: &str = "semantic-cache";

/// Anti-corruption read bound for one cached response. Structured outputs
/// are already bounded well below this at response time; anything larger
/// here is a damaged or foreign file.
pub const MAX_SEMANTIC_CACHE_ENTRY_BYTES: usize = 16 * 1024 * 1024;

/// Set `KUZUSHI_SEMANTIC_CACHE=off` (or `0`) to force every call live —
/// the escape hatch for debugging a suspected stale replay.
pub const SEMANTIC_CACHE_ENV: &str = "KUZUSHI_SEMANTIC_CACHE";

/// Expired entries never replay and are reclaimed incrementally.
pub const SEMANTIC_CACHE_RETENTION_DAYS: u64 = 14;
const MS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

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
    limits: SemanticCacheLimits,
    database: Arc<Mutex<Connection>>,
}

impl SemanticCache {
    /// Uses operator-owned policy; a target cannot raise its cache quota.
    pub fn open_for_target(target_root: impl AsRef<Path>) -> Option<Self> {
        if disabled_by_env() {
            return None;
        }
        let limits = crate::config::load_config_for_target(None)
            .ok()?
            .operator
            .semantic_cache;
        let root = crate::workspace::workspace_state_dir(target_root).join(SEMANTIC_CACHE_DIR);
        Self::open_at_with_limits(root, limits).ok()
    }

    pub fn open_at(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_at_with_limits(root, SemanticCacheLimits::default())
    }

    pub fn open_at_with_limits(
        root: impl AsRef<Path>,
        limits: SemanticCacheLimits,
    ) -> Result<Self> {
        limits.validate()?;
        let root = root.as_ref().to_path_buf();
        ensure_cache_directory(&root)?;
        let database = Arc::new(Mutex::new(database::open(&root, limits)?));
        let cache = Self {
            root,
            limits,
            database,
        };
        // The database remains usable if legacy cleanup fails. Its cursor is not
        // advanced and the next open retries; a maintenance caller sees the error.
        let _ = cache.maintain();
        Ok(cache)
    }

    pub fn get(&self, key: &Blake3Hash) -> Option<SemanticCacheEntry> {
        let connection = self.connection().ok()?;
        let cutoff = maintenance::retention_cutoff(crate::fs_atomic::now_ms());
        let body = database::read(&connection, key.as_str(), cutoff).ok()??;
        serde_json::from_slice(&body).ok()
    }

    pub fn put(&self, key: &Blake3Hash, entry: &SemanticCacheEntry) -> Result<()> {
        let body =
            kuzushi_mcp_common::server::bounded_json_bytes(entry, MAX_SEMANTIC_CACHE_ENTRY_BYTES)?
                .context("semantic cache entry exceeds its serialization limit")?;
        anyhow::ensure!(
            (body.len() as u64) <= self.limits.max_bytes / 2,
            "semantic cache entry exceeds its byte quota"
        );
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        database::remove(&transaction, key.as_str())?;
        let admitted = maintenance::make_room(&transaction, self.limits, body.len() as u64)?;
        if admitted {
            database::insert(&transaction, key.as_str(), entry.created_at_ms, &body)?;
        }
        transaction.commit()?;
        anyhow::ensure!(
            admitted,
            "semantic cache quota pressure; bounded eviction remains pending"
        );
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.database
            .lock()
            .map_err(|_| anyhow::anyhow!("semantic cache lock poisoned"))
    }
}

/// Legacy key constructor retained for compatibility with stored-entry tooling.
/// Runtime queries use the attested, versioned execution-contract key instead.
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
