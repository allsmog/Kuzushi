use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Operator-owned cache policy. The byte limit includes SQLite pages; at most
/// half is admitted as response payload, leaving room for indexes and metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SemanticCacheLimits {
    pub max_bytes: u64,
    pub max_entries: u64,
}

impl Default for SemanticCacheLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_entries: 10_000,
        }
    }
}

impl SemanticCacheLimits {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (128 * 1024..=512 * 1024 * 1024).contains(&self.max_bytes),
            "semantic cache max_bytes must be between 128 KiB and 512 MiB"
        );
        anyhow::ensure!(
            (1..=100_000).contains(&self.max_entries),
            "semantic cache max_entries must be between 1 and 100000"
        );
        Ok(())
    }

    pub(super) fn admits(&self, entries: u64, bytes: u64) -> bool {
        entries <= self.max_entries && bytes <= self.max_bytes / 2
    }
}
