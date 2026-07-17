//! Kuzushi context boundary.
//!
//! Repository context is deterministic input for scanners, threat modeling,
//! recommender planning, and reports. It should remain free of LLM dispatch and
//! UI rendering concerns.

use std::path::{Path, PathBuf};

pub use crate::repository_inventory::*;
pub use crate::static_context::*;

pub const CONTEXT_SNAPSHOT_FILE: &str = "context-snapshot.json";

/// Maximum size of Kuzushi's canonical repository-context artifact.
///
/// Context snapshots intentionally carry inventory and attack-surface data and
/// can exceed ordinary prompt-source limits on large repositories. Producers
/// and consumers must share this artifact bound; prompt construction applies
/// its smaller, operator-configured limit after the JSON is parsed.
pub const MAX_CONTEXT_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

pub fn context_snapshot_path(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(CONTEXT_SNAPSHOT_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_snapshot_path_uses_workspace_state_root() {
        let target = Path::new("/repo");
        let state_root = crate::workspace::workspace_state_root(target);

        assert_eq!(
            context_snapshot_path(target),
            state_root.join(CONTEXT_SNAPSHOT_FILE)
        );
    }
}
