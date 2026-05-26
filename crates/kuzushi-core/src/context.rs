//! Kuzushi context boundary.
//!
//! Repository context is deterministic input for scanners, threat modeling,
//! recommender planning, and reports. It should remain free of LLM dispatch and
//! UI rendering concerns.

use std::path::{Path, PathBuf};

pub use crate::repository_inventory::*;
pub use crate::static_context::*;

pub const CONTEXT_SNAPSHOT_FILE: &str = "context-snapshot.json";

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
