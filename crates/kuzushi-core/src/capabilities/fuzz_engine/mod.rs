//! Agentic-fuzz-engine (AFE) integration.
//!
//! AFE is an external Python fuzzing engine (libFuzzer + SymCC + KLEE rounds
//! with its own disk/RSS guards). Kuzushi drives it as a bounded subprocess:
//! `fuzz:run` bootstraps a workspace and runs campaign rounds, `fuzz:import`
//! folds the engine's verified crash ledger into the findings store, and
//! `fuzz:author` runs a bridge-driven agent loop that writes harnesses for
//! sink vectors the deterministic generators could not reach.
//!
//! The engine workspace lives OUTSIDE the scanned repository (it holds
//! gigabytes of corpus); the scanned repo is only ever read.

pub mod author;
pub mod bootstrap;
pub mod crash_location;
pub mod engine_cli;
pub mod import;
pub mod index_rows;
pub mod provision;
pub mod rounds;
pub mod severity;

use std::path::{Path, PathBuf};

/// Resolved locations one fuzz tool invocation operates on.
#[derive(Debug, Clone)]
pub struct FuzzPaths {
    /// AFE checkout (must contain `src/agentic_fuzz_engine/cli.py`).
    pub afe_repo: PathBuf,
    /// Python interpreter used to run the engine.
    pub python_bin: PathBuf,
    /// Engine workspace root (targets/, bin/, work/, generators/, data/).
    pub workspace_root: PathBuf,
    /// Engine state root (runs/, findings-index.jsonl); default `<ws>/data`.
    pub data_root: PathBuf,
    /// The scanned repository the engine reads sources from.
    pub source_dir: PathBuf,
}

impl FuzzPaths {
    pub fn data_root_for(workspace_root: &Path) -> PathBuf {
        workspace_root.join("data")
    }
}

/// Default engine workspace for a scanned target: an external per-target
/// directory keyed by the target's basename plus a path hash, so two
/// checkouts with the same basename never share corpus state.
pub fn derived_workspace_root(home: &Path, target_root: &Path) -> PathBuf {
    let name = target_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target");
    let hash = crate::identity::hash_parts(
        "fuzz-workspace",
        &[target_root.display().to_string().as_bytes()],
    );
    home.join(".cache/agentic-fuzz/kuzushi")
        .join(format!("{name}-{}", &hash.as_str()[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_workspace_root_is_stable_and_checkout_specific() {
        let home = Path::new("/home/op");
        let first = derived_workspace_root(home, Path::new("/repos/monorepo"));
        let again = derived_workspace_root(home, Path::new("/repos/monorepo"));
        let sibling = derived_workspace_root(home, Path::new("/other/monorepo"));

        assert_eq!(first, again);
        assert_ne!(first, sibling);
        assert!(first.starts_with("/home/op/.cache/agentic-fuzz/kuzushi"));
        assert!(first
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("monorepo-"));
    }
}
