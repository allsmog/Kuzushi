//! Fleet layer: multi-target aggregation under `~/.kuzushi/v3/fleet/`.
//!
//! Per-target `.kuzushi/v3` stores remain the immutable truth. Everything
//! here is derived and rebuildable: the corpus is torn down and rebuilt
//! from the per-target stores on every ingest, rows that fail the ingest
//! contract get counted `quality_flags` (never dropped or silently fixed),
//! and remote artifacts only ever enter through the local inbox.

mod corpus;
mod diff_findings;
mod registry;
mod status;
#[cfg(test)]
mod tests;

pub use corpus::{query_corpus_rows, rebuild_corpus, CorpusFindingRow, CorpusReport};
pub use diff_findings::{diff_findings, DiffFindingEntry, DiffFindingsReport, FindingLead};
pub use registry::{
    default_fleet_dir, load_fleet_targets, register_fleet_target, FleetTarget,
    FLEET_TARGETS_FILE,
};
pub use status::{fleet_status, FleetStatusReport, FleetTargetStatus};

use std::path::{Path, PathBuf};

pub const FLEET_DIR: &str = "fleet";
pub const FLEET_CORPUS_DB_FILE: &str = "corpus.sqlite3";

pub fn fleet_corpus_db_path(fleet_dir: &Path) -> PathBuf {
    fleet_dir.join(FLEET_CORPUS_DB_FILE)
}
