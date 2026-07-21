//! Coverage ledger: the durable record of what was scanned, at which
//! revision, by which phase. Rows are written only from persisted run
//! summaries (receipt-backed truth), so coverage can never claim more than
//! the run artifacts prove. Sweep and the scan recommender read this store;
//! nothing else writes it.

mod guards;
mod schema;
mod store;
mod summary_intake;
mod sweep;
#[cfg(test)]
mod tests;

pub use guards::{guard_conflict, GuardRow};
pub use store::{BaselineRow, CoverageLedger};
pub use summary_intake::record_baseline_from_summary;
pub use sweep::{
    sweep_target, write_sweep_skips, ScopeSweepEntry, SweepReport, SweepVerdict, SWEEP_RUN_ID,
};

use std::path::{Path, PathBuf};

pub const WORKSPACE_COVERAGE_DB_FILE: &str = "coverage.sqlite3";

/// Mode recorded when `sweep --write-skips` advances a baseline without a
/// scan because a whole-repo diff proved the scope unchanged.
pub const SWEEP_SKIP_MODE: &str = "sweep-skip";

pub fn workspace_coverage_db_path(root: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_dir(root).join(WORKSPACE_COVERAGE_DB_FILE)
}
