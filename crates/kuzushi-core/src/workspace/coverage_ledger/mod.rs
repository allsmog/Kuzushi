//! Historical scope/phase Git baseline records from completed run summaries.
//! These legacy rows do not identify exact source content, accepted context or
//! complete scan scope. A sweep compares tracked source and may add explicit
//! sweep-skip records; neither operation establishes coverage or a finding fix.

mod cancellation;
mod guards;
mod schema;
mod source_budget;
mod store;
mod summary_intake;
mod sweep;
#[cfg(test)]
mod tests;

pub use guards::{guard_conflict, GuardRow};
pub(crate) use source_budget::{SourceComparisonBudget, SourceComparisonLimits};
pub use store::{BaselineRow, CoverageLedger};
pub use summary_intake::record_baseline_from_summary;
pub use sweep::{
    sweep_target, write_sweep_skips, ScopeSweepEntry, SourceCheckIssue, SweepReport, SweepVerdict,
    SWEEP_RUN_ID,
};
pub(crate) use sweep::{sweep_target_with_budget, write_sweep_skips_with_budget};

use std::path::{Path, PathBuf};

pub const WORKSPACE_COVERAGE_DB_FILE: &str = "coverage.sqlite3";

/// Mode recorded when `sweep --write-skips` advances a baseline without a
/// scan because a whole-repo diff proved the scope unchanged.
pub const SWEEP_SKIP_MODE: &str = "sweep-skip";

pub fn workspace_coverage_db_path(root: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_dir(root).join(WORKSPACE_COVERAGE_DB_FILE)
}
