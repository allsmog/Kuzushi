use anyhow::Result;

use super::build_dataset::build_review_yield_dataset;
use crate::review_yield::domain::CensusReport;
use crate::review_yield::persistence::ReviewYieldProjectionReader;
use crate::workspace::WorkspaceTarget;

/// Counts what the target's adjudication corpus contains without writing
/// anything. Runs the same build as the export and discards the rows, so a
/// census can never promise rows the export would not produce.
pub fn run_census(workspace: &WorkspaceTarget) -> Result<CensusReport> {
    let reader = ReviewYieldProjectionReader::open(workspace)?;
    Ok(build_review_yield_dataset(&reader, workspace)?.census)
}
