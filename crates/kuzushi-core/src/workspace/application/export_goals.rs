//! Export every operator relevance revision, including clears and historical bases.
use super::export_projection_model::WorkspaceFindingExportRecord;
use super::*;

pub(super) fn attach_goals(
    store: &FindingStore,
    findings: &[Finding],
    records: &mut [WorkspaceFindingExportRecord],
) -> Result<()> {
    anyhow::ensure!(
        findings.len() == records.len(),
        "Goal export findings differ from records"
    );
    for (finding, record) in findings.iter().zip(records) {
        record.goal_assessments =
            store.finding_goal_history(finding.id.context("Goal export finding id is missing")?)?;
    }
    Ok(())
}
