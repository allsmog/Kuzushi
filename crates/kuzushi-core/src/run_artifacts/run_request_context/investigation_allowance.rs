use super::*;
use crate::allowance::AllowanceSnapshot;

/// Inspect the shared ledger bound to recorded requests. This neither selects
/// unrelated target history nor grants work, and does not load scope artifacts.
pub fn load_investigation_allowance_for_runs(
    target: &Path,
    runs: &[String],
) -> Result<Option<AllowanceSnapshot>> {
    let workspace = WorkspaceTarget::new(target)?;
    let mut investigation = None;
    for run_id in runs {
        let input = authenticated_input(target, run_id)?;
        let (read, _) = allowance::read_allowance(&workspace, run_id, &input);
        let Some(context) = read.map_err(anyhow::Error::msg)? else {
            continue;
        };
        let id = context.reference.investigation_id;
        anyhow::ensure!(
            investigation
                .as_ref()
                .is_none_or(|selected| selected == &id),
            "Selected requests reference multiple investigation allowances"
        );
        investigation = Some(id);
    }
    investigation
        .map(|id| crate::SpendLimiter::read_allowance_snapshot(&workspace.findings_db_path(), &id))
        .transpose()
}
