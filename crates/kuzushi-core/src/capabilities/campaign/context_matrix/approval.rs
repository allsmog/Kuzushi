//! Matrix approval reuses the shared finite-work ledger and prepared jobs.
use super::*;

pub(in crate::capabilities::campaign) fn review_for_approval(
    root: &Path,
    id: &str,
    plan: &Value,
    approval: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Option<BatchEquivalenceKey>> {
    if plan["kind"] != json!(CONTEXT_MATRIX_KIND) {
        return Ok(None);
    }
    let metadata = validate_context_matrix_plan(id, plan)?;
    anyhow::ensure!(
        approval["campaignJobs"] == plan["jobCount"],
        "Approved job count differs from the fixed context matrix"
    );
    for case in &metadata.cases {
        scope_comparison::validate_current_projection(root, case)?;
        super::super::scan_cases::review_case(root, case, approval, ctx, registry)?;
    }
    Ok(Some(metadata.baseline()?.equivalence.clone()))
}
