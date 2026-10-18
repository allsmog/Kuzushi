//! Recover investigation accounting from accepted, source-bound Map evidence.
use super::*;
use crate::allowance::AllowanceSnapshot;

/// Legacy results without accounting provenance remain unbound. A recorded
/// reference with missing accounting fails instead of starting fresh spending.
pub fn load_accepted_map_allowance(root: &Path) -> Result<Option<AllowanceSnapshot>> {
    allowance_from_context(
        root,
        crate::workflow_attempts::accepted_map_run_context(root)?,
    )
}

/// Preparing a replacement Map may retain authenticated historical accounting.
/// Source drift still blocks ordinary scan continuation and plan execution.
pub fn load_selected_map_history_allowance(root: &Path) -> Result<Option<AllowanceSnapshot>> {
    allowance_from_context(
        root,
        crate::workflow_attempts::selected_map_history_run_context(root)?,
    )
}

/// Explicit diagram follow-ups retain the accounting of their displayed Map runs.
pub fn load_map_run_allowance(root: &Path, runs: &[String]) -> Result<Option<AllowanceSnapshot>> {
    allowance_from_context(
        root,
        crate::workflow_attempts::load_map_run_context(root, runs)?,
    )
}

fn allowance_from_context(
    root: &Path,
    context: Option<crate::workflow_attempts::MapRunContext>,
) -> Result<Option<AllowanceSnapshot>> {
    let reference = context.and_then(|context| context.allowance_ref);
    let Some(reference) = reference else {
        return Ok(None);
    };
    let snapshot =
        super::study_receipt::load_investigation_allowance(root, &reference.investigation_id)?
            .context(
                "Accepted Map investigation accounting is missing; restore it before planning work",
            )?;
    anyhow::ensure!(
        snapshot.revision >= reference.revision,
        "Accepted Map allowance is newer than its accounting ledger; restore the current ledger"
    );
    Ok(Some(snapshot))
}

pub(super) fn study_investigation(
    input: &Value,
    root: &Path,
    scan_input: &Value,
) -> Result<Option<String>> {
    if let Some(id) = string_input(input, &["investigationId"]) {
        return Ok(Some(id));
    }
    if let Some(value) = scan_input.get("scanScopeRef") {
        let reference: crate::workspace::ScanScopeRef = serde_json::from_value(value.clone())?;
        if let Some(snapshot) = super::load_scope_proposal_allowance(root, &reference.proposal)? {
            return Ok(Some(snapshot.investigation_id));
        }
    }
    // Context preparation already requires current Map or an explicit context
    // choice. Spending remains historical across source changes, and this new
    // finite plan still needs its own approval before execution.
    Ok(load_selected_map_history_allowance(root)?.map(|snapshot| snapshot.investigation_id))
}
