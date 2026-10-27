//! Approved job input is already frozen. Saved options cannot expand it.
use super::*;
use crate::ToolOptionStore;

pub(in crate::modules) fn preparation_option_store<'a>(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    store: Option<&'a ToolOptionStore>,
) -> Result<Option<&'a ToolOptionStore>> {
    if store.is_none() {
        return Ok(None);
    }
    if authenticates_frozen_input(name, input, ctx)? {
        return Ok(None);
    }
    Ok(store)
}

/// This read claims no attempt or provider reservation. Dispatch still checks
/// the plan, current source/configuration, authorization and attempt allowance.
fn authenticates_frozen_input(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<bool> {
    let Some(reference) = reference(input)? else {
        return Ok(false);
    };
    let snapshot = open_ledger(ctx)?.allowance_snapshot(&reference.investigation_id)?;
    let Some(plan) = snapshot.work_plan else {
        return Ok(false);
    };
    anyhow::ensure!(
        snapshot.revision == reference.revision,
        "allowance revision changed; review remaining work"
    );
    let job = plan.job(&reference.work_id)?;
    anyhow::ensure!(
        job.tool == name
            && job.input_sha256 == crate::capabilities::campaign::work_input_digest(input)?,
        "job input or tool differs from the approved frozen work"
    );
    Ok(true)
}
