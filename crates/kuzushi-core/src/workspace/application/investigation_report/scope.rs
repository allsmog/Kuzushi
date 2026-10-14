//! Report the frozen boundary without treating current source as historical work.
use crate::workspace::{load_scan_scope_proposal, ScanScopeRef, ScanScopeReview, WorkspaceTarget};
use anyhow::{Context, Result};
use serde_json::Value;
mod context_guidance;
pub(super) use context_guidance::recorded_context_guidance;

pub(super) fn report_scope(workspace: &WorkspaceTarget, input: &Value) -> Result<Value> {
    let mut scope = scope_input(input);
    scope["contextGuidance"] = recorded_context_guidance(workspace, input);
    if let Some(value) = input.get("scanScopeRef") {
        let reference: ScanScopeRef = serde_json::from_value(value.clone())
            .context("study report has an invalid scanScopeRef")?;
        let proposal = accepted_proposal(workspace, &reference)?;
        scope["acceptedScopeProposal"] = serde_json::to_value(proposal)?;
    }
    Ok(scope)
}

fn scope_input(input: &Value) -> Value {
    let mut scope = serde_json::Map::new();
    for key in [
        "paths",
        "shard",
        "scope",
        "scopeFile",
        "since",
        "scanScopeRef",
        "includePatterns",
        "excludePatterns",
        "languages",
        "language",
        "severity",
        "taskMode",
        "tasks",
        "mode",
        "thinkingLevel",
    ] {
        if let Some(value) = input.get(key) {
            scope.insert(key.into(), value.clone());
        }
    }
    Value::Object(scope)
}

fn accepted_proposal(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeRef,
) -> Result<ScanScopeReview> {
    // Historical reads authenticate committed evidence but do not demand that
    // today's source still matches the source on which the boundary was accepted.
    let proposal = load_scan_scope_proposal(workspace, &reference.proposal)
        .context("study report's accepted scope evidence is unavailable")?;
    anyhow::ensure!(
        proposal.record.acceptance.is_some(),
        "study report scope was not accepted"
    );
    let members = proposal
        .coverage
        .discovery_members
        .get(&reference.scope_id)
        .context("study report scope has no discovery membership")?;
    anyhow::ensure!(
        members.total > 0,
        "study report scope has no discovery files"
    );
    Ok(proposal)
}
