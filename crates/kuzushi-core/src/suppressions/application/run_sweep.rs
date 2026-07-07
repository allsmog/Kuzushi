use super::effective_rules::effective_suppression_rules;
use super::reconcile_suppression_events::{reconcile_suppression_events, SuppressionReconcileSummary};
use crate::findings::FindingStore;
use crate::suppressions::domain::{evaluate_with_comment_diagnostics, SuppressionReport};
use crate::workspace::{load_program_scope, WorkspaceTarget};
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

/// Outcome of a suppression sweep: the freshly-evaluated report plus the
/// reconciliation delta applied to the event log.
pub struct SuppressionSweep {
    pub report: SuppressionReport,
    pub summary: SuppressionReconcileSummary,
}

/// Read-then-reconcile: load every stored finding, assemble the effective
/// rule set (file + scope + whitebox + in-source comments), evaluate against
/// the current clock, and append the lifecycle delta. Idempotent.
///
/// This is the shared sweep hook for scan-start and TUI target-load. The clock
/// is read here (adapter boundary); the domain evaluation stays pure.
pub fn run_suppression_sweep(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    actor: &str,
) -> Result<SuppressionSweep> {
    let now_unix = now_unix();
    let findings = store.list_findings(usize::MAX)?;
    let scope = load_program_scope(workspace)?;
    let effective = effective_suppression_rules(workspace, &findings, scope.as_ref())?;
    let report = evaluate_with_comment_diagnostics(
        &findings,
        &effective.rules,
        scope.as_ref(),
        now_unix,
        effective.malformed_comments,
    );
    let summary = reconcile_suppression_events(store, &report, actor)?;
    Ok(SuppressionSweep { report, summary })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
