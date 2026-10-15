//! `campaign:status` — the snapshot fold rendered as a tool result.

use super::snapshot::{campaign_ids, load_campaign_snapshot, CampaignSnapshot};
use super::string_input;
use crate::findings::{FindingStore, ReviewDecisionRecord};
use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

pub fn execute_campaign_status(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("campaign:status requires an active workspace target")?;
    let root = workspace.root();
    let (trend, trend_history) = workspace_trend_json(root, ctx);
    match string_input(input, &["campaignId", "campaign_id", "id"]) {
        Some(campaign_id) => single_campaign_status(root, &campaign_id, trend, trend_history),
        None => all_campaigns_status(root, trend, trend_history),
    }
}

/// Workspace-level trend (decisions span campaigns, so it is the same object
/// on every status shape). Without a findings store, decision counts fold
/// over zero records and only spend is populated. A store that is present
/// but unreadable is a different answer, and reports itself as one rather
/// than borrowing the empty ledger's numbers. Every status run also
/// records a deduped snapshot into `.kuzushi/trend-history.jsonl` (why the
/// tool policy is workspace-write) and carries the bounded history back as
/// `trendHistory`; a history write failure degrades to history-less status
/// rather than failing the read.
fn workspace_trend_json(root: &Path, ctx: &ToolExecutionContext<'_>) -> (Value, Value) {
    let read = ctx
        .findings_store
        .map(FindingStore::list_all_review_decisions);
    let metrics = super::trend::trend_metrics_from_ledger(
        decision_ledger(&read),
        super::trend::workspace_campaign_spend_report(root),
    );
    let _ = super::trend_history::record_trend_snapshot(root, &metrics);
    let history =
        super::trend_history::load_trend_history(root, super::trend_history::TREND_HISTORY_LIMIT);
    (
        super::trend::trend_json(&metrics),
        super::trend_history::history_json(&history),
    )
}

/// No store at all folds over an empty ledger, as it always has — there is
/// no database to have failed. Only a read that failed is unreadable.
fn decision_ledger(
    read: &Option<Result<Vec<ReviewDecisionRecord>>>,
) -> super::trend::DecisionLedger<'_> {
    match read {
        Some(Ok(records)) => super::trend::DecisionLedger::Read(records),
        Some(Err(_)) => super::trend::DecisionLedger::Unreadable,
        None => super::trend::DecisionLedger::Read(&[]),
    }
}

fn all_campaigns_status(root: &Path, trend: Value, trend_history: Value) -> Result<Value> {
    let mut rows = Vec::new();
    for campaign_id in campaign_ids(root)? {
        let snapshot = load_campaign_snapshot(root, &campaign_id)?;
        rows.push(json!({
            "campaignId": snapshot.campaign_id,
            "tool": snapshot.tool,
            "createdAtMs": snapshot.created_at_ms,
            "jobCount": snapshot.jobs.len(),
            "states": snapshot.state_counts(),
            "totalCostUsd": snapshot.total_cost_usd,
            "providerSpendUnresolved": snapshot.provider_spend_unresolved,
        }));
    }
    let output = format!("campaign:status found {} campaign(s)", rows.len());
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "campaigns": rows, "trend": trend, "trendHistory": trend_history,
            "historyWindow": super::trend_history::history_window_json() }),
    ))
}

fn single_campaign_status(
    root: &Path,
    campaign_id: &str,
    trend: Value,
    trend_history: Value,
) -> Result<Value> {
    let snapshot = load_campaign_snapshot(root, campaign_id)?;
    let counts = snapshot.state_counts();
    let plan_digest = super::campaign_plan_digest(root, campaign_id)?;
    let output = format!(
        "campaign {} — {} job(s): {}\nPlan digest: {}",
        campaign_id,
        snapshot.jobs.len(),
        counts_line(&counts),
        plan_digest,
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "campaignId": snapshot.campaign_id,
            "planPath": super::campaign_plan_path(root, campaign_id).display().to_string(),
            "planSha256": plan_digest,
            "tool": snapshot.tool,
            "createdAtMs": snapshot.created_at_ms,
            "pausedUntilMs": snapshot.paused_until_ms,
            "states": counts,
            "budgetUsd": snapshot.budget_usd,
            "jobBudgetUsd": snapshot.job_budget_usd,
            "fillGaps": snapshot.fill_gaps,
            "skippedCoveredCells": snapshot.skipped_covered_cells,
            "totalCostUsd": snapshot.total_cost_usd,
            "providerSpendUnresolved": snapshot.provider_spend_unresolved,
            "trend": trend,
            "trendHistory": trend_history,
            "historyWindow": super::trend_history::history_window_json(),
            "jobs": job_rows(root, &snapshot),
        }),
    ))
}

fn job_rows(root: &Path, snapshot: &CampaignSnapshot) -> Vec<Value> {
    snapshot
        .jobs
        .iter()
        .map(|job| {
            json!({
                "jobId": job.job_id,
                "displayLabel": job.display_label,
                "shard": job.shard,
                "threatId": job.threat_id,
                "priority": job.priority,
                "state": job.state,
                "attempts": job.attempts,
                "dispatches": job.dispatches,
                "exitCode": job.exit_code,
                "costUsd": job.cost_usd,
                "providerSpendUnresolved": job.provider_spend_unresolved,
                "findings": job.findings,
                "runId": job.run_id,
                "reason": job.reason,
                "doneSentinel": job.run_id.as_deref().map(|run| done_sentinel_present(root, run)),
            })
        })
        .collect()
}

fn done_sentinel_present(root: &Path, run_id: &str) -> bool {
    crate::workspace::workspace_state_dir(root)
        .join("runs")
        .join(run_id)
        .join("done.json")
        .exists()
}

fn counts_line(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "no jobs".to_string();
    }
    counts
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect::<Vec<_>>()
        .join(", ")
}
