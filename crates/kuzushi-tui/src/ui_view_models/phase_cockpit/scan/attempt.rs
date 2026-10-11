use crate::app::finding_delta_in_ledger_unit;
use crate::ui_view_models::{ScanAttemptModel, ScanEngineOutcomeModel};
use crate::{ShellApp, ViewDataState};
use kuzushi_core::run_artifacts::{PhaseStageReceipt, ScanEngineStageOutcome};
use kuzushi_core::workflow_attempts::{
    PhaseAttemptOutcome, PhaseAttemptRecord, PhaseTargetSnapshot,
};
use kuzushi_core::RunSummary;

pub(super) fn scan_attempt_from_stage(
    app: &ShellApp,
    record: &PhaseAttemptRecord,
    disposition: &str,
    receipt: &PhaseStageReceipt,
) -> Option<ScanAttemptModel> {
    let scan = receipt.scan.as_ref()?;
    let findings = scan
        .finding_delta
        .added
        .saturating_add(scan.finding_delta.updated);
    let run_refs = typed_run_refs(receipt, record);
    let facts = app.attempt_finding_facts(&run_refs, Some(findings));
    let (findings_added, findings_updated) = finding_delta_in_ledger_unit(
        facts.count,
        scan.finding_delta.added,
        scan.finding_delta.updated,
    );
    Some(ScanAttemptModel {
        attempt_id: Some(record.completed.attempt_id.clone()),
        run_id: typed_run_id(receipt, record),
        run_refs,
        outcome: attempt_outcome_label(record.completed.outcome).to_string(),
        disposition: disposition.to_string(),
        freshness: attempt_freshness(app, &scan.target_snapshot),
        findings: facts.count,
        findings_observed: facts.observed,
        findings_added,
        findings_updated,
        severity_counts: typed_severity_counts(scan, facts.severity_counts),
        artifact_count: scan.artifact_delta.len(),
        artifact_paths: typed_artifact_paths(scan),
        duration_secs: Some(scan.duration_ms.saturating_add(999) / 1_000),
        cost_usd: scan.cost.map(|cost| cost.observed_usd),
        cost_complete: scan.cost.map(|cost| cost.complete),
        error: typed_scan_error(scan),
    })
}

fn typed_severity_counts(
    scan: &kuzushi_core::run_artifacts::ScanStageData,
    ledger: Vec<(String, u64)>,
) -> Vec<(String, u64)> {
    if !ledger.is_empty() {
        return ledger;
    }
    scan.severity_counts
        .iter()
        .map(|bucket| (bucket.severity.as_str().to_string(), bucket.count))
        .collect()
}

fn typed_run_id(receipt: &PhaseStageReceipt, record: &PhaseAttemptRecord) -> String {
    match receipt.run_refs.first() {
        Some(run_ref) => run_ref.clone(),
        None => leading_run_ref(&record.completed.run_refs),
    }
}

/// The run an attempt is named by, or an honest placeholder when it recorded
/// none — never a blank that reads as a run id.
fn leading_run_ref(run_refs: &[String]) -> String {
    run_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "run reference missing".to_string())
}

fn typed_run_refs(receipt: &PhaseStageReceipt, record: &PhaseAttemptRecord) -> Vec<String> {
    let mut refs = record.completed.run_refs.clone();
    for run_ref in &receipt.run_refs {
        if !refs.contains(run_ref) {
            refs.push(run_ref.clone());
        }
    }
    refs
}

fn typed_artifact_paths(scan: &kuzushi_core::run_artifacts::ScanStageData) -> Vec<String> {
    scan.artifact_delta
        .iter()
        .map(|artifact| format!("{}:{}", artifact.run_ref, artifact.path))
        .collect()
}

fn typed_scan_error(scan: &kuzushi_core::run_artifacts::ScanStageData) -> Option<String> {
    scan.engines
        .iter()
        .find(|engine| engine.outcome == ScanEngineStageOutcome::Failed)
        .and_then(|engine| engine.detail.clone())
}

pub(super) fn scan_attempt_from_record(
    app: &ShellApp,
    record: &PhaseAttemptRecord,
    disposition: &str,
    summaries: &[&RunSummary],
) -> ScanAttemptModel {
    let run_id = leading_run_ref(&record.completed.run_refs);
    let (cost_usd, cost_complete) = summed_recorded_cost(summaries);
    let findings =
        app.attempt_finding_facts(&record.completed.run_refs, sum_recorded_findings(summaries));
    ScanAttemptModel {
        attempt_id: Some(record.completed.attempt_id.clone()),
        run_id,
        run_refs: record.completed.run_refs.clone(),
        outcome: attempt_outcome_label(record.completed.outcome).to_string(),
        disposition: disposition.to_string(),
        freshness: attempt_freshness(app, &record.completed.target_snapshot),
        findings: findings.count,
        findings_observed: findings.observed,
        findings_added: None,
        findings_updated: None,
        severity_counts: findings.severity_counts,
        artifact_count: summaries
            .iter()
            .map(|summary| summary.artifacts.len())
            .sum(),
        artifact_paths: Vec::new(),
        duration_secs: sum_recorded_durations(summaries),
        cost_usd,
        cost_complete,
        error: summaries.iter().find_map(|summary| summary.error.clone()),
    }
}

pub(super) fn scan_attempt_from_legacy_summary(
    app: &ShellApp,
    summary: &RunSummary,
) -> ScanAttemptModel {
    let findings =
        app.attempt_finding_facts(std::slice::from_ref(&summary.run_id), summary.findings);
    ScanAttemptModel {
        attempt_id: None,
        run_id: summary.run_id.clone(),
        run_refs: vec![summary.run_id.clone()],
        outcome: normalized_outcome(&summary.status),
        disposition: "legacy inferred".to_string(),
        freshness: scan_freshness(app, summary),
        findings: findings.count,
        findings_observed: findings.observed,
        findings_added: None,
        findings_updated: None,
        severity_counts: findings.severity_counts,
        artifact_count: summary.artifacts.len(),
        artifact_paths: Vec::new(),
        duration_secs: summary
            .completed_at_unix
            .map(|completed| completed.saturating_sub(summary.started_at_unix)),
        cost_usd: summary.cost_usd.or(summary.observed_cost_usd),
        cost_complete: summary
            .cost_usd
            .map(|_| true)
            .or_else(|| summary.observed_cost_usd.map(|_| false)),
        error: summary.error.clone(),
    }
}

fn sum_recorded_findings(summaries: &[&RunSummary]) -> Option<u64> {
    let values = summaries
        .iter()
        .filter_map(|summary| summary.findings)
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.into_iter().sum())
}

fn sum_recorded_durations(summaries: &[&RunSummary]) -> Option<u64> {
    let values = summaries
        .iter()
        .filter_map(|summary| {
            summary
                .completed_at_unix
                .map(|completed| completed.saturating_sub(summary.started_at_unix))
        })
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.into_iter().sum())
}

fn summed_recorded_cost(summaries: &[&RunSummary]) -> (Option<f64>, Option<bool>) {
    let values = summaries
        .iter()
        .filter_map(|summary| summary.cost_usd.or(summary.observed_cost_usd))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return (None, None);
    }
    let total = values.into_iter().sum::<f64>() + 0.0;
    let complete = !summaries
        .iter()
        .any(|summary| summary.provider_spend_unresolved);
    (Some(total), Some(complete))
}

fn attempt_outcome_label(outcome: PhaseAttemptOutcome) -> &'static str {
    match outcome {
        PhaseAttemptOutcome::Completed => "completed",
        PhaseAttemptOutcome::Partial => "partial",
        PhaseAttemptOutcome::Blocked => "blocked",
        PhaseAttemptOutcome::Failed => "failed",
        PhaseAttemptOutcome::Canceled => "canceled",
    }
}

pub(super) fn engine_outcome_from_attempt(outcome: PhaseAttemptOutcome) -> &'static str {
    match outcome {
        PhaseAttemptOutcome::Completed => "complete",
        PhaseAttemptOutcome::Partial => "partial",
        PhaseAttemptOutcome::Blocked => "blocked",
        PhaseAttemptOutcome::Failed => "failed",
        PhaseAttemptOutcome::Canceled => "canceled",
    }
}

fn normalized_outcome(status: &str) -> String {
    let status = status.trim().to_ascii_lowercase();
    if status.is_empty() {
        "unknown".to_string()
    } else {
        status
    }
}

fn scan_freshness(app: &ShellApp, summary: &RunSummary) -> String {
    let current = app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(app.target());
    match (summary.target_git.as_ref(), current) {
        (Some(recorded), ViewDataState::Ready(Some(current))) if recorded.sha == current.sha => {
            "current revision".to_string()
        }
        (Some(_), ViewDataState::Ready(Some(_))) => "stale revision".to_string(),
        (None, _) => "revision not recorded".to_string(),
        (_, ViewDataState::Loading) => "freshness loading".to_string(),
        (_, ViewDataState::NotRequested | ViewDataState::Ready(None)) => {
            "freshness unavailable".to_string()
        }
    }
}

fn attempt_freshness(app: &ShellApp, recorded: &PhaseTargetSnapshot) -> String {
    let current = app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(app.target());
    match (recorded.revision.as_deref(), current) {
        (Some(revision), ViewDataState::Ready(Some(current))) if revision == current.sha => {
            "current revision".to_string()
        }
        (Some(_), ViewDataState::Ready(Some(_))) => "stale revision".to_string(),
        (None, _) => "revision not recorded".to_string(),
        (_, ViewDataState::Loading) => "freshness loading".to_string(),
        (_, ViewDataState::NotRequested | ViewDataState::Ready(None)) => {
            "freshness unavailable".to_string()
        }
    }
}

pub(super) fn engine_outcome(summary: &RunSummary) -> ScanEngineOutcomeModel {
    ScanEngineOutcomeModel {
        engine: summary
            .tool
            .as_deref()
            .map(kuzushi_core::modules::tool_display_name)
            .unwrap_or_else(|| "scan run".to_string()),
        tool_key: summary.tool.clone(),
        outcome: normalized_engine_outcome(&summary.status).to_string(),
        run_ref: Some(summary.run_id.clone()),
        detail: summary.error.clone(),
    }
}

fn normalized_engine_outcome(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "complete" | "completed" | "success" | "succeeded" => "complete",
        "partial" => "partial",
        "skipped" => "skipped",
        "blocked" | "refused" => "blocked",
        "canceled" | "cancelled" => "canceled",
        "interrupted" => "interrupted",
        _ => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_canceled_and_interrupted_runs_keep_their_terminal_identity() {
        let mut canceled = RunSummary::running(
            "run-canceled",
            "tool",
            Some("semgrep:scan".to_string()),
            ".",
        );
        canceled.status = "canceled".to_string();
        let mut interrupted = canceled.clone();
        interrupted.status = "interrupted".to_string();
        let mut blocked = canceled.clone();
        blocked.status = "blocked".to_string();

        assert_eq!(engine_outcome(&blocked).outcome, "blocked");
        assert_eq!(engine_outcome(&canceled).outcome, "canceled");
        assert_eq!(engine_outcome(&interrupted).outcome, "interrupted");
        assert_eq!(
            engine_outcome_from_attempt(PhaseAttemptOutcome::Canceled),
            "canceled"
        );
        assert_eq!(
            engine_outcome_from_attempt(PhaseAttemptOutcome::Blocked),
            "blocked"
        );
    }

    #[test]
    fn mixed_scan_cost_is_an_incomplete_lower_bound() {
        let mut exact = RunSummary::running("run-exact", "scan", None, ".");
        exact.cost_usd = Some(0.5);
        let mut unresolved = RunSummary::running("run-unresolved", "scan", None, ".");
        unresolved.observed_cost_usd = Some(0.25);
        unresolved.provider_spend_unresolved = true;

        assert_eq!(
            summed_recorded_cost(&[&exact, &unresolved]),
            (Some(0.75), Some(false))
        );
    }
}
