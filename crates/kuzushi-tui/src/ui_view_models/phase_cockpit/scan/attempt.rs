use crate::ui_view_models::{ScanAttemptModel, ScanEngineOutcomeModel};
use crate::{ShellApp, ViewDataState};
use kuzushi_core::run_artifacts::{PhaseStageOutcome, PhaseStageReceipt, ScanEngineStageOutcome};
use kuzushi_core::workflow_attempts::{
    PhaseAttemptOutcome, PhaseAttemptRecord, PhaseTargetSnapshot,
};
use kuzushi_core::RunSummary;
use std::collections::BTreeSet;

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
    Some(ScanAttemptModel {
        attempt_id: Some(record.completed.attempt_id.clone()),
        run_id: typed_run_id(receipt, record),
        run_refs: typed_run_refs(receipt, record),
        outcome: stage_outcome_label(receipt.outcome).to_string(),
        disposition: disposition.to_string(),
        freshness: attempt_freshness(app, &scan.target_snapshot),
        findings: Some(findings),
        findings_observed: None,
        findings_added: Some(scan.finding_delta.added),
        findings_updated: Some(scan.finding_delta.updated),
        severity_counts: scan
            .severity_counts
            .iter()
            .map(|bucket| (bucket.severity.as_str().to_string(), bucket.count))
            .collect(),
        artifact_count: scan.artifact_delta.len(),
        artifact_paths: typed_artifact_paths(scan),
        duration_secs: Some(scan.duration_ms.saturating_add(999) / 1_000),
        cost_usd: scan.cost.map(|cost| cost.observed_usd),
        cost_complete: scan.cost.map(|cost| cost.complete),
        error: typed_scan_error(scan),
    })
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
    let findings = attempt_finding_facts(
        app,
        &record.completed.run_refs,
        sum_recorded_findings(summaries),
    );
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
        attempt_finding_facts(app, std::slice::from_ref(&summary.run_id), summary.findings);
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

fn stage_outcome_label(outcome: PhaseStageOutcome) -> &'static str {
    match outcome {
        PhaseStageOutcome::Completed => "completed",
        PhaseStageOutcome::Partial => "partial",
        PhaseStageOutcome::Failed => "failed",
        PhaseStageOutcome::Skipped => "skipped",
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

/// What the loaded ledger says about one attempt's runs: how many distinct
/// findings it attributes to them, and how those split across severity bands.
struct AttributedFindings {
    distinct: u64,
    /// Highest band first, zero buckets omitted.
    severity_counts: Vec<(String, u64)>,
}

/// Bucket the findings the ledger attributes to this attempt's runs, counting
/// the total and the bands in one pass so a panel can never print one number
/// as "findings" and break a different one down beside it.
///
/// Attribution is `finding_observed_in_runs`, the shared source-aware rule: a
/// finding re-observed by a later run keeps that run as its representative
/// `scan_id` while the earlier run stays in `sources`, so matching the
/// representative alone would drop the finding from the very attempt that
/// found it — and then read the recorded count's excess as corroboration.
///
/// `None` when the claim has no backing. A clamped ledger holds only part of
/// the target's findings and a filtered one only the rows the operator asked
/// to see, so in either case both numbers would be floors — a filter must
/// never move what an accepted attempt found. An attempt the ledger attributes
/// nothing to is the ordinary case of a summary whose findings were never
/// projected, not an observed zero. The typed receipt path never consults the
/// ledger; its counts are the durable truth.
fn attributed_findings(app: &ShellApp, run_refs: &[String]) -> Option<AttributedFindings> {
    if app.findings_are_partial() || app.active_findings_filter().is_some() {
        return None;
    }
    let run_refs = run_refs.iter().cloned().collect::<BTreeSet<_>>();
    let mut counts = std::collections::BTreeMap::new();
    let mut distinct = 0_u64;
    for finding in app.findings() {
        if crate::app::finding_observed_in_runs(finding, &run_refs) {
            distinct += 1;
            *counts.entry(finding.severity).or_insert(0u64) += 1;
        }
    }
    (distinct > 0).then(|| AttributedFindings {
        distinct,
        severity_counts: counts
            .into_iter()
            .rev()
            .map(|(severity, count)| (severity.as_str().to_string(), count))
            .collect(),
    })
}

/// The three finding facts one attempt's panel shows, derived together so the
/// count and the bands beneath it can never come from different evidence.
struct AttemptFindingFacts {
    count: Option<u64>,
    observed: Option<u64>,
    severity_counts: Vec<(String, u64)>,
}

/// `recorded` is what the attempt's runs reported emitting. The ledger folds
/// same-issue observations into one finding, so a recorded count above the
/// ledger's is that fold, not a second finding count: reporting it as the
/// attempt's findings is what made the delta panel read `findings 27` beside
/// its own `20 high · 5 medium` breakdown. It is disclosed only when it is the
/// higher number, since nothing else would be a fold. Without ledger evidence
/// the recorded count stands alone with no bands, which is all this projection
/// ever knew.
fn attempt_finding_facts(
    app: &ShellApp,
    run_refs: &[String],
    recorded: Option<u64>,
) -> AttemptFindingFacts {
    let Some(ledger) = attributed_findings(app, run_refs) else {
        return AttemptFindingFacts {
            count: recorded,
            observed: None,
            severity_counts: Vec::new(),
        };
    };
    AttemptFindingFacts {
        count: Some(ledger.distinct),
        observed: recorded.filter(|observations| *observations > ledger.distinct),
        severity_counts: ledger.severity_counts,
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
