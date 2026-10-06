use super::{LiveScanModel, ScanAttemptModel, ScanEngineOutcomeModel, ScanPhaseModel};
use crate::ui_view_models::scoped_target_path_label;
use crate::{RunSummaryEntriesState, ScanStageReceiptState, ShellApp, ViewDataState};
use kuzushi_core::run_artifacts::ScanEngineStageOutcome;
use kuzushi_core::workflow_attempts::{
    PhaseAttemptDisposition, PhaseAttemptOutcome, PhaseAttemptRecord,
};
use kuzushi_core::{RunSummaryEntry, WorkflowPhase};

mod attempt;
mod receipts;
mod summaries;

use attempt::{
    scan_attempt_from_legacy_summary, scan_attempt_from_record, scan_attempt_from_stage,
};
use summaries::{scanner_outcomes, scanner_plan, summaries_for_refs, terminal_scan_summary};

pub(super) fn scan_phase_model(app: &ShellApp) -> ScanPhaseModel {
    let default_scope = app
        .target()
        .map(|_| scoped_target_path_label(app))
        .unwrap_or_else(|| "no target selected".to_string());
    let summary_index = scan_summary_entries(app);
    let entries = &summary_index.entries;
    let projection = durable_attempt(app)
        .map(|(record, disposition)| durable_projection(app, record, disposition, entries))
        .or_else(|| legacy_projection(app, entries));
    let has_projection = projection.is_some();
    ScanPhaseModel {
        scope: projection
            .as_ref()
            .map(|projection| projection.scope.clone())
            .unwrap_or(default_scope),
        plan: projection
            .as_ref()
            .map(|projection| projection.plan.clone())
            .unwrap_or_else(|| "scanner plan not recorded yet".to_string()),
        attempt: projection
            .as_ref()
            .map(|projection| projection.attempt.clone()),
        engine_outcomes: projection
            .map(|projection| projection.engine_outcomes)
            .unwrap_or_default(),
        empty_hint: scan_page_hint(&summary_index, has_projection),
        live: live_scan_model(app),
    }
}

/// The in-flight scan run, when one exists. Only identity and coarse stage
/// come from the scan panel; the trace itself remains Run Focus territory.
fn live_scan_model(app: &ShellApp) -> Option<LiveScanModel> {
    let scan = app.scan()?;
    scan.running.then(|| LiveScanModel {
        run_id: scan.run_id.clone(),
        stage: scan.stage.clone(),
        findings: scan.findings_count,
    })
}

/// The run-summary index reloads on every external workspace refresh. While
/// a durable projection is already on screen, a transient "receipts are
/// loading" note would flap in and out beneath it, so pending-index hints
/// only show when the page has nothing else to stand on.
fn scan_page_hint(index: &ScanSummaryIndex, has_projection: bool) -> Option<String> {
    if index.index_pending && has_projection {
        return None;
    }
    index.load_hint.clone().or_else(|| {
        (!has_projection).then(|| {
            "no terminal Scan run is recorded — describe a target in the Scan composer".to_string()
        })
    })
}

struct ScanProjection {
    scope: String,
    plan: String,
    attempt: ScanAttemptModel,
    engine_outcomes: Vec<ScanEngineOutcomeModel>,
}

fn durable_attempt(app: &ShellApp) -> Option<(&PhaseAttemptRecord, &'static str)> {
    use crate::app::DisplayedAttempt;
    let (record, standing) = app
        .engagement
        .displayed_phase_attempt(WorkflowPhase::Scan)?;
    let disposition = match standing {
        DisplayedAttempt::Unresolved => "awaiting disposition",
        DisplayedAttempt::Selected => selected_disposition(record),
        DisplayedAttempt::EarlierSource => "selected · earlier source",
    };
    Some((record, disposition))
}

fn selected_disposition(record: &PhaseAttemptRecord) -> &'static str {
    match record
        .disposition
        .as_ref()
        .map(|recorded| &recorded.disposition)
    {
        Some(PhaseAttemptDisposition::Selected {
            acknowledged_partial: true,
        }) => "selected · partial acknowledged",
        Some(PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        }) => "selected",
        Some(PhaseAttemptDisposition::Discarded) => "discarded",
        None => "awaiting disposition",
    }
}

fn durable_projection(
    app: &ShellApp,
    record: &PhaseAttemptRecord,
    disposition: &'static str,
    entries: &[RunSummaryEntry],
) -> ScanProjection {
    if let Some(receipt) = typed_scan_receipt(app, record) {
        if let Some(projection) = typed_scan_projection(app, record, disposition, &receipt) {
            return projection;
        }
    }
    let summaries = summaries_for_refs(entries, &record.completed.run_refs);
    ScanProjection {
        scope: app
            .target()
            .map(|_| scoped_target_path_label(app))
            .unwrap_or_else(|| "no target selected".to_string()),
        plan: scanner_plan(&summaries),
        engine_outcomes: scanner_outcomes(&summaries, record.completed.outcome),
        attempt: scan_attempt_from_record(app, record, disposition, &summaries),
    }
}

fn legacy_projection(app: &ShellApp, entries: &[RunSummaryEntry]) -> Option<ScanProjection> {
    let summary = entries.iter().find_map(terminal_scan_summary)?;
    Some(ScanProjection {
        scope: app
            .target()
            .map(|_| scoped_target_path_label(app))
            .unwrap_or_else(|| "no target selected".to_string()),
        plan: summary
            .tool
            .as_ref()
            .map(|tool| format!("recorded tool {tool}"))
            .unwrap_or_else(|| "scanner plan not recorded".to_string()),
        attempt: scan_attempt_from_legacy_summary(app, summary),
        engine_outcomes: vec![attempt::engine_outcome(summary)],
    })
}

fn typed_scan_receipt(
    app: &ShellApp,
    record: &PhaseAttemptRecord,
) -> Option<receipts::ScanReceiptSummary> {
    let target = app.target()?;
    let receipts = record
        .completed
        .run_refs
        .iter()
        .map(|run_ref| {
            match app
                .workbench_cache()
                .borrow()
                .cached_scan_stage_receipt(target, run_ref)
            {
                ViewDataState::Ready(ScanStageReceiptState::Ready(receipt)) => Some(receipt),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>()?;
    receipts::summarize(&receipts)
}

fn typed_scan_projection(
    app: &ShellApp,
    record: &PhaseAttemptRecord,
    disposition: &str,
    summary: &receipts::ScanReceiptSummary,
) -> Option<ScanProjection> {
    let receipt = &summary.receipt;
    let scan = receipt.scan.as_ref()?;
    let engine_outcomes = scan
        .engines
        .iter()
        .map(|engine| ScanEngineOutcomeModel {
            engine: kuzushi_core::modules::tool_display_name(&engine.engine),
            tool_key: Some(engine.engine.clone()),
            outcome: typed_engine_outcome(engine.outcome, record.completed.outcome).to_string(),
            run_ref: engine.run_ref.clone(),
            detail: engine.detail.clone(),
        })
        .collect();
    Some(ScanProjection {
        scope: summary.scope.clone(),
        plan: summary.plan.clone(),
        attempt: scan_attempt_from_stage(app, record, disposition, receipt)?,
        engine_outcomes,
    })
}

fn typed_engine_outcome(
    outcome: ScanEngineStageOutcome,
    attempt: PhaseAttemptOutcome,
) -> &'static str {
    if outcome == ScanEngineStageOutcome::Failed && attempt == PhaseAttemptOutcome::Canceled {
        return "stopped";
    }
    recorded_engine_outcome(outcome)
}

fn recorded_engine_outcome(outcome: ScanEngineStageOutcome) -> &'static str {
    match outcome {
        ScanEngineStageOutcome::Complete => "complete",
        ScanEngineStageOutcome::Partial => "partial",
        ScanEngineStageOutcome::Skipped => "skipped",
        ScanEngineStageOutcome::Failed => "failed",
    }
}

struct ScanSummaryIndex {
    entries: Vec<RunSummaryEntry>,
    load_hint: Option<String>,
    /// The entries index is still hydrating — its hint is transient, not a
    /// durable statement about the recorded Scan attempt.
    index_pending: bool,
}

fn scan_summary_entries(app: &ShellApp) -> ScanSummaryIndex {
    let state = app
        .workbench_cache()
        .borrow()
        .cached_run_summary_entries(app.target());
    let receipt_hint = scan_receipt_load_hint(app);
    match state {
        ViewDataState::Ready(RunSummaryEntriesState::Ready(entries)) => ScanSummaryIndex {
            entries,
            load_hint: receipt_hint,
            index_pending: false,
        },
        ViewDataState::Ready(RunSummaryEntriesState::Failed(error)) => ScanSummaryIndex {
            entries: Vec::new(),
            load_hint: Some(format!("Scan receipt index unavailable: {error}")),
            index_pending: false,
        },
        ViewDataState::Loading => ScanSummaryIndex {
            entries: Vec::new(),
            load_hint: Some("Scan receipts are loading".to_string()),
            index_pending: true,
        },
        ViewDataState::NotRequested => ScanSummaryIndex {
            entries: Vec::new(),
            load_hint: Some("Scan receipts have not been loaded for this target".to_string()),
            index_pending: true,
        },
    }
}

fn scan_receipt_load_hint(app: &ShellApp) -> Option<String> {
    let target = app.target()?;
    let record = app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Scan)
        .or_else(|| app.engagement.selected_phase_attempt(WorkflowPhase::Scan))?;
    let mut missing = false;
    for run_ref in record.completed.run_refs.iter().rev() {
        match app
            .workbench_cache()
            .borrow()
            .cached_scan_stage_receipt(target, run_ref)
        {
            ViewDataState::Ready(ScanStageReceiptState::Ready(_)) => {}
            ViewDataState::Ready(ScanStageReceiptState::Failed(error)) => {
                return Some(format!("Scan receipt unavailable: {error}"));
            }
            ViewDataState::Ready(ScanStageReceiptState::Missing) => missing = true,
            ViewDataState::Loading => return Some("Scan receipt is loading".to_string()),
            ViewDataState::NotRequested => {
                return Some("Scan receipt has not been loaded".to_string());
            }
        }
    }
    missing.then(|| "typed Scan receipt missing · showing legacy run summary".to_string())
}

#[cfg(test)]
mod tests;
