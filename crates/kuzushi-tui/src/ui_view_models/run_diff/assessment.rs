use super::*;
use crate::app::ScanStageReceiptState;
use kuzushi_core::findings::scan_reassessment_block;

pub(super) fn classify_absences(
    app: &ShellApp,
    right: &str,
    base: &RunDiffMetadata,
    compare: &RunDiffMetadata,
    rows: &mut [RunDiffFindingRow],
) {
    let receipt = scan_receipt(app, right);
    let findings_available = findings_snapshot_available(app, right);
    for row in rows {
        if !findings_available {
            row.reassessment_block = Some("later findings snapshot is missing or malformed".into());
            continue;
        }
        row.reassessment_block = scan_reassessment_block(
            base.target.as_deref(),
            &compare.status,
            receipt.as_ref(),
            &row.file_path,
            &row.tool,
        )
        .map(str::to_string);
    }
}

fn findings_snapshot_available(app: &ShellApp, run: &str) -> bool {
    let Some(value) = artifact_json(app, run, FINDINGS_FILE) else {
        return false;
    };
    findings_array(&value).is_some_and(|rows| rows.iter().all(|row| finding_key(row).is_some()))
}

fn scan_receipt(
    app: &ShellApp,
    run: &str,
) -> Option<kuzushi_core::run_artifacts::PhaseStageReceipt> {
    let state = app
        .workbench_cache()
        .borrow()
        .cached_scan_stage_receipt(app.target()?, run);
    match state {
        ViewDataState::Ready(ScanStageReceiptState::Ready(receipt)) => Some(receipt),
        _ => None,
    }
}

pub(super) fn run_target(state: &JsonFileState) -> Option<String> {
    let JsonFileState::Present(value) = state else {
        return None;
    };
    value.get("target")?.as_str().map(str::to_string)
}

pub(super) fn source_label(app: &ShellApp, run: &str) -> String {
    let summary = artifact_json(app, run, RUN_FILE);
    let result = artifact_json(app, run, "result.json");
    kuzushi_core::run_artifacts::RunSourceRevision::from_artifacts(
        summary.as_ref(),
        result.as_ref(),
    )
    .label()
}

fn artifact_json(app: &ShellApp, run: &str, leaf: &str) -> Option<serde_json::Value> {
    match run_json_state(app, run, leaf) {
        ViewDataState::Ready(JsonFileState::Present(value)) => Some(value),
        _ => None,
    }
}

pub(super) fn context_label(app: &ShellApp, run: &str) -> String {
    recorded_context(app, run).label()
}

pub(super) fn context_comparison(app: &ShellApp, left: &str, right: &str) -> String {
    recorded_context(app, left)
        .comparison_label(&recorded_context(app, right))
        .to_string()
}

fn recorded_context(
    app: &ShellApp,
    run: &str,
) -> kuzushi_core::run_artifacts::RunThreatModelContext {
    let input = artifact_json(app, run, "scan-input.json");
    kuzushi_core::run_artifacts::RunThreatModelContext::from_scan_input(input.as_ref())
}
