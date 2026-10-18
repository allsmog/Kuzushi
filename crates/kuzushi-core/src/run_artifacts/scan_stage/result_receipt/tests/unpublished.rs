use super::*;
use crate::run_lifecycle::{
    OperationFingerprint, RunCallId, RunItemId, RunItemRecord, RunItemSource, RunItemStatus,
    RunItemV1, RunObservationHandle, SafeText, WorkflowContinuation,
};
use crate::runtime::RuntimeCostReport;
use std::collections::BTreeMap;

fn start(target: &Path, run: &str) -> (RunObservationHandle, crate::ApplicationToolCall) {
    record_tool_run_started(
        ToolRunRecord::new(target, run, "tool", "sast:scan"),
        &json!({}),
    );
    let observation = RunObservationHandle::jsonl(target, run)
        .unwrap()
        .start_root_task("Unpublished Scan fixture")
        .unwrap();
    let call =
        crate::ApplicationToolCall::start(observation.clone(), "sast:scan", &json!({}), None, None)
            .unwrap();
    (observation, call)
}

fn run_files(target: &Path, run: &str) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(run_dir(target, run))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

#[test]
fn unfinished_scan_ignores_sidecars_and_becomes_readable_only_after_publication() {
    let target = tempfile::tempdir().unwrap();
    let run = "publishing-parent";
    let (observation, call) = start(target.path(), run);
    let expected = receipt(target.path());
    let mut forged = expected.clone();
    forged.run_refs = vec!["unrelated-run".into()];
    write_legacy(target.path(), run, &forged);
    let before = run_files(target.path(), run);
    assert_eq!(load_scan_stage_data(target.path(), run).unwrap(), None);
    assert_eq!(
        scan_finding_run_refs(target.path(), &[run.into()]).unwrap(),
        [run]
    );
    assert_eq!(
        run_files(target.path(), run),
        before,
        "Reading cannot repair or settle work"
    );

    let output = json!({"ok":true,"data":{"phaseStages":[expected]}});
    let completion = call.completion_from_result(&Ok(output.clone()));
    crate::run_artifacts::try_record_tool_run_complete_settled(
        ToolRunRecord::new(target.path(), run, "tool", "sast:scan"),
        &output,
        &observation,
        completion,
    )
    .unwrap();
    assert_eq!(
        load_scan_stage_data(target.path(), run).unwrap(),
        Some(expected)
    );
    assert_eq!(
        scan_finding_run_refs(target.path(), &[run.into()]).unwrap(),
        ["engine-child", run]
    );
}

#[test]
fn terminal_calls_without_results_remain_errors_even_with_a_running_summary() {
    for status in [
        RunItemStatus::Completed,
        RunItemStatus::Partial,
        RunItemStatus::Failed,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
        RunItemStatus::Blocked,
    ] {
        let target = tempfile::tempdir().unwrap();
        let (_observation, call) = start(target.path(), "terminal-call");
        call.completion(status, RuntimeCostReport::UNAVAILABLE, vec![], 0, 0)
            .finish(None)
            .unwrap();
        write_legacy(target.path(), "terminal-call", &receipt(target.path()));
        let error = load_scan_stage_data(target.path(), "terminal-call").unwrap_err();
        assert!(
            error.to_string().contains("no authenticated artifact"),
            "{status:?}: {error}"
        );
    }
}

#[test]
fn unfinished_call_cannot_override_a_terminal_or_unknown_summary() {
    for status in [
        "completed",
        "partial",
        "failed",
        "canceled",
        "interrupted",
        "unknown",
    ] {
        let target = tempfile::tempdir().unwrap();
        let (_observation, _call) = start(target.path(), "summary-conflict");
        let mut summary =
            load_run_summary_without_repair(target.path(), "summary-conflict").unwrap();
        summary.status = status.into();
        write_run_summary(target.path(), &summary).unwrap();
        write_legacy(target.path(), "summary-conflict", &receipt(target.path()));
        assert!(
            load_scan_stage_data(target.path(), "summary-conflict").is_err(),
            "{status}"
        );
    }
}

#[test]
fn incomplete_publication_markers_and_unreadable_summaries_are_not_pending_receipts() {
    for marker in [
        "completed-at",
        "terminal-digest",
        "malformed-summary",
        "missing-summary",
    ] {
        let target = tempfile::tempdir().unwrap();
        let (_observation, _call) = start(target.path(), "broken-publication");
        let mut summary =
            load_run_summary_without_repair(target.path(), "broken-publication").unwrap();
        match marker {
            "completed-at" => summary.completed_at_unix = Some(1),
            "terminal-digest" => summary.terminal_result_sha256 = Some("recorded-terminal".into()),
            _ => {}
        }
        write_run_summary(target.path(), &summary).unwrap();
        let metadata = run_dir(target.path(), "broken-publication").join("run.json");
        match marker {
            "malformed-summary" => fs::write(&metadata, "damaged").unwrap(),
            "missing-summary" => fs::remove_file(&metadata).unwrap(),
            _ => {}
        }
        write_legacy(target.path(), "broken-publication", &receipt(target.path()));
        assert!(
            load_scan_stage_data(target.path(), "broken-publication").is_err(),
            "{marker}"
        );
    }
}

#[test]
fn terminal_lifecycle_does_not_hide_an_unsettled_parent_result() {
    let target = tempfile::tempdir().unwrap();
    let (observation, _call) = start(target.path(), "terminal-run");
    observation
        .emit_and_flush(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Dispatch,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible("Terminal without a parent result"),
                cost: RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("Owned terminal fixture"),
                },
            },
        ))
        .unwrap();
    write_legacy(target.path(), "terminal-run", &receipt(target.path()));
    assert!(load_scan_stage_data(target.path(), "terminal-run").is_err());
}

#[test]
fn damaged_unfinished_history_is_not_silently_treated_as_pending() {
    let target = tempfile::tempdir().unwrap();
    let (_observation, _call) = start(target.path(), "damaged-parent");
    write_legacy(target.path(), "damaged-parent", &receipt(target.path()));
    fs::write(
        run_dir(target.path(), "damaged-parent").join("items.jsonl"),
        "damaged\n",
    )
    .unwrap();
    assert!(load_scan_stage_data(target.path(), "damaged-parent").is_err());
}

#[test]
fn multiple_unfinished_scan_parents_remain_ambiguous() {
    let target = tempfile::tempdir().unwrap();
    let (observation, _first) = start(target.path(), "ambiguous-parent");
    let _second =
        crate::ApplicationToolCall::start(observation, "sast:scan", &json!({}), None, None)
            .unwrap();
    write_legacy(target.path(), "ambiguous-parent", &receipt(target.path()));
    let error = load_scan_stage_data(target.path(), "ambiguous-parent").unwrap_err();
    assert!(error.to_string().contains("ambiguous"), "{error}");
}

#[test]
fn a_requested_scan_without_execution_has_no_published_coverage() {
    let target = tempfile::tempdir().unwrap();
    let run = "requested-parent";
    record_tool_run_started(
        ToolRunRecord::new(target.path(), run, "tool", "sast:scan"),
        &json!({}),
    );
    let observation = RunObservationHandle::jsonl(target.path(), run).unwrap();
    observation
        .emit_and_flush(
            RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Dispatch,
                RunItemV1::ToolCallRequested {
                    tool_name: SafeText::operator_visible("sast:scan"),
                    operation_fingerprint: OperationFingerprint::from_bytes(
                        b"owned requested fixture",
                    ),
                    safe_option_names: vec![],
                },
            )
            .with_call(RunCallId::new()),
        )
        .unwrap();
    write_legacy(target.path(), run, &receipt(target.path()));
    let before = run_files(target.path(), run);
    assert_eq!(load_scan_stage_data(target.path(), run).unwrap(), None);
    assert_eq!(run_files(target.path(), run), before);
}
