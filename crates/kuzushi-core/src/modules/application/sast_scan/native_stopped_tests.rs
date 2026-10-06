use super::*;
use crate::run_artifacts::{load_run_summary, load_scan_stage_data, ToolRunRecord};
use crate::run_lifecycle::{RunItemStatus, RunObservationHandle};
use std::{os::unix::fs::PermissionsExt, path::Path};

fn scanner_fixture(root: &Path, fixture: &Path, canceled: bool) -> Value {
    for name in ["a", "b", "c"] {
        std::fs::create_dir(root.join(name)).unwrap();
    }
    std::fs::write(root.join("a/app.js"), "fixture(1);\n").unwrap();
    let marker = fixture.join("waiting");
    let binary = fixture.join("labeled-protocol-scanner.sh");
    let stop = if canceled {
        "exec sleep 30"
    } else {
        "echo 'Labeled scanner failure' >&2; exit 2"
    };
    let output = json!({"results":[{"check_id":"labeled-fixture", "path":"app.js", "start":{"line":1}, "extra":{"severity":"WARNING", "message":"Labeled protocol observation"}}], "errors":[]});
    std::fs::write(&binary, format!("#!/bin/sh\ncase \"$PWD\" in */a) printf '%s' '{output}';; *) touch '{}'; {stop};; esac\n", marker.display())).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    json!({"tasks":["semgrep"], "semgrepBinary":binary, "semgrepConfig":["labeled-protocol-fixture"]})
}

fn cancellation_thread(
    marker: std::path::PathBuf,
    cancel: crate::scan::ScanCancellation,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for _ in 0..500 {
            if marker.is_file() {
                cancel.cancel();
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        cancel.cancel();
        panic!("Scanner did not reach the labeled cancellation point");
    })
}

fn dispatch_stop(root: &Path, fixture: &Path, canceled: bool) -> crate::WorkspaceTarget {
    let workspace = crate::WorkspaceTarget::new(root).unwrap();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = crate::V2Config::default();
    let cancel = crate::scan::ScanCancellation::default();
    let observation = RunObservationHandle::jsonl(root, "native-stop")
        .unwrap()
        .start_root_task("Run the finite native plan")
        .unwrap();
    observation
        .task_handle()
        .unwrap()
        .update_and_flush(RunItemStatus::Running, None)
        .unwrap();
    let trace = observation.trace_handle();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: Some(&trace),
        cancellation: Some(&cancel),
        authorization: Default::default(),
    };
    let mut input = json!({"runId":"native-stop", "taskMode":"manual", "paths":["a","b","c"], "triage":false, "verify":false, "autoPatch":false});
    input.as_object_mut().unwrap().extend(
        scanner_fixture(root, fixture, canceled)
            .as_object()
            .unwrap()
            .clone(),
    );
    execute_stop(root, fixture, canceled, input, &ctx, &observation);

    workspace
}

fn execute_stop(
    root: &Path,
    fixture: &Path,
    canceled: bool,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    observation: &RunObservationHandle,
) {
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input, &ctx, None)
        .unwrap();
    let waiter = canceled
        .then(|| cancellation_thread(fixture.join("waiting"), ctx.cancellation.unwrap().clone()));
    let outcome = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
        .unwrap();
    if let Some(waiter) = waiter {
        waiter.join().unwrap();
    }
    settle_stop(root, canceled, observation, outcome);
}

fn settle_stop(
    root: &Path,
    canceled: bool,
    observation: &RunObservationHandle,
    outcome: crate::modules::ObservedDispatchOutcome,
) {
    let error = outcome.execution.unwrap_err();
    let record = ToolRunRecord::new(root, "native-stop", "scan", "sast:scan");
    if canceled {
        crate::run_artifacts::try_record_tool_run_canceled_settled(
            record,
            &error.to_string(),
            &observation,
            outcome.completion,
        )
        .unwrap();
    } else {
        crate::run_artifacts::try_record_tool_run_failed_settled(
            record,
            &error.to_string(),
            &observation,
            outcome.completion,
        )
        .unwrap();
    }
}

#[test]
fn native_stopped_dispatch_keeps_authenticated_receipts_counts_and_observations() {
    for canceled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let workspace = dispatch_stop(root.path(), fixture.path(), canceled);
        let status = if canceled { "canceled" } else { "failed" };
        assert_stopped_receipt(root.path(), status);
        let reopened = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(
            reopened.run_status("native-stop").unwrap().as_deref(),
            Some(status)
        );
        assert_eq!(
            reopened
                .list_findings_for_scan_id("native-stop")
                .unwrap()
                .len(),
            1
        );
    }
}

fn assert_stopped_receipt(root: &Path, status: &str) {
    let summary = load_run_summary(root, "native-stop").unwrap();
    assert_eq!(summary.status, status);
    assert_eq!(summary.findings, Some(1));
    let result: Value = serde_json::from_str(
        &std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
            root,
            "native-stop",
            "result.json",
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(result["status"], status);
    assert_eq!(result["data"]["findingsCount"], 1);
    assert_eq!(result["data"]["treeHash"].as_str().unwrap().len(), 64);
    let engines = result["data"]["nativeCoverage"]["engines"]
        .as_array()
        .unwrap();
    assert_eq!(engines.len(), 3);
    assert_eq!(engines[0]["disposition"], "complete");
    assert_eq!(engines[1]["disposition"], status);
    assert_eq!(engines[2]["disposition"], "not_started");
    let receipt = load_scan_stage_data(root, "native-stop").unwrap().unwrap();
    let scan = receipt.scan.unwrap();
    assert_eq!(scan.finding_delta.added, 1);
    assert_eq!(
        scan.engines[0].outcome,
        crate::run_artifacts::ScanEngineStageOutcome::Failed
    );
}
