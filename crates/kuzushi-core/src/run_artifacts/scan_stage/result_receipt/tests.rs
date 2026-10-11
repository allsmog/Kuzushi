use super::*;
use crate::run_artifacts::{record_tool_run_started, ToolRunRecord};
use serde_json::json;

fn receipt(target: &Path) -> PhaseStageReceipt {
    PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Completed,
        run_refs: vec!["engine-child".into()],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                target: target.display().to_string(),
                paths: Vec::new(),
            },
            plan: ScanStagePlan {
                selection: "manual".into(),
                engines: vec!["agentic".into()],
            },
            engines: Vec::new(),
            finding_delta: ScanFindingDelta::default(),
            severity_counts: Vec::new(),
            artifact_delta: Vec::new(),
            duration_ms: 1,
            cost: None,
            target_snapshot: PhaseTargetSnapshot::capture(target),
        }),
    }
}

fn write_legacy(target: &Path, run: &str, value: &PhaseStageReceipt) {
    let path = run_dir(target, run).join(SAST_PHASE_STAGES_JSONL_FILE);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_string(value).unwrap()).unwrap();
}

fn record_result(target: &Path, run: &str, tool: &str, stages: Value) {
    let record = ToolRunRecord {
        target,
        run_id: run,
        kind: "tool",
        tool,
    };
    record_tool_run_started(record, &json!({}));
    let observation = crate::run_lifecycle::RunObservationHandle::jsonl(target, run)
        .unwrap()
        .start_root_task("Read Scan result fixture")
        .unwrap();
    let call = crate::ApplicationToolCall::start(observation.clone(), tool, &json!({}), None, None)
        .unwrap();
    let output = json!({"ok":true,"data":{"phaseStages":stages}});
    let completion = call.completion_from_result(&Ok(output.clone()));
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &observation,
        completion,
    )
    .unwrap();
}

#[test]
fn authenticated_membership_wins_over_a_changed_legacy_file() {
    let target = tempfile::tempdir().unwrap();
    let expected = receipt(target.path());
    record_result(target.path(), "scan-parent", "sast:scan", json!([expected]));
    let mut changed = expected.clone();
    changed.run_refs = vec!["unrelated-run".into()];
    write_legacy(target.path(), "scan-parent", &changed);
    assert_eq!(
        load_scan_stage_data(target.path(), "scan-parent").unwrap(),
        Some(expected)
    );
    assert_eq!(
        scan_finding_run_refs(target.path(), &["scan-parent".into()]).unwrap(),
        vec!["engine-child", "scan-parent"]
    );
}

#[test]
fn changed_result_or_damaged_history_never_uses_the_legacy_receipt() {
    for artifact in ["result.json", "items.jsonl"] {
        let target = tempfile::tempdir().unwrap();
        let expected = receipt(target.path());
        record_result(target.path(), "scan-parent", "sast:scan", json!([expected]));
        write_legacy(target.path(), "scan-parent", &expected);
        fs::write(
            run_dir(target.path(), "scan-parent").join(artifact),
            "damaged\n",
        )
        .unwrap();
        assert!(load_scan_stage_data(target.path(), "scan-parent").is_err());
    }
}

#[test]
fn malformed_authenticated_stages_and_invalid_membership_are_errors() {
    let target = tempfile::tempdir().unwrap();
    record_result(
        target.path(),
        "bad-stages",
        "sast:scan",
        json!({"unexpected":true}),
    );
    assert!(load_scan_stage_data(target.path(), "bad-stages").is_err());
    let mut invalid = receipt(target.path());
    invalid.run_refs = vec!["../outside".into()];
    record_result(
        target.path(),
        "bad-membership",
        "sast:scan",
        json!([invalid]),
    );
    assert!(scan_finding_run_refs(target.path(), &["bad-membership".into()]).is_err());
}

#[test]
fn legacy_stage_only_runs_remain_readable_and_direct_tools_do_not_inherit_them() {
    let target = tempfile::tempdir().unwrap();
    let expected = receipt(target.path());
    write_legacy(target.path(), "legacy-parent", &expected);
    assert_eq!(
        load_scan_stage_data(target.path(), "legacy-parent").unwrap(),
        Some(expected.clone())
    );
    record_result(
        target.path(),
        "direct-engine",
        "agentic-sast:scan",
        json!([]),
    );
    write_legacy(target.path(), "direct-engine", &expected);
    assert_eq!(
        load_scan_stage_data(target.path(), "direct-engine").unwrap(),
        None
    );
    assert_eq!(load_scan_stage_data(target.path(), "absent").unwrap(), None);
}

#[test]
fn interrupted_recovery_authenticates_its_result_without_inventing_scan_membership() {
    let target = tempfile::tempdir().unwrap();
    let run = "interrupted-scan";
    let record = ToolRunRecord::new(target.path(), run, "run", "sast:scan");
    record_tool_run_started(record, &json!({}));
    let observation = crate::run_lifecycle::RunObservationHandle::jsonl(target.path(), run)
        .unwrap()
        .start_root_task("Stopped Scan fixture")
        .unwrap();
    let call = crate::ApplicationToolCall::start(observation, "sast:scan", &json!({}), None, None)
        .unwrap();
    let config = crate::V2Config::default();
    let trace = call.execution_observation().trace_handle();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    crate::workspace::source_snapshot::SourceSnapshot::capture(&ctx, "sast:scan", target.path())
        .unwrap();
    drop(trace);
    let engine = crate::ApplicationToolCall::start(
        call.execution_observation(),
        "agentic-sast:scan",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    drop(engine);
    drop(call);
    let summary = load_run_summary(target.path(), run)
        .unwrap()
        .with_process_id(u32::MAX);
    write_run_summary(target.path(), &summary).unwrap();
    let recovered = load_run_summary(target.path(), run).unwrap();
    assert_eq!(recovered.status, "interrupted");
    let projection =
        crate::run_lifecycle::load_run_projection_unhydrated(target.path(), run).unwrap();
    let root_call = projection
        .calls
        .values()
        .find(|call| call.label.as_str() == "sast:scan")
        .unwrap();
    let engine_call = projection
        .calls
        .values()
        .find(|call| call.label.as_str() == "agentic-sast:scan")
        .unwrap();
    assert!(root_call.result_artifact.is_some());
    assert!(engine_call.result_artifact.is_none());
    let identity =
        crate::workflow_attempts::referenced_run_content_identity(target.path(), &[run.into()]);
    assert!(identity.permits_cross_attempt_reuse());
    assert_eq!(load_scan_stage_data(target.path(), run).unwrap(), None);
    assert_eq!(
        scan_finding_run_refs(target.path(), &[run.into()]).unwrap(),
        vec![run.to_string()]
    );
    let start =
        run_dir(target.path(), run).join(format!("source-start-{}.json", root_call.item_id));
    let original = fs::read(&start).unwrap();
    fs::write(&start, "{}").unwrap();
    assert!(!crate::workflow_attempts::referenced_run_content_identity(
        target.path(),
        &[run.into()]
    )
    .permits_cross_attempt_reuse());
    fs::write(&start, original).unwrap();
    assert_eq!(
        crate::workflow_attempts::referenced_run_content_identity(target.path(), &[run.into()]),
        identity
    );
    fs::write(run_dir(target.path(), run).join("result.json"), "{}").unwrap();
    assert!(load_scan_stage_data(target.path(), run).is_err());
    assert!(!crate::workflow_attempts::referenced_run_content_identity(
        target.path(),
        &[run.into()]
    )
    .permits_cross_attempt_reuse());
}
