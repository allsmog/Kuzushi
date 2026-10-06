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
