use super::*;
use crate::{FindingStore, V2Config, WorkspaceTarget};

fn result() -> Value {
    json!({"status":"completed","output":"sast:scan owned completed: 0 finding(s)\nRecorded engine work","data":{"phaseStages":[
        {"phase":"scan","outcome":"completed","runRefs":["owned"],"scan":{
            "scope":{"target":"/owned"},"plan":{"selection":"manual","engines":["semgrep"]},
            "engines":[{"engine":"semgrep","outcome":"complete"}],
            "findingDelta":{"added":0,"updated":0},"durationMs":1,
            "targetSnapshot":{"target":"/owned"}
        }},
        {"phase":"review","outcome":"completed","runRefs":["review"]}
    ]}})
}

#[test]
fn final_source_outcome_changes_only_scan_coverage_and_preserves_engine_work() {
    let mut output = result();
    let review = output["data"]["phaseStages"][1].clone();
    let partial = finalize_receipt(&mut output, false).unwrap();
    assert_eq!(partial.outcome, PhaseStageOutcome::Partial);
    assert_eq!(
        partial.scan.unwrap().engines[0].outcome,
        ScanEngineStageOutcome::Complete
    );
    assert_eq!(output["data"]["phaseStages"][1], review);
    assert_eq!(
        output["output"],
        "sast:scan owned partial: 0 finding(s)\nRecorded engine work"
    );
    assert_eq!(
        finalize_receipt(&mut result(), true).unwrap().outcome,
        PhaseStageOutcome::Completed
    );
}

#[test]
fn missing_or_malformed_coverage_cannot_be_published_as_completed() {
    for mut value in [
        json!({}),
        json!({"data":{"phaseStages":[]}}),
        json!({"data":{"phaseStages":[{"phase":"scan"}]}}),
    ] {
        assert!(finalize_receipt(&mut value, true).is_err());
    }
}

#[test]
fn late_cancellation_refuses_publication_without_creating_a_completed_receipt() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let cancel = crate::scan::ScanCancellation::default();
    cancel.cancel();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: Some(&cancel),
        authorization: Default::default(),
    };
    let artifacts = SastRunArtifacts::create(&workspace, "late-cancel").unwrap();
    assert!(publish(&ctx, "late-cancel", 0, &artifacts, &mut result())
        .unwrap_err()
        .to_string()
        .contains("stopped"));
    assert!(load_sast_phase_stages(&artifacts).unwrap().is_empty());
}
