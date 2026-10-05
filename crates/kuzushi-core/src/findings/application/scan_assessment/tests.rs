use super::*;
use crate::run_artifacts::*;
use crate::workflow_attempts::PhaseTargetSnapshot;
use crate::WorkflowPhase;

fn receipt() -> PhaseStageReceipt {
    PhaseStageReceipt {
        phase: WorkflowPhase::Scan, outcome: PhaseStageOutcome::Completed, run_refs: vec![],
        scan: Some(ScanStageData {
            scope: ScanStageScope { target: "/repo".into(), paths: vec!["src".into()] },
            plan: ScanStagePlan { selection: "explicit".into(), engines: vec!["agentic-sast".into()] },
            engines: vec![ScanStageEngine { engine: "agentic-sast".into(), outcome: ScanEngineStageOutcome::Complete, run_ref: None, detail: None }],
            finding_delta: ScanFindingDelta::default(), severity_counts: vec![], artifact_delta: vec![],
            duration_ms: 1, cost: None,
            target_snapshot: PhaseTargetSnapshot { target: "/repo".into(), revision: Some("new-sha".into()), dirty: false },
        }),
    }
}

#[test]
fn completed_agentic_coverage_proves_reassessment_without_claiming_a_fix() {
    assert_eq!(scan_reassessment_block(Some("/repo"), "completed", Some(&receipt()), "src/a.rs", "agentic-sast"), None);
}

#[test]
fn partial_missing_different_and_uncovered_work_is_not_reassessed() {
    let mut scan = receipt();
    for (status, target, file, engine) in [
        ("partial", "/repo", "src/a.rs", "agentic-sast"),
        ("completed", "/another", "src/a.rs", "agentic-sast"),
        ("completed", "/repo", "other/a.rs", "agentic-sast"),
        ("completed", "/repo", "src/a.rs", "agentic-sast,codeql"),
        ("completed", "/repo", "src/a.rs", ""),
    ] {
        assert!(scan_reassessment_block(Some(target), status, Some(&scan), file, engine).is_some());
    }
    assert!(scan_reassessment_block(Some("/repo"), "completed", None, "src/a.rs", "agentic-sast").is_some());
    scan.scan.as_mut().unwrap().engines[0].outcome = ScanEngineStageOutcome::Partial;
    assert!(scan_reassessment_block(Some("/repo"), "completed", Some(&scan), "src/a.rs", "agentic-sast").is_some());
}
