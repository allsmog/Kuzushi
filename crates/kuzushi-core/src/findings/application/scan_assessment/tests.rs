use super::*;
use crate::run_artifacts::*;
use crate::workflow_attempts::PhaseTargetSnapshot;
use crate::WorkflowPhase;
use serde_json::json;

fn receipt() -> PhaseStageReceipt {
    PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Completed,
        run_refs: vec![],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                inspected_files: None,
                target: "/repo".into(),
                paths: vec!["src".into()],
            },
            plan: ScanStagePlan {
                selection: "explicit".into(),
                engines: vec!["agentic-sast".into()],
            },
            engines: vec![ScanStageEngine {
                engine: "agentic-sast".into(),
                outcome: ScanEngineStageOutcome::Complete,
                rule_ids: None,
                run_ref: None,
                detail: None,
            }],
            finding_delta: ScanFindingDelta::default(),
            severity_counts: vec![],
            artifact_delta: vec![],
            duration_ms: 1,
            cost: None,
            target_snapshot: PhaseTargetSnapshot {
                target: "/repo".into(),
                revision: Some("new-sha".into()),
                dirty: false,
            },
        }),
    }
}

#[test]
fn completed_agentic_coverage_proves_reassessment_without_claiming_a_fix() {
    assert_eq!(
        scan_reassessment_block(
            Some("/repo"),
            "completed",
            Some(&receipt()),
            "src/a.rs",
            "agentic-sast"
        ),
        None
    );
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
    assert!(
        scan_reassessment_block(Some("/repo"), "completed", None, "src/a.rs", "agentic-sast")
            .is_some()
    );
    scan.scan.as_mut().unwrap().engines[0].outcome = ScanEngineStageOutcome::Partial;
    assert!(scan_reassessment_block(
        Some("/repo"),
        "completed",
        Some(&scan),
        "src/a.rs",
        "agentic-sast"
    )
    .is_some());
}

#[test]
fn explicit_rule_policy_distinguishes_disabled_from_unrecorded_checks() {
    let mut receipt = receipt();
    let engine = &mut receipt.scan.as_mut().unwrap().engines[0];
    engine.engine = "license-scan".into();
    let check = |receipt: &PhaseStageReceipt, rule| {
        scan_reassessment_block_for_rule(
            Some("/repo"),
            "completed",
            Some(receipt),
            "src/a.rs",
            "license-scan",
            rule,
        )
    };
    assert_eq!(
        check(&receipt, "license-scan/missing-spdx-header"),
        Some("finding rule coverage was not recorded")
    );
    receipt.scan.as_mut().unwrap().engines[0].rule_ids =
        Some(vec!["license-scan/missing-license".into()]);
    assert_eq!(
        check(&receipt, "license-scan/missing-spdx-header"),
        Some("finding rule was not enabled in the later scan")
    );
    assert_eq!(check(&receipt, "license-scan/missing-license"), None);
    receipt.scan.as_mut().unwrap().engines[0].rule_ids = Some(vec![]);
    assert!(check(&receipt, "license-scan/missing-license").is_some());
}

#[test]
fn legacy_engine_rule_coverage_remains_unspecified_without_inventing_a_policy() {
    let legacy = json!({"engine":"license-scan","outcome":"complete"});
    let parsed: ScanStageEngine = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.rule_ids, None);
    assert!(serde_json::to_value(parsed)
        .unwrap()
        .get("ruleIds")
        .is_none());
}

#[test]
fn unrecorded_go_advisory_policy_cannot_establish_reassessment() {
    let mut recorded = receipt();
    recorded.scan.as_mut().unwrap().engines[0].engine = "govulncheck".into();
    assert_eq!(
        scan_reassessment_block_for_rule(
            Some("/repo"),
            "completed",
            Some(&recorded),
            "src/main.go",
            "govulncheck",
            "govulncheck/GO-OWNED-1"
        ),
        Some("finding rule coverage was not recorded")
    );
}
