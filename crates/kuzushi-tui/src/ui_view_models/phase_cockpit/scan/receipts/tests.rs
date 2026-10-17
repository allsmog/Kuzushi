use super::*;
use kuzushi_core::findings::Severity;
use kuzushi_core::workflow_attempts::PhaseTargetSnapshot;
use kuzushi_core::WorkflowPhase;

fn stage(pass: usize) -> PhaseStageReceipt {
    let child = format!("engine-{pass}");
    PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Completed,
        run_refs: vec![child.clone()],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                inspected_files: None,
                target: "/fixture".into(),
                paths: vec!["src".into()],
            },
            plan: ScanStagePlan {
                selection: "manual".into(),
                engines: vec!["agentic".into()],
            },
            engines: vec![ScanStageEngine {
                engine: "agentic-sast:scan".into(),
                outcome: ScanEngineStageOutcome::Complete,
                rule_ids: None,
                run_ref: Some(child.clone()),
                detail: None,
            }],
            finding_delta: ScanFindingDelta {
                added: 1,
                updated: 2,
            },
            severity_counts: vec![ScanSeverityCount {
                severity: Severity::High,
                count: 3,
            }],
            artifact_delta: vec![ScanArtifactDelta {
                run_ref: child,
                path: "result.json".into(),
            }],
            duration_ms: 1200,
            cost: Some(ScanStageCost {
                observed_usd: 0.25,
                complete: true,
            }),
            target_snapshot: PhaseTargetSnapshot {
                target: "/fixture".into(),
                revision: Some("source-a".into()),
                dirty: false,
            },
        }),
    }
}

#[test]
fn three_parent_receipts_contribute_once_to_the_summary() {
    let summary = summarize(&[stage(1), stage(2), stage(3)]).unwrap();
    assert_eq!(
        summary.receipt.run_refs,
        ["engine-1", "engine-2", "engine-3"]
    );
    assert_eq!(summary.scope, "/fixture · paths src");
    assert_eq!(summary.plan, "3 scan runs · manual selection · agentic");
    let scan = summary.receipt.scan.unwrap();
    assert_eq!(
        scan.finding_delta,
        ScanFindingDelta {
            added: 3,
            updated: 6
        }
    );
    assert_eq!(
        scan.severity_counts,
        [ScanSeverityCount {
            severity: Severity::High,
            count: 9
        }]
    );
    assert_eq!(scan.artifact_delta.len(), 3);
    assert_eq!(scan.duration_ms, 3600);
    assert_eq!(
        scan.cost,
        Some(ScanStageCost {
            observed_usd: 0.75,
            complete: true
        })
    );
    assert_eq!(scan.engines.len(), 3);
    assert_eq!(scan.engines[2].detail.as_deref(), Some("scan run 3 of 3"));
}

#[test]
fn missing_or_unpriced_cost_is_never_an_exact_zero() {
    let first = stage(1);
    let mut second = stage(2);
    second.scan.as_mut().unwrap().cost = None;
    let scan = summarize(&[first, second]).unwrap().receipt.scan.unwrap();
    assert_eq!(
        scan.cost,
        Some(ScanStageCost {
            observed_usd: 0.25,
            complete: false
        })
    );
    let mut unpriced = stage(3);
    unpriced.scan.as_mut().unwrap().cost = Some(ScanStageCost {
        observed_usd: 0.0,
        complete: false,
    });
    assert!(
        !summarize(&[unpriced])
            .unwrap()
            .receipt
            .scan
            .unwrap()
            .cost
            .unwrap()
            .complete
    );
}

#[test]
fn different_scopes_are_named_and_different_source_snapshots_cannot_be_combined() {
    let first = stage(1);
    let mut second = stage(2);
    second.scan.as_mut().unwrap().scope.paths = vec!["packages".into()];
    assert!(summarize(&[first.clone(), second.clone()])
        .unwrap()
        .scope
        .starts_with("2 recorded scopes"));
    second.scan.as_mut().unwrap().target_snapshot.revision = Some("source-b".into());
    assert!(summarize(&[first, second]).is_none());
    let mut absent = stage(3);
    absent.scan = None;
    assert!(summarize(&[absent]).is_none());
    assert!(summarize(&[]).is_none());
}

#[test]
fn exact_file_counts_keep_the_scope_label_bounded() {
    let scope = ScanStageScope {
        target: "/fixture".into(),
        paths: vec!["selected".into()],
        inspected_files: Some(
            (0..10000)
                .map(|index| format!("selected/{index}"))
                .collect(),
        ),
    };
    assert_eq!(
        scope_label(&scope),
        "paths selected · 10000 inspected files · workspace /fixture"
    );
}

#[test]
fn inspected_scope_keeps_primary_facts_ahead_of_a_long_workspace_path() {
    let scope = ScanStageScope {
        target: format!("/workspace/{}", "long".repeat(40)),
        paths: vec!["selected".into()],
        inspected_files: Some(["selected/Dockerfile".into()].into()),
    };
    assert!(scope_label(&scope).starts_with("paths selected · 1 inspected file · workspace "));
    let mut empty = scope;
    empty.paths.clear();
    empty.inspected_files.as_mut().unwrap().clear();
    assert!(scope_label(&empty).starts_with("requested target · 0 inspected files · workspace "));
}
