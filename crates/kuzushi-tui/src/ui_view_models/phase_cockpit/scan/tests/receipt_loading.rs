use super::*;

#[test]
fn incomplete_indexed_runs_cannot_become_a_failed_engine_or_partial_aggregate() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let target = workspace.root();
    for (run_id, finished) in [("first", true), ("last", false)] {
        let summary = RunSummary::running(
            run_id,
            "scan",
            Some("sast:scan".into()),
            target.display().to_string(),
        )
        .with_findings(Some(1));
        let summary = if finished {
            summary.complete()
        } else {
            summary
        };
        write_run_summary(target, &summary).unwrap();
    }
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec!["first".into(), "last".into()],
        PhaseTargetSnapshot::capture(target),
        PhaseAttemptOutcome::Completed,
    );
    append_phase_attempt_completed(target, completed).unwrap();
    let mut app = hydrated_app(&workspace);
    app.refresh_phase_attempt_projection();
    let pending = scan_phase_model(&app);
    assert!(pending.attempt.is_none(), "Do not total stale indexed runs");
    assert!(pending.engine_outcomes.is_empty(), "Running is not failed");
    assert!(pending.empty_hint.is_some());

    for run_id in ["first", "last"] {
        record_typed_scan_attempt(target, run_id);
    }
    app.hydrate_view_keys_blocking(
        target,
        ["first", "last"]
            .into_iter()
            .map(|run_id| ViewHydrationKey::ScanStageReceipt {
                run_id: run_id.into(),
            })
            .collect(),
    );
    let ready = scan_phase_model(&app);
    assert_eq!(ready.engine_outcomes.len(), 4);
    assert!(ready
        .engine_outcomes
        .iter()
        .all(|engine| engine.outcome != "failed"));
    assert_eq!(ready.attempt.unwrap().run_refs.len(), 3);
}
