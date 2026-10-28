use super::*;
use crate::app::guided_scan::{GuidedScanFlow, GuidedScanStage};
use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

#[test]
fn completed_study_reader_shortcut_keeps_the_pending_result_and_draft() {
    let (root, mut app) = fixture();
    crate::test_support::record_indexed_run(root.path(), "scan", "sast:scan", json!({"ok":true}));
    let attempt = crate::test_support::append_typed_attempt(
        root.path(),
        WorkflowPhase::Scan,
        "scan",
        PhaseAttemptOutcome::Completed,
    );
    app.refresh_phase_attempt_projection();
    hydrate_allowance(&mut app, root.path());
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::AwaitingResult {
            phase: WorkflowPhase::Scan,
            attempt_id: attempt.attempt_id.clone(),
        }));
    app.set_input("Held draft λ\nnext line");
    app.set_input_mode(InputMode::Prompt);
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(app.input().ends_with('c'));
    app.set_input("Held draft λ\nnext line");
    app.set_cursor(4);
    app.set_input_mode(InputMode::Navigate);
    let route = app.router.workbench().clone();
    let before = std::fs::read(
        root.path()
            .join(".kuzushi/v3/workflow/phase-attempts.v2.jsonl"),
    )
    .unwrap();
    assert!(app.phase_result_is_open());
    assert!(
        app.scan_study_progress_key().is_some(),
        "page {:?}, allowance key {:?}",
        crate::ui_view_models::active_workbench_page(&app),
        app.investigation_allowance_key()
    );
    assert_eq!(app.scan_study_jobs_key(), 'c');
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        ID
    );
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench(), &route);
    assert_eq!(
        (app.input(), app.cursor(), app.input_mode()),
        ("Held draft λ\nnext line", 4, InputMode::Navigate)
    );
    assert!(app.phase_result_is_open());
    assert_eq!(
        std::fs::read(
            root.path()
                .join(".kuzushi/v3/workflow/phase-attempts.v2.jsonl")
        )
        .unwrap(),
        before
    );
}

fn hydrate_allowance(app: &mut ShellApp, root: &std::path::Path) {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let allowance = kuzushi_core::SpendLimiter::read_campaign_allowance_report(
        &workspace.findings_db_path(),
        ID,
    )
    .unwrap()
    .unwrap()
    .current_investigation;
    let target = app.target_owned().unwrap();
    let key = app.investigation_allowance_key().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::InvestigationAllowance(Ok(Some(Arc::new(allowance)))),
        });
}
