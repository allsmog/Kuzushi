use super::*;
use crate::{InputMode, WorkbenchPage};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{ModuleRegistry, ToolExecutionContext};
use serde_json::json;

const ID: &str = "owned-study-progress";

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("README.md"),
        "Owned offline study progress\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let plan = registry.execute_tool("campaign:study", json!({"campaignId":ID,"investigationId":ID,
        "scanInput":{"taskMode":"manual","tasks":["license-scan"],"threatModelRef":null,"scanContextRef":null}}), &ctx).unwrap();
    let approval = registry.prepare_dispatch_input("campaign:approve-allowance", json!({
        "campaignId":ID,"investigationId":ID,"expectedRevision":0,"campaignPlanSha256":plan["data"]["planSha256"],
        "campaignJobs":3,"maxJobAttempts":1,"model":"openai-codex:gpt-5.5","maxProviderCalls":7,
        "protectedReviewCalls":2,"reason":"Offline navigation and progress; no jobs start"
    }), &ctx, None).unwrap().authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(approval, &ctx, None)
        .unwrap();
    crate::test_support::record_indexed_run(
        root.path(),
        "map",
        "threat-model:build",
        json!({"ok":true}),
    );
    let map = crate::test_support::append_typed_attempt(
        root.path(),
        WorkflowPhase::Map,
        "map",
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(root.path(), &map);
    let mut app = ShellApp::new(config, Some(&workspace));
    app.refresh_phase_attempt_projection();
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Scan));
    let allowance = kuzushi_core::SpendLimiter::read_campaign_allowance_report(
        &workspace.findings_db_path(),
        ID,
    )
    .unwrap()
    .unwrap()
    .current_investigation;
    assert!(
        allowance.work_plan.is_some(),
        "Fixture must have real approved work"
    );
    let target = app.target_owned().unwrap();
    let key = app.investigation_allowance_key().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::InvestigationAllowance(Ok(Some(Arc::new(allowance)))),
        });
    (root, app)
}

fn progress(app: &ShellApp, value: ScanStudyProgressRead) {
    let target = app.target_owned().unwrap();
    let key = app.scan_study_progress_key().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::ScanStudyProgress(value),
        });
}

fn recorded_queue(root: &Path) {
    let plan = kuzushi_core::capabilities::campaign::read_campaign_plan_document(root, ID).unwrap();
    let states = ["completed", "running", "planned"];
    let jobs = plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .zip(states)
        .map(|(job, state)| {
            (
                job["jobId"].as_str().unwrap().into(),
                json!({"state":state}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    std::fs::write(
        kuzushi_core::capabilities::campaign::campaign_queue_path(root, ID),
        json!({"jobs":jobs}).to_string(),
    )
    .unwrap();
}

fn scan(app: &ShellApp) -> crate::ui_view_models::ScanPhaseModel {
    let model = crate::ui_view_models::phase_cockpit_model_for_phase(app, WorkflowPhase::Scan);
    let crate::ui_view_models::PhaseCockpitBody::Scan(scan) = model.body else {
        panic!("Scan model required");
    };
    scan
}

#[test]
fn plan_binding_is_target_and_scan_specific_and_never_uses_an_unreadable_allowance() {
    let (_root, mut app) = fixture();
    assert_eq!(
        app.scan_study_progress_key(),
        Some(ViewHydrationKey::ScanStudyProgress {
            campaign_id: ID.into()
        })
    );
    for page in [WorkbenchPage::Map, WorkbenchPage::Review] {
        app.router.workbench_mut().set_page(Some(page));
        assert!(app.scan_study_progress_key().is_none());
    }
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Scan));
    let target = app.target_owned().unwrap();
    let key = app.investigation_allowance_key().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::InvestigationAllowance(Err(
                "Owned unavailable allowance".into()
            )),
        });
    assert!(app.scan_study_progress_key().is_none());
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    assert!(app.scan_study_progress_key().is_none());
}

#[test]
fn pending_and_failed_reads_never_substitute_a_terminal_engine_for_the_approved_study() {
    let (root, app) = fixture();
    assert!(scan(&app).study.is_some());
    assert!(scan(&app).attempt.is_none());
    progress(&app, Err("Owned changed plan".into()));
    let model = scan(&app);
    assert!(model.attempt.is_none());
    assert!(model.study.unwrap().issue.unwrap().contains("changed plan"));
    recorded_queue(root.path());
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_approved_scan_snapshot(
        root.path(),
        ID,
    )
    .unwrap();
    progress(&app, Ok(Arc::new(snapshot)));
    let queue = scan(&app).study.unwrap().queue.unwrap();
    assert_eq!((queue.completed, queue.running, queue.queued), (1, 1, 1));
}

#[test]
fn native_layout_models_keep_the_complete_queue_summary_at_every_viewport() {
    use ratatui::{backend::TestBackend, Terminal};
    let (root, app) = fixture();
    recorded_queue(root.path());
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_approved_scan_snapshot(
        root.path(),
        ID,
    )
    .unwrap();
    progress(&app, Ok(Arc::new(snapshot)));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        for expected in [
            "APPROVED STUDY",
            "1/3 complete",
            "1 running",
            "1 queued",
            "c study jobs",
        ] {
            assert!(
                text.contains(expected),
                "{width}x{height} missing {expected}: {text}"
            );
        }
        assert!(!text.contains("legacy inferred"));
    }
}

#[test]
fn study_read_completion_keeps_the_draft_cursor_phase_and_input_mode() {
    let (root, mut app) = fixture();
    app.set_input("Held study draft λ\nsecond line");
    app.set_cursor(5);
    app.set_input_mode(InputMode::Navigate);
    let before = (
        app.shell_view(),
        app.router.workbench().clone(),
        app.input_mode(),
    );
    recorded_queue(root.path());
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_approved_scan_snapshot(
        root.path(),
        ID,
    )
    .unwrap();
    progress(&app, Ok(Arc::new(snapshot)));
    assert_eq!(
        (
            app.shell_view(),
            app.router.workbench().clone(),
            app.input_mode()
        ),
        before
    );
    assert_eq!(
        (app.input(), app.cursor()),
        ("Held study draft λ\nsecond line", 5)
    );
}

#[test]
fn study_shortcut_respects_prompt_ownership_and_restores_the_scan_origin() {
    let (root, mut app) = fixture();
    app.set_input("Held draft");
    app.set_input_mode(InputMode::Prompt);
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(app.input().contains('c'));
    app.set_input("Held draft λ");
    app.set_cursor(4);
    app.set_input_mode(InputMode::Navigate);
    let before = app.router.workbench().clone();
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
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.router.campaign().job_detail);
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert!(!app.router.campaign().job_detail);
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench(), &before);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert_eq!((app.input(), app.cursor()), ("Held draft λ", 4));
    let allowance = kuzushi_core::SpendLimiter::read_campaign_allowance_report(
        &WorkspaceTarget::new(root.path())
            .unwrap()
            .findings_db_path(),
        ID,
    )
    .unwrap()
    .unwrap();
    assert_eq!(allowance.current_investigation.committed_calls, 0);
    assert!(
        kuzushi_core::capabilities::campaign::snapshot::load_approved_scan_snapshot(
            root.path(),
            ID
        )
        .unwrap()
        .jobs
        .iter()
        .all(|job| job.state == "planned")
    );
}

#[cfg(unix)]
#[test]
fn owned_dispatcher_identity_wins_over_a_different_selected_row_and_never_crosses_targets() {
    let (root, mut app) = fixture();
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_approved_scan_snapshot(
        root.path(),
        ID,
    )
    .unwrap();
    let directory = kuzushi_core::capabilities::campaign::campaign_dir(root.path(), "other-draft");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("plan.json"),
        json!({"kind":"scan-batch","jobs":[]}).to_string(),
    )
    .unwrap();
    let other = kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(
        root.path(),
        "other-draft",
    )
    .unwrap();
    app.router.campaign_mut().campaigns = vec![other, snapshot];
    app.router.campaign_mut().selected_campaign = 0;
    let target = app.target_owned().unwrap();
    let key = app.investigation_allowance_key().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: target.clone(),
            key,
            value: ViewHydrationValue::InvestigationAllowance(Err(
                "Owned unavailable allowance".into()
            )),
        });
    let child = std::process::Command::new("/bin/sleep")
        .arg("5")
        .spawn()
        .unwrap();
    app.runtime_state.hold_dispatcher(child, target, ID.into());
    assert_eq!(
        app.scan_study_progress_key(),
        Some(ViewHydrationKey::ScanStudyProgress {
            campaign_id: ID.into()
        })
    );
    let different = tempfile::tempdir().unwrap();
    app.set_target(Some(different.path().into()));
    assert!(app.scan_study_progress_key().is_none());
    let mut child = app.runtime_state.take_dispatcher_child().unwrap();
    let _ = child.kill();
    child.wait().unwrap();
}
