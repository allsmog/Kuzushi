use super::*;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct DelayedAllowanceReader {
    entered: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}

impl ViewArtifactReader for DelayedAllowanceReader {
    fn read(&self, _target: &Path, _key: &ViewHydrationKey) -> ViewHydrationValue {
        self.entered.store(true, Ordering::Release);
        let _ = self
            .wake
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(3),
                |released| !*released,
            )
            .unwrap();
        ViewHydrationValue::InvestigationAllowance(Err("Owned delayed read".into()))
    }
}

fn app_with_attempts(root: &Path) -> ShellApp {
    for (phase, run) in [(WorkflowPhase::Map, "map"), (WorkflowPhase::Scan, "scan")] {
        crate::test_support::record_indexed_run(
            root,
            run,
            "sast:scan",
            serde_json::json!({"ok":true,"summary":"Owned recorded phase fixture"}),
        );
        let completed = crate::test_support::append_typed_attempt(
            root,
            phase,
            run,
            kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
        );
        crate::test_support::select_typed_attempt(root, &completed);
    }
    let workspace = WorkspaceTarget::new(root).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.refresh_phase_attempt_projection();
    app.set_shell_view(ShellView::Workbench);
    app
}

#[test]
fn allowance_binding_follows_displayed_phase_and_never_substitutes_latest_target_history() {
    let root = tempfile::tempdir().unwrap();
    let mut app = app_with_attempts(root.path());
    crate::test_support::record_indexed_run(
        root.path(),
        "pending",
        "sast:scan",
        serde_json::json!({"ok":true}),
    );
    crate::test_support::append_typed_attempt(
        root.path(),
        WorkflowPhase::Scan,
        "pending",
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    app.refresh_phase_attempt_projection();
    for (page, run) in [
        (WorkbenchPage::Map, "map"),
        (WorkbenchPage::Scan, "pending"),
        (WorkbenchPage::Review, "scan"),
    ] {
        app.router.workbench_mut().set_page(Some(page));
        assert_eq!(
            app.investigation_allowance_key(),
            Some(ViewHydrationKey::InvestigationAllowance {
                run_refs: vec![run.into()]
            })
        );
    }
    app.set_shell_view(ShellView::Replay);
    assert!(
        app.investigation_allowance_key().is_none(),
        "Replay retains its separate recorded-request accounting"
    );
}

#[test]
fn delayed_allowance_read_preserves_navigation_draft_and_focus() {
    let root = tempfile::tempdir().unwrap();
    let reader = Arc::new(DelayedAllowanceReader::default());
    let mut app = app_with_attempts(root.path());
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Scan));
    let key = app.investigation_allowance_key().unwrap();
    let target = app.target().unwrap().to_path_buf();
    app.set_view_artifact_reader_for_test(reader.clone());
    app.set_input("held operator draft");
    let start = Instant::now();
    app.schedule_view_hydration_keys(target.clone(), vec![key.clone()]);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !reader.entered.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    app.set_shell_view(ShellView::Report);
    assert!(start.elapsed() < Duration::from_millis(250));
    *reader.released.lock().unwrap() = true;
    reader.wake.notify_all();
    while !matches!(
        app.workbench_cache()
            .borrow()
            .cached_investigation_allowance(&target, &key),
        ViewDataState::Ready(_)
    ) {
        assert!(Instant::now() < deadline);
        app.apply_view_hydration_results();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input(), "held operator draft");
}

#[test]
fn unavailable_allowance_never_looks_like_zero_usage_in_rail_footer_or_plain_output() {
    let root = tempfile::tempdir().unwrap();
    let mut app = app_with_attempts(root.path());
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Scan));
    let key = app.investigation_allowance_key().unwrap();
    let target = app.target().unwrap().to_path_buf();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::InvestigationAllowance(Err("Owned missing ledger".into())),
        });
    let rail = crate::ui_view_models::rail_sections(&app, 40);
    assert!(!rail.iter().any(|section| section.title == "SESSION COST"));
    let section = rail
        .iter()
        .find(|section| section.title == "INVESTIGATION ALLOWANCE")
        .unwrap();
    assert!(section
        .rows
        .iter()
        .any(|line| line.to_string().contains("Ledger unavailable")));
    let footer = crate::ui_view_models::status_footer_model(&app);
    assert_eq!(footer.compact_right_segments, ["calls unavailable"]);
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("INVESTIGATION ALLOWANCE"));
    assert!(plain.contains("Owned missing ledger"));
    assert!(!plain.contains("No spend recorded"));
    assert!(!plain.contains('\u{1b}'));
}

#[test]
fn shared_call_counter_survives_source_warning_and_longest_policy_at_every_viewport() {
    use kuzushi_core::{
        allowance::{AllowanceLimits, AllowanceSnapshot},
        runtime::RuntimeCostReport,
    };
    use ratatui::{backend::TestBackend, Terminal};
    let root = tempfile::tempdir().unwrap();
    let mut app = app_with_attempts(root.path());
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Scan));
    app.config_mut().autonomy = kuzushi_core::modules::autonomy::AutonomyPosture::Review;
    app.domain_mut().set_returning_source_unverified(true);
    let key = app.investigation_allowance_key().unwrap();
    let target = app.target().unwrap().to_path_buf();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::InvestigationAllowance(Ok(Some(Arc::new(
                AllowanceSnapshot {
                    schema_version: 1,
                    investigation_id: "owned".into(),
                    revision: 1,
                    model: "operator:model".into(),
                    limits: AllowanceLimits {
                        max_provider_calls: 6,
                        protected_review_calls: 2,
                    },
                    committed_calls: 4,
                    review_calls: 0,
                    unresolved_calls: 1,
                    cost: RuntimeCostReport::UNAVAILABLE,
                    work_plan: None,
                },
            )))),
        });
    for page in [WorkbenchPage::Scan, WorkbenchPage::Review] {
        app.router.workbench_mut().set_page(Some(page));
        for mode in [InputMode::Prompt, InputMode::Navigate] {
            app.set_input_mode(mode);
            for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal
                    .draw(|frame| crate::renderer::render_app(frame, &app))
                    .unwrap();
                let text: String = terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect();
                assert!(text.contains("calls 4/6"), "{width}x{height}: {text}");
                assert!(text.contains("autonomy:review"), "{width}x{height}: {text}");
                let warning = if width < 80 {
                    "⚠ source"
                } else {
                    "history:check source"
                };
                assert!(text.contains(warning), "{width}x{height}: {text}");
            }
        }
    }
}
