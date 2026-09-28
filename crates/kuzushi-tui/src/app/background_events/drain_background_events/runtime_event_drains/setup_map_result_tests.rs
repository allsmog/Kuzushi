use super::*;
use kuzushi_core::workflow_attempts::{PhaseAttemptOutcome, PhaseResultAction};

const RUN_ID: &str = "setup-map-context";

fn completed_map() -> (tempfile::TempDir, ShellApp) {
    map_fixture(true)
}

fn map_fixture(indexed: bool) -> (tempfile::TempDir, ShellApp) {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().canonicalize().unwrap();
    std::fs::write(target.join("lib.rs"), "pub fn example() {}\n").unwrap();
    if indexed {
        crate::test_support::record_indexed_run(
            &target,
            RUN_ID,
            "context:build",
            serde_json::json!({"ok":true,"data":{"snapshot":{"filesIndexed":1}}}),
        );
    } else {
        record_context_result(&target);
    }
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target));
    app.set_shell_view(ShellView::Setup);
    app.set_input_mode(InputMode::Navigate);
    let session = ActivitySession::for_phase(RUN_ID, WorkflowPhase::Map)
        .with_phase_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new());
    let mut session = app.capture_run_focus_origin(session);
    session.mark_run_focus_terminal_pending("completed");
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    app.engagement.set_phase(WorkflowPhase::Scan);
    (dir, app)
}

fn record_context_result(target: &std::path::Path) {
    let record =
        kuzushi_core::run_artifacts::ToolRunRecord::new(target, RUN_ID, "tool", "context:build");
    kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &serde_json::json!({}),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    kuzushi_core::run_artifacts::record_tool_run_complete(
        record,
        &serde_json::json!({"ok":true,"data":{"snapshot":{"filesIndexed":1}}}),
    );
}

#[test]
fn completed_setup_map_presents_its_result_without_selecting_it() {
    let (_target, mut app) = completed_map();
    app.set_input("retained shell draft");

    assert!(app.finalize_run_focus_if_idle());

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(
        crate::ui_view_models::active_workbench_page(&app),
        WorkbenchPage::Map
    );
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert_eq!(app.input(), "retained shell draft");
    let attempt = app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .unwrap();
    assert_eq!(attempt.completed.outcome, PhaseAttemptOutcome::Completed);
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Scan));
}

fn render(app: &mut ShellApp, width: u16, height: u16) -> String {
    app.set_viewport(crate::TerminalViewport::new(width, height));
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn completed_setup_map_renders_acceptance_at_ordinary_sizes() {
    for (width, height) in [(80, 24), (120, 36)] {
        let (_target, mut app) = completed_map();
        assert!(app.finalize_run_focus_if_idle());
        let text = render(&mut app, width, height);
        assert!(text.contains("Use map"), "{text}");
        assert!(!text.contains("NOTHING TO RUN"), "{text}");
        let card = crate::ui_view_models::phase_cockpit_model(&app)
            .unwrap()
            .header
            .result_card
            .unwrap();
        assert!(card.actions.contains(&PhaseResultAction::Select));
        assert!(app
            .engagement
            .selected_phase_attempt(WorkflowPhase::Map)
            .is_none());
    }
}

fn check_origin_guard(change: impl FnOnce(&mut ShellApp), expected: ShellView) {
    let (_target, mut app) = completed_map();
    change(&mut app);
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), expected);
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
}

#[test]
fn completed_setup_map_never_takes_background_or_manual_focus() {
    check_origin_guard(
        |app| {
            app.activity_mut().unwrap().run_focus_backgrounded = true;
            app.set_shell_view(ShellView::Setup);
        },
        ShellView::Setup,
    );
    check_origin_guard(
        |app| {
            app.activity_mut()
                .unwrap()
                .run_focus_origin
                .as_mut()
                .unwrap()
                .auto_return = false;
        },
        ShellView::Activity,
    );
    check_origin_guard(
        |app| {
            app.activity_mut().unwrap().run_focus_origin = None;
        },
        ShellView::Activity,
    );
    check_origin_guard(
        |app| app.set_shell_view(ShellView::Catalog),
        ShellView::Catalog,
    );
}

#[test]
fn completed_setup_map_preserves_other_origins_and_unrecorded_results() {
    check_origin_guard(
        |app| {
            app.activity_mut()
                .unwrap()
                .run_focus_origin
                .as_mut()
                .unwrap()
                .view = ShellView::Home;
        },
        ShellView::Home,
    );
    check_origin_guard(
        |app| {
            app.activity_mut().unwrap().run_focus_receipt = None;
        },
        ShellView::Setup,
    );
    check_origin_guard(
        |app| {
            app.activity_mut()
                .unwrap()
                .run_focus_receipt
                .as_mut()
                .unwrap()
                .origin_phase = Some(WorkflowPhase::Scan);
        },
        ShellView::Setup,
    );
}

fn published_map() -> (tempfile::TempDir, ShellApp) {
    let (target, mut app) = completed_map();
    assert!(app.finalize_run_focus_if_idle());
    app.set_shell_view(ShellView::Setup);
    (target, app)
}

fn inspect_result_destination(app: &mut ShellApp) {
    let origin = app
        .activity()
        .and_then(|activity| activity.run_focus_origin);
    app.open_completed_run_destination(origin, None);
}

#[test]
fn completed_setup_map_requires_a_successful_published_receipt() {
    for outcome in ["failed", "partial", "blocked", "canceled", "interrupted"] {
        let (_target, mut app) = published_map();
        app.activity_mut()
            .unwrap()
            .run_focus_receipt
            .as_mut()
            .unwrap()
            .outcome = outcome.into();
        inspect_result_destination(&mut app);
        assert_eq!(app.shell_view(), ShellView::Setup, "{outcome}");
    }
}

#[test]
fn completed_setup_map_requires_its_exact_unresolved_attempt() {
    let (_target, mut app) = published_map();
    app.activity_mut()
        .unwrap()
        .run_focus_receipt
        .as_mut()
        .unwrap()
        .attempt_id = Some("missing-attempt".into());
    inspect_result_destination(&mut app);
    assert_eq!(app.shell_view(), ShellView::Setup);
}

#[test]
fn completed_setup_map_does_not_reuse_another_targets_result() {
    let (_target, mut app) = published_map();
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().to_path_buf()));
    app.set_shell_view(ShellView::Setup);
    inspect_result_destination(&mut app);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .is_none());
}

#[test]
fn completed_setup_map_requires_a_healthy_attempt_projection() {
    let (target, mut app) = published_map();
    let ledger = kuzushi_core::workflow_attempts::load_phase_attempt_ledger(target.path()).unwrap();
    let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path());
    app.engagement
        .set_phase_attempt_projection_health(Some(snapshot), ledger, true);
    inspect_result_destination(&mut app);
    assert_eq!(app.shell_view(), ShellView::Setup);
}

#[test]
fn completed_setup_map_preserves_prompt_typing_ownership() {
    let (_target, mut app) = completed_map();
    app.activity_mut()
        .unwrap()
        .run_focus_origin
        .as_mut()
        .unwrap()
        .input_mode = InputMode::Prompt;
    app.set_input("draft ");
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.input_mode(), InputMode::Prompt);
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('u'),
        crossterm::event::KeyModifiers::NONE,
    ));
    assert_eq!(app.input(), "draft u");
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
}

#[test]
fn completed_setup_map_arms_the_card_it_presents_over_an_empty_composer() {
    let (_target, mut app) = completed_map();
    app.activity_mut()
        .unwrap()
        .run_focus_origin
        .as_mut()
        .unwrap()
        .input_mode = InputMode::Prompt;

    assert!(app.finalize_run_focus_if_idle());

    assert_eq!(app.input_mode(), InputMode::Navigate);
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('u'),
        crossterm::event::KeyModifiers::NONE,
    ));
    assert_eq!(app.input(), "");
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_some());
}

mod acceptance;
