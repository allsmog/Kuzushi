use super::*;
use crate::ui_view_models::PhaseSurfaceId;
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use kuzushi_core::V2Config;

fn wb_focus(app: &ShellApp) -> crate::ui_view_models::PhaseSurfaceId {
    app.router
        .workbench()
        .focus_for(crate::ui_view_models::active_workbench_page(app))
}
#[test]
fn update_routes_terminal_key_events() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert_eq!(app.input(), "x");
}

#[test]
fn update_routes_command_messages() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(&mut app, Msg::Cmd(ShellCommand::Help(None)));

    assert!(result.changed);
    assert!(result.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Help);
}

#[test]
fn update_routes_scripted_scan_as_effect_data() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(
        &mut app,
        Msg::Cmd(ShellCommand::ScriptedScan(Some(tmp.path().to_path_buf()))),
    );

    assert!(result.changed);
    assert_eq!(result.effects.len(), 1);
    assert!(matches!(
        result.effects[0],
        ShellEffect::ActivateTarget(TargetActivation {
            source: TargetActivationSource::ScriptedScan,
            ..
        })
    ));
    assert!(app.scan().is_none());
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn targetless_scripted_scan_keeps_the_existing_prepare_path() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let result = update(&mut app, Msg::Cmd(ShellCommand::ScriptedScan(None)));

    assert!(result.changed);
    assert!(matches!(
        result.effects.as_slice(),
        [ShellEffect::PrepareScan(ScanStartPreparation {
            target: None,
            ..
        })]
    ));
    assert_eq!(app.target(), Some(workspace.root()));
}

#[test]
fn update_returns_command_effects_without_executing_them() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(&mut app, Msg::Cmd(ShellCommand::Quit));

    assert!(result.changed);
    assert_eq!(result.effects.len(), 1);
    assert!(matches!(result.effects[0], ShellEffect::Quit));
    assert!(!app.should_quit());
}

#[test]
fn update_terminal_enter_returns_submit_effects_without_executing_them() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let history_path = tmp.path().join(".kuzushi/v3/shell-history.txt");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Home);
    app.set_input("tools");
    app.set_cursor(app.input().chars().count());

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert_eq!(app.input(), "");
    assert_eq!(app.shell_view(), ShellView::Tools);
    assert!(result
        .effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::PersistCommandHistory)));
    assert!(!history_path.exists());
}

#[test]
fn update_terminal_picker_demo_command_returns_effect_without_executing_it() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.open_model_picker();

    for code in [
        KeyCode::Char(':'),
        KeyCode::Char('d'),
        KeyCode::Char('e'),
        KeyCode::Char('m'),
        KeyCode::Char('o'),
    ] {
        update(
            &mut app,
            Msg::Term(TermEvent::Key(KeyEvent::new(code, KeyModifiers::empty()))),
        );
    }
    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert!(result
        .effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::StartOfflineDemoFixtureScan)));
    assert!(app.scan_is_none());
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn update_terminal_pending_question_plan_opens_budgeted_form_without_work() {
    let target = tempfile::tempdir().expect("agent target");
    crate::test_support::record_imported_test_map(target.path(), "accepted-map");
    let completed = crate::test_support::append_typed_attempt(
        target.path(),
        kuzushi_core::WorkflowPhase::Map,
        "accepted-map",
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(target.path(), &completed);
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(target.path().to_path_buf()));
    app.session_mut().mark_session_api_key_ready("openai");
    app.refresh_phase_attempt_projection();
    app.hydrate_all_view_data_for_test();
    app.set_pending_plan(PlanProposal {
        goal: "g".to_string(),
        summary: "s".to_string(),
        changes: vec![PlanChange::Ask {
            question: "inspect authz drift".to_string(),
        }],
        unsupported: vec![],
    });

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('y'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert!(!app.engagement.has_pending_plan());
    assert!(result.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    let generation = app.context_generation().expect("question plan");
    assert!(generation.is_question());
    assert_eq!(generation.context_input["question"], "inspect authz drift");
    assert!(generation.context_input["threatModelRef"].is_object());
    assert!(generation.receipt.is_none());
    assert!(!app.has_running_work());
}

#[test]
fn update_terminal_paste_returns_changed_without_effects() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(&mut app, Msg::Term(TermEvent::Paste("hello".to_string())));

    assert!(result.changed);
    assert!(result.effects.is_empty());
    assert_eq!(app.input(), "hello");
}

#[test]
fn update_terminal_empty_paste_is_ignored() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(&mut app, Msg::Term(TermEvent::Paste(String::new())));

    assert!(!result.changed);
    assert!(result.effects.is_empty());
    assert_eq!(app.input(), "");
}

#[test]
fn update_terminal_resize_records_viewport_state() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Resize {
            columns: 0,
            rows: 24,
        }),
    );

    assert!(result.changed);
    assert_eq!(app.viewport(), TerminalViewport::new(1, 24));
}

#[test]
fn update_terminal_mouse_uses_recorded_viewport_for_hit_testing() {
    let (mut app, column, row) = review_detail_hit_test_fixture();

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::empty(),
        })),
    );

    assert!(result.changed);
    assert_eq!(wb_focus(&app), PhaseSurfaceId::ReviewDetail);
}

fn review_detail_hit_test_fixture() -> (ShellApp, u16, u16) {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.set_findings(vec![kuzushi_core::Finding::new_tool(
        "test",
        "test/viewport",
        "src/lib.rs",
        1,
        None,
        kuzushi_core::Severity::High,
        "viewport hit-test fixture",
    )]);
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    update(
        &mut app,
        Msg::Term(TermEvent::Resize {
            columns: 80,
            rows: 20,
        }),
    );
    let viewport = app.viewport();
    let plan = crate::renderer::workbench_phase_plan_for_app(
        &app,
        ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
    )
    .expect("workbench presentation plan");
    let detail = plan
        .surface(crate::ui_view_models::PhaseSurfaceId::ReviewDetail)
        .expect("visible review detail");
    (
        app,
        detail.rect.x + detail.rect.width / 2,
        detail.rect.y + detail.rect.height / 2,
    )
}

#[test]
fn handle_command_executes_command_effects() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.handle_command(ShellCommand::Quit);

    assert!(app.should_quit());
}

#[test]
fn update_and_execute_effects_runs_returned_effects() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let changed = update_and_execute_effects(&mut app, Msg::Cmd(ShellCommand::Quit));

    assert!(changed);
    assert!(app.should_quit());
}

#[test]
fn update_routes_tick_messages() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let now = Instant::now();
    app.set_throttle("test", "stale");
    app.advisory_mut().throttle.as_mut().unwrap().since =
        now - THROTTLE_STALE_AFTER - Duration::from_millis(1);

    let result = update(&mut app, Msg::Tick(now));

    assert!(result.changed);
    assert!(app.advisory().throttle.is_none());
}
