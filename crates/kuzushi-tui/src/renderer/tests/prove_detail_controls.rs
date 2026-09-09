use super::*;
use crate::TerminalViewport;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::WorkflowPhase;

fn press(app: &mut ShellApp, code: KeyCode) {
    press_key(app, KeyEvent::new(code, KeyModifiers::NONE));
}

fn detail_fixture(width: u16, height: u16) -> (tempfile::TempDir, ShellApp) {
    let (target, mut app) = pending_prove_result_fixture();
    let mut selected = app.selected_finding().as_ref().unwrap().clone();
    selected.evidence[0].rationale = (0..30)
        .map(|i| format!("cited evidence row {i} retains the complete source explanation"))
        .collect::<Vec<_>>()
        .join("\n");
    app.findings_mut()[0] = selected.clone();
    *app.selected_finding_mut() = Some(selected);
    app.findings_mut().push(Finding::new_semgrep(
        "second-finding",
        "src/other.rs",
        4,
        None,
        Severity::Medium,
        "another subject",
    ));
    app.set_input_mode(InputMode::Navigate);
    app.set_viewport(TerminalViewport::new(width, height));
    app.router
        .workbench_mut()
        .scroll_mut()
        .set(PhaseSurfaceId::ProveResult, 9);
    (target, app)
}

#[test]
fn pending_trace_routes_scroll_and_draft_to_the_visible_subject() {
    for (width, height) in [(40, 12), (80, 24)] {
        let (_target, mut app) = detail_fixture(width, height);
        let fingerprint = app.selected_finding().as_ref().unwrap().fingerprint.clone();
        let cursor = app.router.findings().cursor();
        press(&mut app, KeyCode::Char('t'));
        let initial = render_phase_app(&app, width, height);
        let bindings = crate::ui_view_models::footer_keybindings(&app);
        assert!(
            bindings
                .iter()
                .any(|b| b.key == "Enter" && b.label == "draft"),
            "{bindings:?}"
        );
        assert!(initial.contains("TRACE · F-0001"), "{initial}");
        assert!(initial.contains("Enter draft"), "{initial}");
        assert!(initial.contains("PgUp/PgDn scroll"), "{initial}");
        assert_eq!(app.phase_result_target_phase(), None);

        for key in [KeyCode::Down, KeyCode::PageDown, KeyCode::Char('G')] {
            press(&mut app, key);
            assert_eq!(app.router.findings().cursor(), cursor);
            assert_eq!(
                app.selected_finding().as_ref().unwrap().fingerprint,
                fingerprint
            );
        }
        assert!(
            app.router
                .workbench()
                .scroll()
                .get(PhaseSurfaceId::ProveTrace)
                > 0
        );
        let bottom = render_phase_app(&app, width, height);
        assert_ne!(bottom, initial);
        assert!(bottom.contains("trace:expand"), "{bottom}");
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            app.input(),
            format!(
                "run trace:expand {}",
                serde_json::json!({"fingerprint": fingerprint})
            )
        );
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert!(!app.has_running_work());
        assert!(!crate::ui_view_models::footer_keybindings(&app)
            .iter()
            .any(|b| b.label == "draft"));
    }
}

#[test]
fn prove_details_park_result_actions_and_escape_restores_the_result() {
    for key in ['v', 't'] {
        let (_target, mut app) = detail_fixture(40, 12);
        let attempt = app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Prove)
            .unwrap()
            .clone();
        press(&mut app, KeyCode::Char(key));
        assert_eq!(app.phase_result_target_phase(), None);
        for key in ['r', 'g', 'u', 'd', 'o'] {
            press(&mut app, KeyCode::Char(key));
            assert!(!app.input().starts_with("run "), "{key}: {}", app.input());
            assert!(!app.has_running_work());
            assert_eq!(app.shell_view(), ShellView::Workbench);
            assert_eq!(
                app.engagement
                    .unresolved_phase_attempt(WorkflowPhase::Prove),
                Some(&attempt)
            );
            app.set_input("");
            app.set_input_mode(InputMode::Navigate);
        }
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.phase_result_target_phase(), Some(WorkflowPhase::Prove));
        assert!(app.router.workbench().investigation_draft().is_none());
        assert!(!app.router.workbench().trace_view_open());
        assert_eq!(
            app.router
                .workbench()
                .scroll()
                .get(PhaseSurfaceId::ProveResult),
            9
        );
        assert!(render_phase_app(&app, 40, 12).contains("RESULT · selected"));
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.shell_view(), ShellView::Replay);
        assert!(!app.has_running_work());
    }
}

#[test]
fn trace_draft_uses_the_remapped_open_key_and_parks_remapped_result_keys() {
    let (_target, mut app) = detail_fixture(40, 12);
    let overrides = [("workbench", "open", "e"), ("phase_result", "open", "b")].map(
        |(context, action, key)| kuzushi_core::config::KeybindingOverrideConfig {
            context: context.into(),
            action: action.into(),
            bindings: vec![key.into()],
        },
    );
    app.ui_mut()
        .replace_runtime_keymap(crate::app::RuntimeKeymap::from_config(&overrides))
        .unwrap();
    press(&mut app, KeyCode::Char('t'));
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(
        bindings.iter().any(|b| b.key == "e" && b.label == "draft"),
        "{bindings:?}"
    );
    assert!(!bindings.iter().any(|b| b.key == "Enter" || b.key == "b"));
    press(&mut app, KeyCode::Char('b'));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(!app.input().starts_with("run "));
    app.set_input("");
    app.set_input_mode(InputMode::Navigate);
    press(&mut app, KeyCode::Enter);
    assert!(app.input().is_empty());
    assert!(!app.has_running_work());
    press(&mut app, KeyCode::Char('e'));
    assert!(app.input().starts_with("run trace:expand "));
    assert!(!app.has_running_work());
    app.set_input("");
    app.set_input_mode(InputMode::Navigate);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('b'));
    assert_eq!(app.shell_view(), ShellView::Replay);
}

#[test]
fn trace_without_a_finding_keeps_the_pending_result_accessible() {
    let (_target, mut app) = detail_fixture(40, 12);
    app.findings_mut().clear();
    *app.selected_finding_mut() = None;
    press(&mut app, KeyCode::Char('t'));
    assert!(!app.router.workbench().trace_view_open());
    assert_eq!(app.phase_result_target_phase(), Some(WorkflowPhase::Prove));
    assert!(app.input().is_empty());
    assert!(!app.has_running_work());
}

#[test]
fn escape_clears_a_detail_draft_before_returning_to_the_result() {
    for key in ['v', 't'] {
        let (_target, mut app) = detail_fixture(40, 12);
        press(&mut app, KeyCode::Char(key));
        if key == 't' {
            press(&mut app, KeyCode::Enter);
        } else {
            // Investigation's Enter intentionally closes its form after drafting.
            // An ordinary typed draft can still be edited over that form.
            app.set_input("an unsent investigation note");
            app.set_input_mode(InputMode::Prompt);
        }
        let draft = app.input().to_string();
        assert!(!draft.is_empty());
        press(&mut app, KeyCode::Esc);
        assert!(app.input().is_empty());
        assert!(app.prove_detail_owns_controls());
        let bindings = crate::ui_view_models::footer_keybindings(&app);
        assert!(bindings.iter().any(|b| b.key == "Esc" && b.label == "back"));
        assert!(!bindings.iter().any(|b| b.label == "draft"));
        app.set_viewport(TerminalViewport::new(80, 24));
        let rendered = render_phase_app(&app, 80, 24);
        assert!(rendered.contains("type a command · Esc back"), "{rendered}");
        assert!(!rendered.contains("Esc list keys"), "{rendered}");
        app.restore_last_cleared_input();
        assert_eq!(app.input(), draft);
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Esc);
        assert!(!app.prove_detail_owns_controls());
        assert!(app.input().is_empty());
        assert_eq!(app.phase_result_target_phase(), Some(WorkflowPhase::Prove));
        assert!(!app.has_running_work());
    }
}

#[test]
fn investigation_title_and_footer_follow_the_remapped_draft_action() {
    let (_target, mut app) = detail_fixture(80, 24);
    let overrides = [kuzushi_core::config::KeybindingOverrideConfig {
        context: "workbench".into(),
        action: "open".into(),
        bindings: vec!["e".into()],
    }];
    app.ui_mut()
        .replace_runtime_keymap(crate::app::RuntimeKeymap::from_config(&overrides))
        .unwrap();
    press(&mut app, KeyCode::Char('v'));
    let rendered = render_phase_app(&app, 80, 24);
    assert!(rendered.contains("F-0001 · INVESTIGATE"), "{rendered}");
    assert!(rendered.contains("e draft"), "{rendered}");
    assert!(!rendered.contains("Enter draft"), "{rendered}");
    press(&mut app, KeyCode::Char('e'));
    assert!(app.input().starts_with("run verify:finding "));
    assert!(app.router.workbench().investigation_draft().is_none());
    assert!(!app.has_running_work());
}

#[test]
fn switching_prove_details_has_one_visible_owner_and_one_back_step() {
    for keys in [['t', 'v'], ['v', 't']] {
        let (_target, mut app) = detail_fixture(40, 12);
        for key in keys {
            press(&mut app, KeyCode::Char(key));
        }
        assert_eq!(app.router.workbench().trace_view_open(), keys[1] == 't');
        assert_eq!(
            app.router.workbench().investigation_draft().is_some(),
            keys[1] == 'v'
        );
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.phase_result_target_phase(), Some(WorkflowPhase::Prove));
    }
}

#[test]
fn prove_detail_error_escape_copy_matches_dismiss_then_back() {
    for mode in [InputMode::Navigate, InputMode::Prompt] {
        let (_target, mut app) = detail_fixture(40, 12);
        press(&mut app, KeyCode::Char('t'));
        app.set_input_mode(mode);
        app.set_error_notice("tool", "Restore the missing helper before retrying.");
        let rendered = render_phase_app(&app, 40, 12);
        assert!(rendered.contains("Esc dismiss"), "{rendered}");
        assert!(!rendered.contains("Esc back"), "{rendered}");
        press(&mut app, KeyCode::Esc);
        assert!(app.advisory().notice.is_none());
        assert!(app.router.workbench().trace_view_open());
        assert!(render_phase_app(&app, 40, 12).contains("Esc back"));
        press(&mut app, KeyCode::Esc);
        assert!(!app.router.workbench().trace_view_open());
    }
}

#[test]
fn prove_detail_completion_keeps_one_escape_back() {
    let (_target, mut app) = detail_fixture(80, 24);
    press(&mut app, KeyCode::Char('t'));
    app.set_success_notice("tool", "Run completed.");
    let rendered = render_phase_app(&app, 80, 24);
    assert!(rendered.contains("Esc back"), "{rendered}");
    assert!(!rendered.contains("Esc dismiss"), "{rendered}");
    press(&mut app, KeyCode::Esc);
    assert!(app.advisory().notice.is_none());
    assert!(!app.router.workbench().trace_view_open());
}
