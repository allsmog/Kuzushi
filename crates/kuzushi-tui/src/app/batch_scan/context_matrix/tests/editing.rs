use super::*;
use crate::app::ShellEffect;

#[test]
fn invalid_name_is_readable_in_narrow_native_and_plain_output() {
    use ratatui::{backend::TestBackend, Terminal};
    let (_root, mut app) = fixture();
    key(&mut app, KeyCode::Char('n'));
    app.handle_batch_config_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    app.reduce_paste("invalid\nname");
    key(&mut app, KeyCode::Enter);
    for (width, height) in [(40, 12), (60, 20)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let native = format!("{:?}", terminal.backend().buffer());
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        for text in [
            "NAME CONTEXT CASE",
            "control characters",
            "Enter save",
            "Esc back",
        ] {
            assert!(native.contains(text), "{native}");
            assert!(plain.contains(text), "{plain}");
        }
    }
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .matrix
            .cases[0]
            .label,
        "Alpha"
    );
}

fn key(app: &mut ShellApp, code: KeyCode) {
    app.handle_batch_config_key(KeyEvent::new(code, KeyModifiers::NONE));
}

#[test]
fn selected_case_inspection_reads_its_exact_revision_and_back_restores_the_case() {
    let (_root, mut app) = fixture();
    app.set_input("kept composer");
    app.set_cursor(4);
    key(&mut app, KeyCode::Down);
    let update = app.handle_context_matrix_key(KeyCode::Enter).unwrap();
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("prepared reader required")
    };
    assert_eq!(request.tool_name, "threat-model:read");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request.input.as_ref().unwrap()).unwrap()
            ["threatModelRef"],
        reference("b")
    );
    assert_eq!(
        app.study_context_picker()
            .unwrap()
            .matrix_case_id
            .as_deref(),
        Some("beta")
    );
    assert!(
        crate::ui_view_models::study_context::context_detail_lines(&app, 120)
            .join("\n")
            .contains("only to case Beta")
    );
    key(&mut app, KeyCode::Esc);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.matrix.open && config.context_picker.is_none());
    assert_eq!(config.study.matrix.cursor, 1);
    assert_eq!(
        config.study.matrix.cases[1].threat_model_ref,
        reference("b")
    );
    assert_eq!((app.input(), app.cursor()), ("kept composer", 4));
}

#[test]
fn omitted_case_inspection_makes_no_request_and_keeps_explicit_omission() {
    let (_root, mut app) = fixture();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .matrix
        .cases[0]
        .threat_model_ref = serde_json::Value::Null;
    assert!(app
        .handle_context_matrix_key(KeyCode::Enter)
        .unwrap()
        .effects
        .is_empty());
    assert_eq!(app.study_context_picker().unwrap().selected, None);
    key(&mut app, KeyCode::Char('a'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.matrix.open);
    assert!(config.study.matrix.cases[0].threat_model_ref.is_null());
}

#[test]
fn rename_keeps_case_identity_baseline_context_repetitions_and_allowance() {
    let (_root, mut app) = fixture();
    app.set_input("kept composer");
    app.set_cursor(4);
    key(&mut app, KeyCode::Char('n'));
    app.handle_batch_config_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    assert!(app.capture_context_case_name_paste("Baseline café"));
    key(&mut app, KeyCode::Enter);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.matrix.cases[0].label, "Baseline café");
    assert_eq!(config.study.matrix.cases[0].id, "alpha");
    assert_eq!(
        config.study.matrix.cases[0].threat_model_ref,
        reference("a")
    );
    assert_eq!(config.study.matrix.cases[0].passes, 3);
    assert_eq!(
        config.study.matrix.baseline_case_id.as_deref(),
        Some("alpha")
    );
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls
        ),
        (Some(8), Some(2))
    );
    assert_eq!(config.study.matrix.cases[1].label, "Beta");
    assert!(!app.context_case_name_editor_open());
    assert_eq!((app.input(), app.cursor()), ("kept composer", 4));
}

#[test]
fn name_rejection_retains_the_uncommitted_field_and_can_be_corrected() {
    let (_root, mut app) = fixture();
    for bad in ["", "line\nbreak", &"é".repeat(129)] {
        key(&mut app, KeyCode::Char('n'));
        app.handle_batch_config_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        app.capture_context_case_name_paste(bad);
        key(&mut app, KeyCode::Enter);
        let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
        assert_eq!(config.study.matrix.cases[0].label, "Alpha");
        assert_eq!(config.context_case_name_edit().unwrap().field.text(), bad);
        assert!(config.context_case_name_edit().unwrap().error.is_some());
        app.handle_batch_config_key(KeyEvent::new(KeyCode::End, KeyModifiers::CONTROL));
        app.handle_batch_config_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        key(&mut app, KeyCode::Esc);
    }
    key(&mut app, KeyCode::Char('n'));
    app.capture_context_case_name_paste("Corrected name");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .matrix
            .cases[0]
            .label,
        "Corrected name"
    );
}

#[test]
fn name_back_retains_draft_cursor_and_field_owns_hotkeys_and_paste() {
    let (_root, mut app) = fixture();
    key(&mut app, KeyCode::Char('n'));
    app.capture_context_case_name_paste(" unsaved");
    key(&mut app, KeyCode::Left);
    key(&mut app, KeyCode::Char('j'));
    let edit = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .context_case_name_edit()
        .unwrap()
        .clone();
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('n'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.context_case_name_edit().unwrap().field, edit.field);
    assert_eq!(config.study.matrix.cursor, 0);
    assert_eq!(config.study.matrix.cases[0].label, "Alpha");
    assert!(app
        .handle_context_case_name_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
        .is_none());
}

#[test]
fn case_context_replacement_refuses_duplicates_and_preserves_siblings() {
    let (_root, mut app) = fixture();
    app.replace_context_case("beta", reference("a"));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        config.study.matrix.cases[1].threat_model_ref,
        reference("b")
    );
    assert!(config.notice.as_ref().unwrap().contains("already included"));
    app.replace_context_case("beta", reference("c"));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        config.study.matrix.cases[1].threat_model_ref,
        reference("c")
    );
    assert_eq!(
        config.study.matrix.cases[0].threat_model_ref,
        reference("a")
    );
    assert_eq!(
        config.study.matrix.baseline_case_id.as_deref(),
        Some("alpha")
    );
    assert_eq!(config.study.matrix.planned_jobs(), 6);
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls
        ),
        (Some(8), Some(2))
    );
}

#[test]
fn removed_case_cannot_redirect_context_or_name_updates() {
    let (_root, mut app) = fixture();
    key(&mut app, KeyCode::Char('n'));
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .matrix
        .cases
        .remove(0);
    key(&mut app, KeyCode::Enter);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .context_case_name_edit()
        .unwrap()
        .error
        .as_ref()
        .unwrap()
        .contains("removed"));
    app.replace_context_case("alpha", reference("c"));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .matrix
            .cases[0]
            .threat_model_ref,
        reference("b")
    );
}

#[test]
fn case_name_field_and_inspection_controls_are_visible_at_every_viewport() {
    use ratatui::{backend::TestBackend, Terminal};
    let (_root, mut app) = fixture();
    key(&mut app, KeyCode::Char('n'));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        for needle in ["NAME CONTEXT CASE", "Alpha", "Enter save", "Esc back"] {
            assert!(screen.contains(needle), "{width}x{height}: {screen}");
        }
    }
}
