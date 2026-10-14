use super::*;
use crate::app::BatchScanConfigRow;
use kuzushi_core::V2Config;
use ratatui::{backend::TestBackend, Terminal};

fn fixture(scoped: bool) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.open_batch_scan_config(None);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    let mut input = json!({"taskMode":"auto","triage":false,"verify":false,"autoPatch":false,"threatModelRef":null,"semgrepConfig":["operator-rules.yml"]});
    if scoped {
        input["scanScopeRef"] = json!({"proposal":{"proposalId":"missing","revision":1,"recordHash":"a".repeat(64)},"scopeId":"named-scope"});
    }
    config.study.scan_input = Some(input);
    config.cursor = BatchScanConfigRow::ALL
        .iter()
        .position(|row| *row == BatchScanConfigRow::Engines)
        .unwrap();
    app.open_study_engine_picker();
    (root, app)
}

fn focus(app: &mut ShellApp, id: &str) {
    let index = crate::ui_view_models::study_engines::engine_rows(app)
        .iter()
        .position(|row| row.id.as_deref() == Some(id))
        .unwrap();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .engine_picker
        .as_mut()
        .unwrap()
        .cursor = index;
}

#[test]
fn scoped_engine_choices_explain_unsupported_work_and_cancel_without_changing_the_study() {
    let (_root, mut app) = fixture(true);
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    focus(&mut app, "systems-hunt");
    let update = app.handle_study_engine_key(KeyCode::Char(' '));
    assert!(update.effects.is_empty());
    assert!(app
        .study_engine_picker()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Unsupported"));
    assert!(app.study_engine_picker().unwrap().automatic);
    focus(&mut app, "secret-scan");
    app.handle_study_engine_key(KeyCode::Char(' '));
    assert_eq!(
        app.study_engine_picker().unwrap().selected,
        BTreeSet::from(["secret-scan".into()])
    );
    app.handle_study_engine_key(KeyCode::Esc);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        original
    );
}

#[test]
fn scoped_agentic_choice_requires_explicit_file_tools_and_preserves_cancelled_options() {
    let (_root, mut app) = fixture(true);
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .engine_picker
        .as_mut()
        .unwrap()
        .input["mcps"] = json!(true);
    focus(&mut app, "agentic");
    app.handle_study_engine_key(KeyCode::Char(' '));
    assert!(app.study_engine_picker().unwrap().automatic);
    assert!(crate::ui_view_models::study_engines::engine_apply_controls(&app).contains("m files"));
    app.handle_study_engine_key(KeyCode::Char('m'));
    assert_eq!(
        app.study_engine_picker().unwrap().input["mcps"],
        json!(false)
    );
    app.handle_study_engine_key(KeyCode::Char(' '));
    assert_eq!(
        app.study_engine_picker().unwrap().selected,
        BTreeSet::from(["agentic".into()])
    );
    app.handle_study_engine_key(KeyCode::Esc);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        original
    );
}

#[test]
fn engine_changes_preserve_scope_context_custom_options_and_investigation_limits() {
    let (_root, mut app) = fixture(true);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(12);
    config.study.protected_review_calls = Some(4);
    let id = config.study.investigation_id.clone();
    let source = config.study.scan_input.clone().unwrap();
    let options = app.option_store().clone();
    focus(&mut app, "secret-scan");
    app.handle_study_engine_key(KeyCode::Enter);
    let update = app.handle_study_engine_key(KeyCode::Char('a'));
    assert!(update.effects.is_empty());
    assert!(app.study_engine_picker().is_none());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    let input = config.study.scan_input.as_ref().unwrap();
    assert_eq!(input["tasks"], json!(["secret-scan"]));
    for key in ["scanScopeRef", "threatModelRef", "semgrepConfig"] {
        assert_eq!(input[key], source[key]);
    }
    assert_eq!(config.study.investigation_id, id);
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls
        ),
        (Some(12), Some(4))
    );
    assert_eq!(
        app.option_store().effective_stored_values("sast:scan"),
        options.effective_stored_values("sast:scan")
    );
}

#[test]
fn empty_selection_cannot_replace_a_saved_draft() {
    let (_root, mut app) = fixture(false);
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .scan_input
        .clone();
    let picker = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .engine_picker
        .as_mut()
        .unwrap();
    picker.automatic = false;
    picker.selected.clear();
    app.handle_study_engine_key(KeyCode::Char('a'));
    assert!(app.study_engine_picker().unwrap().notice.is_some());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .scan_input,
        original
    );
}

#[test]
fn engine_picker_owns_paste_and_renders_all_sizes_with_exhaustive_plain_details() {
    let (_root, mut app) = fixture(true);
    app.set_input("preserved draft");
    app.reduce_paste("hidden command\nsecond line");
    assert_eq!(app.input(), "preserved draft");
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            text.contains("CHOOSE DISCOVERY ENGINES"),
            "{width}x{height}"
        );
        assert!(text.contains("a apply choices"), "{width}x{height}");
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("UNSUPPORTED"));
    assert!(plain.contains("secret-scan"));
    assert!(plain.contains("No jobs start"));
}

#[test]
fn task_order_survives_unchanged_selection_and_deliberate_edits() {
    let mut picker = StudyEnginePicker::new(json!({
        "taskMode":"manual", "tasks":["secret-scan", "semgrep"]
    }));
    assert_eq!(
        picker.prepared_selection()["tasks"],
        json!(["secret-scan", "semgrep"])
    );
    let row = crate::ui_view_models::study_engines::StudyEngineRow {
        id: Some("secret-scan".into()),
        label: "secret-scan".into(),
        notes: String::new(),
        selected: true,
        unsupported: None,
    };
    toggle_explicit_engine(&mut picker, &row);
    assert_eq!(picker.prepared_selection()["tasks"], json!(["semgrep"]));
    toggle_explicit_engine(&mut picker, &row);
    assert_eq!(
        picker.prepared_selection()["tasks"],
        json!(["semgrep", "secret-scan"])
    );
}

#[test]
fn applying_unchanged_engines_retains_the_saved_study() {
    let (_root, mut app) = fixture(true);
    focus(&mut app, "secret-scan");
    app.handle_study_engine_key(KeyCode::Enter);
    app.handle_study_engine_key(KeyCode::Char('a'));
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.campaign_id = Some("saved-study".into());
    let original = config.study.clone();
    app.open_study_engine_picker();
    app.handle_study_engine_key(KeyCode::Char('a'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study, original);
    assert!(config.notice.as_ref().unwrap().contains("choices retained"));
}

#[test]
fn selected_unknown_engine_is_removable_without_discarding_supported_choices() {
    let (_root, mut app) = fixture(true);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .scan_input = Some(json!({"taskMode":"manual", "tasks":["retired-engine", "secret-scan"]}));
    app.open_study_engine_picker();
    focus(&mut app, "retired-engine");
    app.handle_study_engine_key(KeyCode::Enter);
    app.handle_study_engine_key(KeyCode::Char('a'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        config.study.scan_input.as_ref().unwrap()["tasks"],
        json!(["secret-scan"])
    );
}

#[test]
fn narrow_engine_details_show_position_and_reach_the_final_guidance() {
    let (_root, mut app) = fixture(true);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    focus(&mut app, "agentic");
    let model = crate::ui_view_models::study_engines::engine_layout(40, 12, 14);
    let initial = crate::ui_view_models::study_engines::engine_read_position(&app, model.detail);
    for _ in 0..30 {
        app.handle_study_engine_key(KeyCode::PageDown);
    }
    let final_position =
        crate::ui_view_models::study_engines::engine_read_position(&app, model.detail);
    assert_ne!(initial, final_position);
    let lines =
        crate::ui_view_models::study_engines::engine_detail(&app, model.detail.width as usize);
    assert_eq!(
        app.study_engine_picker().unwrap().scroll,
        lines.len() - model.detail.height as usize
    );
    assert!(lines.last().unwrap().contains("guarantee."));
}

fn path_conflict_fixture(scoped: bool) -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture(scoped);
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool("sast:scan".into()),
        "paths",
        json!(["older/scope"]),
    );
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    let input = config.study.scan_input.as_mut().unwrap();
    input["taskMode"] = json!("manual");
    input["tasks"] = json!(["secret-scan"]);
    input["paths"] = json!(["older/scope"]);
    config.study.campaign_id = Some("saved-study".into());
    config.study.max_provider_calls = Some(8);
    config.study.protected_review_calls = Some(2);
    app.open_study_engine_picker();
    (root, app)
}

#[test]
fn clearing_path_conflicts_is_local_and_cancel_restores_the_original_study() {
    let (_root, mut app) = path_conflict_fixture(true);
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    assert!(app
        .study_engine_picker()
        .unwrap()
        .conflicting_paths()
        .is_some());
    let update = app.handle_study_engine_key(KeyCode::Char('x'));
    assert!(update.effects.is_empty());
    assert!(app
        .study_engine_picker()
        .unwrap()
        .conflicting_paths()
        .is_none());
    assert_eq!(
        app.study_engine_picker().unwrap().prepared_selection()["paths"],
        json!([])
    );
    app.handle_study_engine_key(KeyCode::Esc);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        original
    );
    assert_eq!(
        app.option_store().effective_stored_values("sast:scan")["paths"],
        json!(["older/scope"])
    );
}

#[test]
fn applying_path_replacement_retains_accepted_scope_context_and_consumption() {
    let (_root, mut app) = path_conflict_fixture(true);
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    app.handle_study_engine_key(KeyCode::Char('x'));
    let update = app.handle_study_engine_key(KeyCode::Char('a'));
    assert!(update.effects.is_empty());
    let study = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study;
    assert_eq!(study.campaign_id, None);
    assert_eq!(study.investigation_id, original.investigation_id);
    assert_eq!(study.allowance, original.allowance);
    assert_eq!(
        (study.max_provider_calls, study.protected_review_calls),
        (Some(8), Some(2))
    );
    let input = study.scan_input.as_ref().unwrap();
    for key in ["scanScopeRef", "threatModelRef", "semgrepConfig", "tasks"] {
        assert_eq!(input[key], original.scan_input.as_ref().unwrap()[key]);
    }
    let prepared = app
        .registry()
        .prepare_tool_input("sast:scan", input.clone(), Some(app.option_store()))
        .unwrap();
    assert_eq!(prepared["paths"], json!([]));
    assert_eq!(
        app.option_store().effective_stored_values("sast:scan")["paths"],
        json!(["older/scope"])
    );
}

#[test]
fn path_replacement_is_visible_at_all_sizes_and_unavailable_without_an_accepted_ref() {
    let (_root, app) = path_conflict_fixture(true);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
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
        for control in ["a apply · x clear", "m files", "Esc"] {
            assert!(text.contains(control), "{width}x{height}: {control}");
        }
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("Earlier filters:"));
    assert!(plain.contains("older/scope"));
    for control in ["a apply · x clear", "m files", "Esc"] {
        assert!(plain.contains(control));
    }
    let (_root, mut unscoped) = path_conflict_fixture(false);
    let original = unscoped.study_engine_picker().unwrap().prepared_selection();
    unscoped.handle_study_engine_key(KeyCode::Char('x'));
    assert_eq!(
        unscoped.study_engine_picker().unwrap().prepared_selection(),
        original
    );
    assert!(
        !crate::ui_view_models::study_engines::engine_apply_controls(&unscoped).contains("x clear")
    );
}
