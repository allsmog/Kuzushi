use super::*;
use kuzushi_core::V2Config;

fn fixture(tool: &str, option: &str, filter: OptionsFilter) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.show_options(Some(tool.into()), filter);
    app.router.options_browser_mut().selected = Some(option.into());
    app
}

fn key(app: &mut ShellApp, code: KeyCode) -> InputUpdate {
    app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
}

#[test]
fn selection_edit_and_session_save_preserve_the_composer_and_do_not_dispatch() {
    let mut app = fixture("context:build", "enrichment", OptionsFilter::Advanced);
    app.set_input("kept operator\ndraft");
    app.set_cursor(4);
    assert!(key(&mut app, KeyCode::Enter).effects.is_empty());
    app.router
        .options_browser_mut()
        .edit
        .as_mut()
        .unwrap()
        .field = FieldEditor::new("true");
    let saved = app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert!(saved.effects.is_empty());
    assert_eq!(
        app.option_store().effective_stored_values("context:build")["enrichment"],
        serde_json::json!(true)
    );
    assert_eq!((app.input(), app.cursor()), ("kept operator\ndraft", 4));
    assert_eq!(app.selected_browser_option().as_deref(), Some("enrichment"));
    assert!(!app.tool_option_editor_open());
    assert!(!app.has_running_work());
}

#[test]
fn invalid_value_keeps_the_editor_and_old_setting_until_a_valid_save() {
    let mut app = fixture("context:build", "sampleLimit", OptionsFilter::Standard);
    key(&mut app, KeyCode::Enter);
    app.router
        .options_browser_mut()
        .edit
        .as_mut()
        .unwrap()
        .field = FieldEditor::new("not-a-number");
    let update = key(&mut app, KeyCode::Enter);
    assert!(update.effects.is_empty());
    let edit = app.router.options_browser().edit.as_ref().unwrap();
    assert_eq!(edit.field.text(), "not-a-number");
    assert!(edit.error.is_some());
    assert!(!app
        .option_store()
        .effective_stored_values("context:build")
        .contains_key("sampleLimit"));
    app.router
        .options_browser_mut()
        .edit
        .as_mut()
        .unwrap()
        .field = FieldEditor::new("7");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.option_store().effective_stored_values("context:build")["sampleLimit"],
        serde_json::json!(7)
    );
}

#[test]
fn cancellation_and_tool_switch_keep_multiline_field_drafts_and_cursor() {
    let mut app = fixture("threat-model:ask", "question", OptionsFilter::Standard);
    key(&mut app, KeyCode::Enter);
    app.reduce_paste("Operator α\nsecond line");
    let field = app
        .router
        .options_browser()
        .edit
        .as_ref()
        .unwrap()
        .field
        .clone();
    key(&mut app, KeyCode::Esc);
    assert!(!app.tool_option_editor_open());
    assert!(!app
        .option_store()
        .effective_stored_values("threat-model:ask")
        .contains_key("question"));
    app.show_options(Some("context:build".into()), OptionsFilter::Standard);
    app.show_options(Some("threat-model:ask".into()), OptionsFilter::Standard);
    app.router.options_browser_mut().selected = Some("question".into());
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.router.options_browser().edit.as_ref().unwrap().field,
        field
    );
}

#[test]
fn workflow_supplied_references_are_visible_missing_and_cannot_be_edited() {
    let mut app = fixture("threat-model:ask", "allowanceRef", OptionsFilter::Missing);
    assert!(app
        .option_browser_rows()
        .iter()
        .any(|row| row.cells[0] == "allowanceRef" && row.cells[3] == "missing"));
    key(&mut app, KeyCode::Enter);
    assert!(!app.tool_option_editor_open());
    assert!(app
        .router
        .options_browser()
        .notice
        .as_ref()
        .unwrap()
        .contains("supplied by the workflow"));
}

#[test]
fn declared_structured_setting_saves_and_reopens_without_running_work() {
    let mut app = fixture("uaf-hunt:hunt", "allocFreePairs", OptionsFilter::Advanced);
    app.set_input("kept composer");
    key(&mut app, KeyCode::Enter);
    assert!(app.tool_option_editor_open());
    app.reduce_paste(r#"[{"alloc":"owned_alloc","free":"owned_free"}]"#);
    assert!(key(&mut app, KeyCode::Enter).effects.is_empty());
    let expected = serde_json::json!([{"alloc":"owned_alloc","free":"owned_free"}]);
    assert_eq!(
        app.option_store().effective_stored_values("uaf-hunt:hunt")["allocFreePairs"],
        expected
    );
    assert_eq!(app.input(), "kept composer");
    key(&mut app, KeyCode::Enter);
    let value = app
        .router
        .options_browser()
        .edit
        .as_ref()
        .unwrap()
        .field
        .text();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(value).unwrap(),
        expected
    );
    assert!(!app.has_running_work());
}

#[test]
fn malformed_structured_setting_keeps_the_draft_and_previous_value() {
    let mut app = fixture(
        "uaf-hunt:hunt",
        "extraAllocFreePairs",
        OptionsFilter::Advanced,
    );
    key(&mut app, KeyCode::Enter);
    app.reduce_paste("[{ unfinished");
    assert!(key(&mut app, KeyCode::Enter).effects.is_empty());
    let edit = app.router.options_browser().edit.as_ref().unwrap();
    assert_eq!(edit.field.text(), "[{ unfinished");
    assert!(edit.error.is_some());
    assert!(app
        .option_store()
        .effective_stored_values("uaf-hunt:hunt")
        .is_empty());
    assert!(!app.has_running_work());
}

#[test]
fn global_save_is_explicit_and_uses_the_existing_persistence_effect() {
    let mut app = fixture("context:build", "enrichment", OptionsFilter::Advanced);
    key(&mut app, KeyCode::Enter);
    app.router
        .options_browser_mut()
        .edit
        .as_mut()
        .unwrap()
        .field = FieldEditor::new("true");
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
    assert!(!update.effects.is_empty());
    app.complete_browser_option_save(OptionScope::Global, true);
    assert_eq!(
        app.option_store().effective_stored_values("context:build")["enrichment"],
        serde_json::json!(true)
    );
    assert_eq!(
        app.option_store()
            .effective_stored_value_scope("context:build", "enrichment"),
        Some(OptionScope::Global)
    );
    assert!(app
        .router
        .options_browser()
        .notice
        .as_ref()
        .unwrap()
        .contains("globally"));
    assert!(!app.has_running_work());
}

#[test]
fn global_save_discloses_session_precedence_and_failed_persistence() {
    let mut app = fixture("context:build", "sampleLimit", OptionsFilter::Standard);
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("context:build".into()),
        "sampleLimit",
        serde_json::json!(7),
    );
    key(&mut app, KeyCode::Enter);
    app.router
        .options_browser_mut()
        .edit
        .as_mut()
        .unwrap()
        .field = FieldEditor::new("9");
    app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
    app.complete_browser_option_save(OptionScope::Global, true);
    assert_eq!(
        app.option_store().effective_stored_values("context:build")["sampleLimit"],
        serde_json::json!(7)
    );
    assert!(app
        .router
        .options_browser()
        .notice
        .as_ref()
        .unwrap()
        .contains("unset sampleLimit"));
    app.reduce_unset_option(false, "sampleLimit");
    assert!(app.router.options_browser().notice.is_none());
    assert_eq!(
        app.option_store().effective_stored_values("context:build")["sampleLimit"],
        serde_json::json!(9)
    );
    key(&mut app, KeyCode::Enter);
    app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
    app.complete_browser_option_save(OptionScope::Global, false);
    let notice = app.router.options_browser().notice.as_ref().unwrap();
    assert!(notice.contains("could not be saved"));
    assert!(!notice.contains("Saved globally"));
}

#[test]
fn navigation_modes_preserve_drafts_and_filter_by_canonical_option_identity() {
    let mut app = fixture("threat-model:ask", "question", OptionsFilter::Standard);
    app.set_input("unsubmitted text");
    key(&mut app, KeyCode::Char('a'));
    assert_eq!(app.router.options().filter, OptionsFilter::Advanced);
    key(&mut app, KeyCode::Char('s'));
    assert_eq!(app.selected_browser_option().as_deref(), Some("question"));
    key(&mut app, KeyCode::Down);
    assert_ne!(app.selected_browser_option().as_deref(), Some("question"));
    assert_eq!(app.input(), "unsubmitted text");
}

#[test]
fn options_drafts_trigger_exit_disclosure_and_stay_restores_the_editor() {
    let mut app = fixture("threat-model:ask", "question", OptionsFilter::Standard);
    key(&mut app, KeyCode::Enter);
    app.reduce_paste("private option draft");
    let field = app
        .router
        .options_browser()
        .edit
        .as_ref()
        .unwrap()
        .field
        .clone();
    let quit = app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(quit.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    let model = crate::ui_view_models::quit_confirm_model(&app);
    let text = format!("{:?}", model.sections);
    assert!(text.contains("tool option drafts"));
    assert!(!text.contains("private option draft"));
    app.reduce_paste("ignored in confirmation");
    key(&mut app, KeyCode::Esc);
    assert!(app.tool_option_editor_open());
    assert_eq!(
        app.router.options_browser().edit.as_ref().unwrap().field,
        field
    );
}

#[test]
fn typed_tab_newline_and_paste_share_the_field_limit_without_losing_the_cursor() {
    let mut app = fixture("threat-model:ask", "question", OptionsFilter::Standard);
    key(&mut app, KeyCode::Enter);
    app.router
        .options_browser_mut()
        .edit
        .as_mut()
        .unwrap()
        .field = FieldEditor::new("x".repeat(65536));
    let before = app
        .router
        .options_browser()
        .edit
        .as_ref()
        .unwrap()
        .field
        .clone();
    key(&mut app, KeyCode::Char('東'));
    key(&mut app, KeyCode::Tab);
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT));
    app.reduce_paste("more");
    let edit = app.router.options_browser().edit.as_ref().unwrap();
    assert_eq!(edit.field, before);
    assert!(edit.error.as_ref().unwrap().contains("64 KiB"));
    key(&mut app, KeyCode::Backspace);
    assert_eq!(
        app.router
            .options_browser()
            .edit
            .as_ref()
            .unwrap()
            .field
            .text()
            .len(),
        65535
    );
    assert!(app
        .router
        .options_browser()
        .edit
        .as_ref()
        .unwrap()
        .error
        .is_none());
}

#[test]
fn string_editor_preserves_literal_quotes_whitespace_and_multiline_text() {
    let mut app = fixture("threat-model:ask", "question", OptionsFilter::Standard);
    key(&mut app, KeyCode::Enter);
    let value = "  Inspect \"declared metadata\"\nwith operator α  ";
    app.reduce_paste(value);
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.option_store()
            .effective_stored_values("threat-model:ask")["question"],
        serde_json::json!(value)
    );
    assert!(!app.has_running_work());
}
