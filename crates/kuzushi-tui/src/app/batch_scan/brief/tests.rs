use super::*;
use crate::app::{ShellEffect, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{
    modules::{ModuleRegistry, ToolExecutionContext},
    V2Config, WorkspaceTarget,
};

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "// Owned inert metadata\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(workspace.root().to_path_buf()));
    app.open_batch_scan_config(None);
    (root, app)
}

fn complete(app: &mut ShellApp, update: InputUpdate) -> Value {
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("Expected shared dispatch");
    };
    let workspace = WorkspaceTarget::new(app.target().unwrap()).unwrap();
    let context = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let result = ModuleRegistry::with_v2_builtins()
        .execute_tool(
            &request.tool_name,
            serde_json::from_str(request.input.as_ref().unwrap()).unwrap(),
            &context,
        )
        .unwrap();
    assert!(app.cache_study_result("campaign:brief", &result["data"]));
    result
}

fn key(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) -> InputUpdate {
    app.handle_brief_key(KeyEvent::new(code, modifiers))
        .unwrap()
}

#[test]
fn multiline_editor_review_save_and_reopen_preserve_owned_input() {
    let (_root, mut app) = fixture();
    app.set_input("retained composer draft");
    let opened = app.open_investigation_brief();
    complete(&mut app, opened);
    assert_eq!(app.brief_editor().unwrap().mode, BriefMode::Writing);
    assert!(app.capture_brief_paste(
        "Goal\nReview 東京 package policy\n\nPriorities\nRecord owner questions."
    ));
    assert_eq!(app.input(), "retained composer draft");
    key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert_eq!(app.brief_editor().unwrap().mode, BriefMode::Review);
    let saved = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    let result = complete(&mut app, saved);
    assert_eq!(result["data"]["brief"]["reference"]["revision"], 1);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .brief
            .as_ref()
            .unwrap()
            .reference
            .revision,
        1
    );
    key(&mut app, KeyCode::Char('e'), KeyModifiers::NONE);
    app.capture_brief_paste("\nKeep this unsaved edit.");
    let draft = app.brief_editor().unwrap().editor.clone();
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    app.open_investigation_brief();
    assert_eq!(app.brief_editor().unwrap().editor, draft);
}

#[test]
fn failed_save_refresh_keeps_text_and_background_completion_keeps_focus() {
    let (_root, mut app) = fixture();
    let opened = app.open_investigation_brief();
    complete(&mut app, opened);
    app.capture_brief_paste("Owned unsaved goal\nPreserve review capacity.");
    key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    app.brief_save_failed("campaign:brief", "revision changed");
    let draft = app.brief_editor().unwrap().editor.clone();
    let refresh = key(&mut app, KeyCode::Char('r'), KeyModifiers::NONE);
    app.set_shell_view(ShellView::Logs);
    complete(&mut app, refresh);
    assert_eq!(app.shell_view(), ShellView::Logs);
    assert_eq!(app.brief_editor().unwrap().editor, draft);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .brief
        .is_none());
}

#[test]
fn old_study_save_completion_does_not_select_in_a_new_study() {
    let (_root, mut app) = fixture();
    let opened = app.open_investigation_brief();
    complete(&mut app, opened);
    app.capture_brief_paste("Owned goal");
    key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    let save = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    app.open_batch_scan_config(None);
    complete(&mut app, save);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .brief
        .is_none());
}

#[test]
fn invalid_paste_preserves_text_and_model_work_stays_absent() {
    let (root, mut app) = fixture();
    let opened = app.open_investigation_brief();
    complete(&mut app, opened);
    app.capture_brief_paste("Owned goal");
    let before = app.brief_editor().unwrap().editor.clone();
    app.capture_brief_paste(&"x".repeat(8193));
    app.capture_brief_paste("\0");
    assert_eq!(app.brief_editor().unwrap().editor, before);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
    assert_eq!(app.findings().len(), 0);
}

#[test]
fn unsaved_edits_cannot_select_a_different_saved_revision() {
    let (_root, mut app) = fixture();
    let opened = app.open_investigation_brief();
    complete(&mut app, opened);
    app.capture_brief_paste("Owned saved goal");
    key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    let update = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    complete(&mut app, update);
    key(&mut app, KeyCode::Char('e'), KeyModifiers::NONE);
    app.capture_brief_paste("\nNew unsaved priorities");
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(app
        .brief_editor()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Unsaved text"));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .brief
            .as_ref()
            .unwrap()
            .document
            .text,
        "Owned saved goal"
    );
}
