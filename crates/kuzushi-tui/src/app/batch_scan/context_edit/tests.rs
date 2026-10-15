use super::*;
use crate::app::{EffectRuntime, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::capabilities::threat_model::{
    commit_threat_model_revision, load_active_threat_model, ScopeRef, ThreatModelCommit,
    ThreatModelRevisionSource,
};
use kuzushi_core::{modules::ToolExecutionContext, ThreatModelRef, V2Config, WorkspaceTarget};
mod checkpoints;

fn commit(root: &std::path::Path, label: &str) -> ThreatModelRef {
    commit_threat_model_revision(root, &json!({"version":"1","methodology":"stride","systemContext":"Original overview","dfd":{"nodes":[{"id":"reader","name":"Reader","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{},"openQuestions":["Who owns the input?"]}), ThreatModelCommit {model_id:None,new_model:true,label:label.into(),scope:ScopeRef::legacy_root(root,&format!("sha256:{}","1".repeat(64))),methodology:"stride".into(),source:ThreatModelRevisionSource::Import,source_revision_id:None,run_id:None,activate:Some(true),actor:"test".into()}).unwrap().model_ref
}

fn read(app: &mut ShellApp, root: &std::path::Path, reference: &ThreatModelRef) {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let config = app.config().clone();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = app
        .registry()
        .prepare_dispatch_input(
            "threat-model:read",
            json!({"threatModelRef":reference}),
            &ctx,
            None,
        )
        .unwrap();
    let result = app
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    app.cache_study_context_preview(&result["data"]);
}

fn fixture() -> (tempfile::TempDir, ShellApp, ThreatModelRef, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("lib.rs"),
        "// Benign context fixture, never executed.\n",
    )
    .unwrap();
    let first = commit(root.path(), "Original context");
    let active = commit(root.path(), "Active context");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.hydrate_all_view_data_for_test();
    app.open_study_context_picker();
    app.edit_context_picker(|config| {
        config.context_picker.as_mut().unwrap().selected = Some(first.clone())
    });
    read(&mut app, root.path(), &first);
    (root, app, first, active)
}

fn key(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) {
    let update = app
        .handle_context_edit_key(KeyEvent::new(code, modifiers))
        .unwrap();
    EffectRuntime::execute(app, update.effects);
}

fn settle_tool(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        app.drain_background_events();
        if !app.has_running_work() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("Context edit did not settle: {:?}", app.log_lines());
}

fn edited_overview(app: &mut ShellApp) {
    app.open_context_editor();
    key(app, KeyCode::Enter, KeyModifiers::NONE);
    key(app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    assert!(app.capture_context_edit_paste("Operator overview\nUnicode α"));
    key(app, KeyCode::Esc, KeyModifiers::NONE);
}

#[test]
fn hidden_context_copy_warns_before_quit_and_stay_retains_its_draft() {
    let (_root, mut app, _, _) = fixture();
    assert!(!app.context_copies_not_checkpointed());
    app.open_context_editor();
    assert!(!app.context_copies_not_checkpointed());
    edited_overview(&mut app);
    app.close_context_editor();
    assert!(app.context_copies_not_checkpointed());
    let before = app.runtime_state.context_edit_drafts.clone();
    let update = app.reduce_quit_chord_for_test();
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    let text = format!("{:?}", crate::ui_view_models::quit_confirm_model(&app));
    assert!(text.contains("context copy"));
    assert!(text.contains("return to review and save"));
    assert!(!text.contains("Operator overview"));
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.runtime_state.context_edit_drafts, before);
    app.open_context_editor();
    assert_eq!(
        app.context_edit_draft().unwrap().entries[1].text(),
        "Operator overview\nUnicode α"
    );
}

#[test]
fn back_navigation_keeps_context_text_cursor_and_composer() {
    let (_root, mut app, first, _) = fixture();
    app.set_input("Unrelated composer draft");
    edited_overview(&mut app);
    let cursor = app.context_edit_draft().unwrap().entries[1]
        .editor
        .as_ref()
        .unwrap()
        .cursor();
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert!(app.context_edit_draft().is_none());
    app.handle_study_context_key(KeyCode::Esc);
    app.open_study_context_picker();
    app.edit_context_picker(|config| {
        config.context_picker.as_mut().unwrap().selected = Some(first)
    });
    app.open_context_editor();
    assert_eq!(
        app.context_edit_draft().unwrap().entries[1].text(),
        "Operator overview\nUnicode α"
    );
    assert_eq!(
        app.context_edit_draft().unwrap().entries[1]
            .editor
            .as_ref()
            .unwrap()
            .cursor(),
        cursor
    );
    assert_eq!(app.input(), "Unrelated composer draft");
}

#[test]
fn reviewed_save_uses_shared_dispatch_and_requires_new_copy_inspection() {
    let (root, mut app, first, active) = fixture();
    edited_overview(&mut app);
    key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert_eq!(
        app.context_edit_draft().unwrap().mode,
        ContextEditMode::Review
    );
    assert_eq!(
        app.study_context_picker().unwrap().selected,
        Some(first.clone())
    );
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    settle_tool(&mut app);
    let picker = app.study_context_picker().unwrap();
    let copy = picker.selected.clone().unwrap();
    assert_ne!(
        copy,
        first,
        "mode={:?}; notice={:?}; logs={:?}",
        app.context_edit_draft().map(|draft| draft.mode),
        app.context_edit_draft()
            .and_then(|draft| draft.notice.as_ref()),
        app.log_lines()
    );
    assert!(picker.preview.is_none());
    assert!(app.context_edit_draft().is_none());
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
    read(&mut app, root.path(), &copy);
    assert_eq!(
        app.study_context_picker()
            .unwrap()
            .preview
            .as_ref()
            .unwrap()
            .document["systemContext"],
        "Operator overview\nUnicode α"
    );
}

#[test]
fn read_only_states_keep_paste_out_of_commands_and_writing_owns_letters() {
    let (_root, mut app, _, _) = fixture();
    app.set_input("composer");
    app.open_context_editor();
    assert!(app.capture_context_edit_paste("scan start"));
    assert_eq!(app.input(), "composer");
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('r'), KeyModifiers::NONE);
    assert_eq!(
        app.context_edit_draft().unwrap().mode,
        ContextEditMode::Writing
    );
    assert!(app.context_edit_draft().unwrap().entries[1]
        .text()
        .ends_with('r'));
}

#[test]
fn failure_retains_review_and_text_without_retry_or_selection_change() {
    let (_root, mut app, first, _) = fixture();
    edited_overview(&mut app);
    app.context_edit_draft_mut().unwrap().mode = ContextEditMode::Saving;
    app.context_edit_save_failed("threat-model:revise", "store unavailable");
    assert_eq!(
        app.context_edit_draft().unwrap().mode,
        ContextEditMode::Review
    );
    assert_eq!(
        app.context_edit_draft().unwrap().entries[1].text(),
        "Operator overview\nUnicode α"
    );
    assert_eq!(app.study_context_picker().unwrap().selected, Some(first));
    assert!(app
        .context_edit_draft()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("before retrying"));
}

#[test]
fn field_and_diff_controls_survive_all_six_viewports_and_plain_projection() {
    let (_root, mut app, _, _) = fixture();
    edited_overview(&mut app);
    key(&mut app, KeyCode::Char('r'), KeyModifiers::NONE);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_shell_view(ShellView::Campaign);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(
            text.contains("REVIEW CONTEXT CHANGES"),
            "{width}x{height}: {text}"
        );
        assert!(text.contains("Enter save copy"), "{width}x{height}: {text}");
        let lines =
            crate::ui_view_models::study_context::context_detail_lines(&app, width as usize);
        assert!(lines.join(" ").contains("Unicode α"));
        assert!(lines.join(" ").contains("Original overview"));
    }
}
