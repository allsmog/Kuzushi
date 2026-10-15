use super::*;
use kuzushi_core::session_transcript::{
    ContextDraftStore, SessionMetadata, SessionTranscriptStore,
};

fn attach(app: &mut ShellApp, home: &std::path::Path) -> ContextDraftStore {
    let root = kuzushi_core::session_transcript::default_sessions_root(home);
    let store = SessionTranscriptStore::from_root(&root);
    let recorder = store.start(SessionMetadata::new("shell", home)).unwrap();
    app.attach_session_transcript(recorder);
    ContextDraftStore::from_sessions_root(root)
}

fn settle(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        app.drain_context_checkpoints();
        let loading = app
            .context_edit_draft()
            .is_some_and(|d| matches!(d.recovery, crate::app::ContextDraftRecovery::Loading));
        if !app.context_checkpoints_pending() && !loading {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "checkpoint did not settle"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn reopen(root: &std::path::Path, home: &std::path::Path, reference: &ThreatModelRef) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.into()));
    app.open_batch_scan_config(None);
    app.hydrate_all_view_data_for_test();
    app.open_study_context_picker();
    app.edit_context_picker(|c| {
        c.context_picker.as_mut().unwrap().selected = Some(reference.clone())
    });
    read(&mut app, root, reference);
    attach(&mut app, home);
    app.open_context_editor();
    settle(&mut app);
    app
}

fn write(app: &mut ShellApp, text: &str) {
    app.open_context_editor();
    settle(app);
    key(app, KeyCode::Enter, KeyModifiers::NONE);
    key(app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    app.capture_context_edit_paste(text);
    key(app, KeyCode::Home, KeyModifiers::NONE);
    key(app, KeyCode::Right, KeyModifiers::NONE);
    settle(app);
}

#[test]
fn restart_recovers_exact_text_cursor_and_base_without_accepting_context() {
    let (root, mut app, reference, active) = fixture();
    let home = tempfile::tempdir().unwrap();
    attach(&mut app, home.path());
    write(&mut app, "α\noperator checkpoint 東京");
    assert!(!app.context_copies_not_checkpointed());
    assert!(app.context_copies_checkpointed());
    let expected = app.context_edit_draft().unwrap().entries[1]
        .editor
        .as_ref()
        .unwrap()
        .clone();
    let mut restarted = reopen(root.path(), home.path(), &reference);
    assert_eq!(
        restarted.context_edit_draft().unwrap().mode,
        ContextEditMode::Recovery
    );
    key(&mut restarted, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut restarted);
    assert_eq!(
        restarted.context_edit_draft().unwrap().entries[1]
            .editor
            .as_ref(),
        Some(&expected)
    );
    assert_eq!(
        restarted.context_edit_draft().unwrap().mode,
        ContextEditMode::Writing
    );
    assert_eq!(
        restarted.study_context_picker().unwrap().selected,
        Some(reference)
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
    assert!(!restarted.has_running_work());
}

#[test]
fn reviewed_copy_save_resolves_only_the_adopted_checkpoint() {
    let (root, mut app, reference, _) = fixture();
    let home = tempfile::tempdir().unwrap();
    let store = attach(&mut app, home.path());
    write(&mut app, "Adopted operator draft");
    let mut restarted = reopen(root.path(), home.path(), &reference);
    key(&mut restarted, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut restarted);
    key(&mut restarted, KeyCode::Char('s'), KeyModifiers::CONTROL);
    key(&mut restarted, KeyCode::Enter, KeyModifiers::NONE);
    settle_tool(&mut restarted);
    settle(&mut restarted);
    assert!(store
        .recover(&root.path().canonicalize().unwrap(), &reference)
        .unwrap()
        .is_empty());
    assert!(restarted.runtime_state.context_edit_drafts.is_empty());
}

#[test]
fn rapid_typing_coalesces_to_the_latest_checkpoint_and_pending_quit_is_honest() {
    let (root, mut app, reference, _) = fixture();
    let home = tempfile::tempdir().unwrap();
    let store = attach(&mut app, home.path());
    app.open_context_editor();
    settle(&mut app);
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    for _ in 0..100 {
        app.capture_context_edit_paste("x");
    }
    let warning = format!("{:?}", crate::ui_view_models::quit_confirm_model(&app));
    assert!(warning.contains("not yet durable"));
    settle(&mut app);
    let saved = store
        .recover(&root.path().canonicalize().unwrap(), &reference)
        .unwrap()
        .remove(0);
    assert_eq!(
        saved.record.snapshot.unwrap().fields[0].text.as_deref(),
        Some("x".repeat(100).as_str())
    );
    let warning = format!("{:?}", crate::ui_view_models::quit_confirm_model(&app));
    assert!(warning.contains("RECOVERABLE DRAFTS"));
    assert!(!warning.contains("context copy unsaved"));
}

#[cfg(unix)]
#[test]
fn failed_checkpoint_keeps_private_text_and_never_claims_durability() {
    use std::os::unix::fs::symlink;
    let (_root, mut app, _, _) = fixture();
    let home = tempfile::tempdir().unwrap();
    attach(&mut app, home.path());
    app.open_context_editor();
    settle(&mut app);
    let unsafe_root = home.path().join(".kuzushi/v3/context-drafts");
    symlink(home.path().join("elsewhere"), unsafe_root).unwrap();
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    app.capture_context_edit_paste("Private unsaved draft");
    settle(&mut app);
    assert_eq!(
        app.context_edit_draft().unwrap().entries[1].text(),
        "Private unsaved draft"
    );
    assert!(app.context_checkpoint_note().unwrap().contains("not saved"));
    assert!(app.context_copies_not_checkpointed());
    assert!(!app.context_copies_checkpointed());
}

#[test]
fn multiple_sessions_offer_distinct_drafts_and_keep_unselected_edits() {
    let (root, mut first, reference, _) = fixture();
    let home = tempfile::tempdir().unwrap();
    let store = attach(&mut first, home.path());
    write(&mut first, "First operator draft");
    let mut second = reopen(root.path(), home.path(), &reference);
    key(&mut second, KeyCode::Char('n'), KeyModifiers::NONE);
    write(&mut second, "Second operator draft");
    let mut third = reopen(root.path(), home.path(), &reference);
    let crate::app::ContextDraftRecovery::Choices { drafts, .. } =
        &third.context_edit_draft().unwrap().recovery
    else {
        panic!("choices required")
    };
    assert_eq!(drafts.len(), 2);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        third.set_viewport(crate::TerminalViewport::new(width, height));
        let plain = crate::renderer::render_plain_app(&third, width as usize);
        assert!(
            plain.contains("RECOVER CONTEXT DRAFT") && plain.contains("Enter recover"),
            "{plain}"
        );
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &third))
            .unwrap();
        let native = format!("{:?}", terminal.backend().buffer());
        assert!(
            native.contains("▸") && native.contains("Enter recover"),
            "{native}"
        );
    }
    key(&mut third, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut third);
    key(&mut third, KeyCode::Esc, KeyModifiers::NONE);
    key(&mut third, KeyCode::Char('d'), KeyModifiers::NONE);
    key(&mut third, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut third);
    assert_eq!(
        store
            .recover(&root.path().canonicalize().unwrap(), &reference)
            .unwrap()
            .len(),
        1
    );
}
