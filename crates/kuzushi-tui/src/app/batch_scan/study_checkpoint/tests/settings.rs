use super::*;
use crate::app::{BriefEditor, BriefMode};
use kuzushi_core::{
    capabilities::campaign::BriefRevision, modules::ToolExecutionContext, WorkspaceTarget,
};

fn plain(app: &mut ShellApp) {
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .scan_input = Some(
        serde_json::json!({"taskMode":"manual","tasks":["semgrep"],"threatModelRef":null,"triage":false,"verify":false,"patch":false}),
    );
}

fn draft(app: &mut ShellApp, base: Option<BriefRevision>, text: &str) {
    let mut editor = FieldEditor::new(text);
    editor.restore_cursor(2).unwrap();
    let target = app.target_owned().unwrap();
    app.runtime_state.brief_drafts.insert(
        target,
        BriefEditor {
            mode: BriefMode::Writing,
            loaded: base,
            editor,
            scroll: 3,
            preserve_text: false,
            pending_study: None,
            notice: None,
        },
    );
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .brief_open = true;
    app.checkpoint_study_choices();
    settle(app);
}

fn save_base(app: &mut ShellApp, text: &str, revision: u32) -> BriefRevision {
    let workspace = WorkspaceTarget::new(app.target().unwrap()).unwrap();
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
            "campaign:brief",
            serde_json::json!({"mode":"save","text":text,"expectedRevision":revision}),
            &ctx,
            None,
        )
        .unwrap();
    let result = app
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    serde_json::from_value(result["data"]["brief"].clone()).unwrap()
}

#[test]
fn untouched_study_and_navigation_create_no_private_draft() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    for code in [
        KeyCode::Down,
        KeyCode::Up,
        KeyCode::PageDown,
        KeyCode::PageUp,
    ] {
        key(&mut app, code);
    }
    settle(&mut app);
    let (store, _) = app
        .runtime_state
        .study_checkpoints
        .binding
        .as_ref()
        .unwrap();
    assert!(store
        .read(&target.path().canonicalize().unwrap())
        .unwrap()
        .is_empty());
    assert!(!app.study_choices_not_checkpointed());
}

#[test]
fn ordinary_settings_recover_without_inventing_context_cases_or_approval() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    plain(&mut first);
    let config = first
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.trials = 4;
    config.requested_workers = 2;
    config.study.max_provider_calls = Some(9);
    config.study.protected_review_calls = Some(2);
    config.cursor = 6;
    first.checkpoint_study_choices();
    settle(&mut first);
    assert!(first.study_choices_checkpointed());
    let original = first
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .clone();
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let restored = next.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(restored.trials, 4);
    assert_eq!(restored.requested_workers, 2);
    assert_eq!(restored.study.scan_input, original.study.scan_input);
    assert_eq!(
        restored.study.investigation_id,
        original.study.investigation_id
    );
    assert_eq!(restored.study.max_provider_calls, Some(9));
    assert_eq!(restored.cursor, 6);
    assert!(restored.study.matrix.cases.is_empty());
    assert!(!restored.study.approved());
    assert!(!next.has_running_work());
}

#[test]
fn unpublished_goal_recovers_exact_unicode_cursor_and_stays_unselected() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    plain(&mut first);
    draft(
        &mut first,
        None,
        "Goal α\nReview 東京 context, retain spending and source questions.",
    );
    let expected = first.brief_editor().unwrap().editor.clone();
    assert!(!first.uncheckpointed_goal_drafts());
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    assert_eq!(next.brief_editor().unwrap().editor, expected);
    assert_eq!(next.brief_editor().unwrap().scroll, 3);
    assert_eq!(next.brief_editor().unwrap().mode, BriefMode::Writing);
    assert!(next
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .brief
        .is_none());
    assert!(!next.has_running_work());
    assert!(!target.path().join(".kuzushi/briefs").exists());
}

#[test]
fn interrupted_goal_save_recovers_to_review_and_preserves_a_newer_accepted_head() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    plain(&mut first);
    let old = save_base(&mut first, "Original accepted intent", 0);
    draft(&mut first, Some(old.clone()), "Interrupted edited goal");
    first.brief_editor_mut().unwrap().mode = BriefMode::Saving;
    first.checkpoint_study_choices();
    settle(&mut first);
    let newer = save_base(&mut first, "Another accepted revision", 1);
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let editor = next.brief_editor().unwrap();
    assert_eq!(editor.loaded.as_ref(), Some(&old));
    assert_eq!(editor.mode, BriefMode::Review);
    assert!(editor.pending_study.is_none());
    let actual =
        kuzushi_core::capabilities::campaign::load_brief(next.target().unwrap(), &newer.reference)
            .unwrap();
    assert_eq!(actual, newer);
    assert!(!next.has_running_work());
}

#[test]
fn prior_version_one_record_without_goal_field_remains_readable() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    fill(&mut app, "Earlier version");
    let state = app
        .runtime_state
        .study_checkpoints
        .states
        .values()
        .next()
        .unwrap();
    let mut encoded = serde_json::to_value(&state.record).unwrap();
    encoded["snapshot"]
        .as_object_mut()
        .unwrap()
        .remove("briefDraft");
    let decoded: StudyCheckpointRecord = serde_json::from_value(encoded).unwrap();
    decoded.validate().unwrap();
    assert!(decoded.snapshot.unwrap().brief_draft.is_none());
}

#[test]
fn failed_ordinary_write_keeps_choices_until_explicit_discard_and_warns_about_goal() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    plain(&mut app);
    app.runtime_state.study_checkpoints.binding = None;
    draft(&mut app, None, "Unsaved private goal");
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .brief_open = false;
    assert!(app.uncheckpointed_goal_drafts());
    let quit = format!("{:?}", crate::ui_view_models::quit_confirm_model(&app));
    assert!(quit.contains("goal draft"));
    assert!(!quit.contains("Unsaved private goal"));
    key(&mut app, KeyCode::Esc);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Discard
    );
    key(&mut app, KeyCode::Enter);
    assert!(app.batch_config_open());
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('d'));
    assert!(!app.batch_config_open());
    assert!(app.runtime_state.brief_drafts.is_empty());
}

#[test]
fn recovery_list_names_ordinary_work_and_goal_at_all_six_viewports() {
    use ratatui::{backend::TestBackend, Terminal};
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    plain(&mut first);
    draft(&mut first, None, "Goal α\nRetain source context");
    let mut next = shell(target.path(), home.path());
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        next.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &next))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        for text in [
            "Whole repository",
            "3 passes",
            "Goal draft: Goal α",
            "Enter restore",
            "Esc back",
        ] {
            assert!(screen.contains(text), "{width}x{height}: {text}");
        }
        assert!(!screen.contains("0 cases"));
    }
}

#[test]
fn recovery_never_overwrites_a_different_unsaved_goal_in_the_current_session() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    plain(&mut first);
    draft(&mut first, None, "Older goal to restore");
    let mut next = shell(target.path(), home.path());
    let mut editor = FieldEditor::new("Keep this newer session goal");
    editor.restore_cursor(2).unwrap();
    next.runtime_state.brief_drafts.insert(
        next.target_owned().unwrap(),
        BriefEditor {
            mode: BriefMode::Writing,
            editor,
            ..Default::default()
        },
    );
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    assert!(matches!(
        next.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Failed(_)
    ));
    assert_eq!(
        next.runtime_state
            .brief_drafts
            .get(next.target().unwrap())
            .unwrap()
            .editor
            .text(),
        "Keep this newer session goal"
    );
    assert!(!next.has_running_work());
}

#[test]
fn refreshing_a_goal_keeps_raw_text_durable_and_failure_notice_precedes_save_status() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    plain(&mut first);
    draft(&mut first, None, "Keep this pending reload goal");
    first.brief_editor_mut().unwrap().mode = BriefMode::Loading;
    first.brief_editor_mut().unwrap().preserve_text = true;
    first.checkpoint_study_choices();
    settle(&mut first);
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    assert_eq!(
        next.brief_editor().unwrap().editor.text(),
        "Keep this pending reload goal"
    );
    assert_eq!(next.brief_editor().unwrap().mode, BriefMode::Read);
    let editor = next.brief_editor_mut().unwrap();
    editor.notice = Some("Brief stopped: revision changed".into());
    let lines = crate::ui_view_models::study_config::brief::notice_lines(
        editor,
        Some("Study choices saved locally."),
    );
    assert_eq!(
        lines,
        [
            "Brief stopped: revision changed",
            "Study choices saved locally."
        ]
    );
}

#[test]
fn real_input_dispatch_checkpoints_goal_paste_and_cursor_changes() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    plain(&mut app);
    let base = save_base(&mut app, "Accepted base", 0);
    let root = app.target_owned().unwrap();
    app.runtime_state.brief_drafts.insert(
        root,
        BriefEditor {
            mode: BriefMode::Read,
            loaded: Some(base),
            editor: FieldEditor::new("Accepted base"),
            ..Default::default()
        },
    );
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .brief_open = true;
    for event in [
        KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE),
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
    ] {
        app.reduce_key(event);
    }
    app.reduce_paste("Goal α\nOwned text");
    app.reduce_key(KeyEvent::new(KeyCode::Home, KeyModifiers::CONTROL));
    app.reduce_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    app.reduce_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    settle(&mut app);
    assert!(
        app.study_choices_checkpointed(),
        "{:?}",
        app.study_checkpoint_note()
    );
    let (store, _) = app
        .runtime_state
        .study_checkpoints
        .binding
        .as_ref()
        .unwrap();
    let saved = persistence::recover(store, app.target().unwrap())
        .unwrap()
        .remove(0);
    let field = &saved.record.snapshot.unwrap().brief_draft.unwrap().field;
    assert_eq!(field.text, "Goal α\nOwned text");
    assert_eq!(field.cursor, 2);
}

#[test]
fn streamed_goal_keys_with_implicit_scan_input_coalesce_to_the_exact_latest_record() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    let base = save_base(&mut app, "Accepted base", 0);
    let root = app.target_owned().unwrap();
    app.runtime_state.brief_drafts.insert(
        root,
        BriefEditor {
            mode: BriefMode::Read,
            loaded: Some(base),
            editor: FieldEditor::new("Accepted base"),
            ..Default::default()
        },
    );
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .brief_open = true;
    app.reduce_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    let text="Goal α\nInspect owner policy and preserve protected review. 東京 context remains source-only.";
    for ch in text.chars() {
        app.reduce_key(KeyEvent::new(
            if ch == '\n' {
                KeyCode::Enter
            } else {
                KeyCode::Char(ch)
            },
            KeyModifiers::NONE,
        ));
    }
    app.reduce_key(KeyEvent::new(KeyCode::Home, KeyModifiers::CONTROL));
    app.reduce_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    app.reduce_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    settle(&mut app);
    assert!(
        app.study_choices_checkpointed(),
        "{:?}",
        app.study_checkpoint_note()
    );
    let (store, _) = app
        .runtime_state
        .study_checkpoints
        .binding
        .as_ref()
        .unwrap();
    let saved = persistence::recover(store, app.target().unwrap())
        .unwrap()
        .remove(0);
    assert_eq!(
        saved.record.snapshot.unwrap().brief_draft.unwrap().field,
        DraftText {
            text: text.into(),
            cursor: 2
        }
    );
}
