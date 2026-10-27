use super::*;
use crate::app::{FieldEditor, ShellEffect, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{ToolExecutionContext, V2Config, WorkspaceTarget};
use ratatui::{backend::TestBackend, Terminal};
mod action_search;
mod additions;
mod enumeration;
mod file_boundaries;
mod findings;
mod literal_paths;
mod overview;
mod reader_position;
mod reading;
mod source;
mod suggestion;
mod tree;
mod workload;

#[test]
fn new_scope_proposal_resets_detail_scroll_and_refresh_preserves_it() {
    let (root, app) = fixture();
    let review = app
        .scope_review()
        .unwrap()
        .review
        .as_deref()
        .unwrap()
        .clone();
    let mut state = ScopeReviewState::new(root.path().into());
    state.scroll = 8;
    state.install(review.clone());
    assert_eq!(state.scroll, 0, "new inventory must open at its first line");
    state.scroll = 8;
    state.install(review.clone());
    assert_eq!(
        state.scroll, 8,
        "refresh must preserve the reading position"
    );
    let mut different = review;
    different.reference.proposal_id.push_str("-different");
    state.install(different);
    assert_eq!(state.scroll, 0, "a different proposal has a new document");
}

#[test]
fn empty_history_read_discloses_completion_and_keeps_an_inspected_revision() {
    let (_root, mut app) = fixture();
    let before = app.scope_review().unwrap().review.clone();
    app.dispatch_scope_request(json!({"operation":"latest"}));
    app.cache_scope_review_result("pack:scopes", &json!({"review":null}));
    let state = app.scope_review().unwrap();
    assert!(state.pending.is_none());
    assert_eq!(state.review, before);
    assert!(state
        .notice
        .as_ref()
        .unwrap()
        .contains("previously inspected"));
}

#[test]
fn initial_empty_history_read_is_ready_for_explicit_inventory_building() {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.open_scope_review();
    app.cache_scope_review_result("pack:scopes", &json!({"review":null}));
    let state = app.scope_review().unwrap();
    assert!(state.pending.is_none());
    assert!(state.review.is_none());
    assert!(state
        .notice
        .as_ref()
        .unwrap()
        .starts_with("No saved scope inventory"));
    assert!(!app.has_running_work());
}

#[test]
fn explicit_shared_context_copy_and_removal_use_prepared_dispatch_without_work() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    app.set_input("kept composer");
    app.set_cursor(4);
    let original = app.scope_review().unwrap().review.as_ref().unwrap().clone();
    let update = app.apply_scope_menu(13);
    finish(&mut app, root.path(), update).unwrap();
    let copied = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(copied.record.draft.scopes, original.record.draft.scopes);
    assert!(!copied.record.draft.shared_discovery);
    assert!(copied.record.acceptance.is_none());
    assert_eq!(
        copied.coverage.discovery_members,
        original.coverage.discovery_members
    );
    let shared = copied.record.draft.shared_scope.as_ref().unwrap();
    assert_eq!(
        copied.coverage.context_members[&shared.id].files,
        vec!["auth/login.rs"]
    );
    assert_eq!(copied.reference.revision, original.reference.revision + 1);
    assert_eq!((app.input(), app.cursor()), ("kept composer", 4));
    let update = app.apply_scope_menu(14);
    finish(&mut app, root.path(), update).unwrap();
    let removed = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(removed.record.draft, original.record.draft);
    assert!(app.findings().is_empty());
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn shared_context_menu_actions_remain_reachable_at_all_viewports() {
    let (_root, mut app) = fixture();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        press(&mut app, KeyCode::Enter);
        for _ in 0..13 {
            press(&mut app, KeyCode::Down);
        }
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert_eq!(app.scope_review().unwrap().menu, Some(13));
        assert!(
            screen.contains("shared context"),
            "{width}x{height}: {screen}"
        );
        press(&mut app, KeyCode::Down);
        terminal
            .draw(|frame| crate::render_app(frame, &app))
            .unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Remove shared"));
        press(&mut app, KeyCode::Esc);
    }
}

#[test]
fn shared_scope_mode_remains_visible_with_a_long_name_at_forty_columns() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    let update = app.apply_scope_menu(13);
    finish(&mut app, root.path(), update).unwrap();
    let shared = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .record
        .draft
        .shared_scope
        .as_ref()
        .unwrap()
        .id
        .clone();
    let update = app.send_scope_edit(kuzushi_core::workspace::ScanScopeEdit::Rename {
        scope_id: shared,
        name: "Long operator selected shared boundary".into(),
    });
    finish(&mut app, root.path(), update).unwrap();
    app.router.scope_review_mut().as_mut().unwrap().cursor = 2;
    app.reduce_resize(40, 12);
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, &app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let rows = (0..12)
        .map(|y| (0..40).map(|x| buffer[(x, y)].symbol()).collect::<String>())
        .collect::<Vec<_>>();
    assert!(
        rows.iter()
            .any(|row| row.contains("▸") && row.contains(" · context")),
        "{rows:?}"
    );
}

#[test]
fn inclusion_form_preserves_literal_path_whitespace() {
    let (_root, app) = fixture();
    let scope = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .record
        .draft
        .scopes[0]
        .clone();
    let mut form = ScopeEditForm::for_scope(ScopeEditKind::IncludePath, &scope);
    form.fields[0].1 = FieldEditor::new(" auth/owned.rs ");
    assert_eq!(
        form.edit(2).unwrap(),
        kuzushi_core::workspace::ScanScopeEdit::IncludePath {
            path: " auth/owned.rs ".into()
        }
    );
}

#[test]
fn whole_repository_keeps_exclusions_until_the_operator_includes_a_recorded_path() {
    let (root, mut app) = fixture();
    let update = app.send_scope_edit(kuzushi_core::workspace::ScanScopeEdit::ExcludePath {
        path: "auth/login.rs".into(),
        reason: "Defer owned fixture file".into(),
    });
    finish(&mut app, root.path(), update).unwrap();
    let update = app.apply_scope_menu(7);
    finish(&mut app, root.path(), update).unwrap();
    let review = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(review.coverage.excluded_files.files, vec!["auth/login.rs"]);
    assert_eq!(
        review.coverage.discovery_members["repository"].files,
        vec!["README.md"]
    );
    assert!(review.record.acceptance.is_none());
    assert!(app.apply_scope_menu(11).effects.is_empty());
    assert_eq!(
        app.scope_review().unwrap().form.as_ref().unwrap().fields[0]
            .1
            .text(),
        "auth/login.rs"
    );
    fill_form(&mut app, &["missing.rs"]);
    let update = press(&mut app, KeyCode::Enter);
    let error = finish(&mut app, root.path(), update).unwrap_err();
    app.scope_review_failed("pack:scopes", &format!("{error:#}"));
    assert_eq!(
        app.scope_review().unwrap().form.as_ref().unwrap().fields[0]
            .1
            .text(),
        "missing.rs"
    );
    fill_form(&mut app, &["auth/login.rs"]);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    let review = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(review.coverage.excluded_files.total, 0);
    assert_eq!(review.coverage.discovery_members["repository"].total, 2);
    assert!(review.record.acceptance.is_none());
    assert!(app.findings().is_empty());
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("auth")).unwrap();
    std::fs::write(root.path().join("auth/login.rs"), "pub fn login() {}\n").unwrap();
    std::fs::write(root.path().join("README.md"), "scope fixture\n").unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    let effects = app.open_scope_review();
    finish(
        &mut app,
        root.path(),
        InputUpdate::handled_with_effects(effects),
    )
    .unwrap();
    let update = press(&mut app, KeyCode::Char('c'));
    finish(&mut app, root.path(), update).unwrap();
    (root, app)
}

fn press(app: &mut ShellApp, code: KeyCode) -> InputUpdate {
    app.handle_scope_review_key(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap()
}

fn discard_unprepared_study(app: &mut ShellApp) {
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        crate::app::StudyDraftRecovery::Discard
    );
    app.reduce_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
}

fn finish(
    app: &mut ShellApp,
    root: &std::path::Path,
    update: InputUpdate,
) -> anyhow::Result<Value> {
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("scope action must use shared dispatch")
    };
    let workspace = WorkspaceTarget::new(root)?;
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = serde_json::from_str(request.input.as_ref().unwrap())?;
    let prepared = app
        .registry()
        .prepare_dispatch_input(&request.tool_name, input, &ctx, None)?;
    let output = app
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)?;
    app.cache_tool_snapshot(&request.tool_name, &output);
    Ok(output)
}

fn fill_form(app: &mut ShellApp, values: &[&str]) {
    let form = app
        .router
        .scope_review_mut()
        .as_mut()
        .unwrap()
        .form
        .as_mut()
        .unwrap();
    for ((_, field), value) in form.fields.iter_mut().zip(values) {
        *field = FieldEditor::new(*value);
    }
}

fn split(app: &mut ShellApp, root: &std::path::Path) {
    app.apply_scope_menu(1);
    fill_form(app, &["Auth", "auth", "Docs", "README.md"]);
    let update = press(app, KeyCode::F(2));
    finish(app, root, update).unwrap();
}

#[test]
fn scope_study_requires_acceptance_and_preserves_the_boundary_before_work() {
    let (_root, mut app) = fixture();
    let update = press(&mut app, KeyCode::Char('p'));
    assert!(update.effects.is_empty());
    assert!(app.scope_review_is_visible());
    assert!(app
        .scope_review()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Accept the exact"));
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn accepted_scope_study_binds_the_selected_revision_and_back_restores_reading_state() {
    use crate::app::state_transitions::ViewHotkeyAction;
    use kuzushi_core::{OptionScope, OptionTarget};
    let (root, mut app) = fixture();
    app.open_scope_acceptance();
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".into()),
        "tasks",
        json!(["secret-scan"]),
    );
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".into()),
        "taskMode",
        json!("manual"),
    );
    let state = app.router.scope_review_mut().as_mut().unwrap();
    state.scroll = 7;
    let expected = state.review.as_ref().unwrap().reference.clone();
    let update = press(&mut app, KeyCode::Char('p'));
    assert!(update.effects.is_empty());
    assert!(!app.scope_review_is_visible());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!((config.trials, config.requested_workers), (3, 1));
    assert!(config.study.receipt.is_none());
    let input = config.study.scan_input.as_ref().unwrap();
    assert_eq!(
        input["scanScopeRef"],
        json!({"proposal":expected,"scopeId":"repository"})
    );
    assert_eq!(input["tasks"], json!(["secret-scan"]));
    app.apply_batch_scan_hotkey(ViewHotkeyAction::CampaignBackToList);
    discard_unprepared_study(&mut app);
    assert!(app.scope_review_is_visible());
    assert_eq!(app.scope_review().unwrap().scroll, 7);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn marked_boundaries_compile_one_six_job_draft_and_back_preserves_the_selection() {
    use crate::app::state_transitions::ViewHotkeyAction;
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    app.open_scope_acceptance();
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char(' '));
    assert_eq!(app.scope_review().unwrap().study_scope_ids.len(), 2);
    let update = press(&mut app, KeyCode::Char('p'));
    assert!(update.effects.is_empty());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.scope_draft.as_ref().unwrap().job_count(), 6);
    assert!(config.study.scope_receipt.is_none());
    app.apply_batch_scan_hotkey(ViewHotkeyAction::CampaignBackToList);
    discard_unprepared_study(&mut app);
    assert!(app.scope_review_is_visible());
    assert_eq!(app.scope_review().unwrap().study_scope_ids.len(), 2);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn scope_review_split_merge_and_accept_use_shared_dispatch_without_starting_jobs() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    assert_eq!(
        app.scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .record
            .draft
            .scopes
            .len(),
        2
    );
    app.apply_scope_menu(2);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    app.open_scope_acceptance();
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    let review = app.scope_review().unwrap().review.as_ref().unwrap();
    assert!(review.record.acceptance.is_some());
    assert_eq!(review.reference.revision, 4);
    assert!(!root.path().join(".kuzushi/campaigns").exists());
    let queue =
        kuzushi_core::load_strategy_queue(&WorkspaceTarget::new(root.path()).unwrap()).unwrap();
    assert_eq!(queue.len(), 1);
    assert!(queue[0].tool.is_none() && queue[0].next_input.is_none());
}

#[test]
fn scope_review_form_owns_unicode_paste_and_preserves_the_composer_and_cursor() {
    let (root, mut app) = fixture();
    app.set_input("held shell draft");
    let original = (app.input().to_string(), app.editor().cursor());
    app.apply_scope_menu(0);
    press(&mut app, KeyCode::Home);
    app.reduce_paste("東京 operator ");
    let state = app.scope_review().unwrap();
    assert!(state.form.as_ref().unwrap().fields[0]
        .1
        .text()
        .starts_with("東京 operator "));
    assert_eq!((app.input().to_string(), app.editor().cursor()), original);
    let update = press(&mut app, KeyCode::F(2));
    finish(&mut app, root.path(), update).unwrap();
    assert_eq!((app.input().to_string(), app.editor().cursor()), original);
    press(&mut app, KeyCode::Esc);
    assert!(!app.scope_review().unwrap().open);
    app.open_scope_review();
    assert!(app.scope_review().unwrap().open);
}

#[test]
fn scope_review_invalid_split_and_source_drift_preserve_form_and_saved_membership() {
    let (root, mut app) = fixture();
    app.apply_scope_menu(1);
    fill_form(&mut app, &["Auth", "auth", "Missing root", "auth"]);
    let form = app.scope_review().unwrap().form.clone();
    let update = press(&mut app, KeyCode::F(2));
    let error = finish(&mut app, root.path(), update).unwrap_err();
    app.scope_review_failed("pack:scopes", &error.to_string());
    assert_eq!(app.scope_review().unwrap().form, form);
    assert_eq!(
        app.scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .reference
            .revision,
        1
    );
    std::fs::write(root.path().join("README.md"), "changed source\n").unwrap();
    fill_form(&mut app, &["Auth", "auth", "Docs", "README.md"]);
    let update = press(&mut app, KeyCode::F(2));
    let error = finish(&mut app, root.path(), update).unwrap_err();
    app.scope_review_failed("pack:scopes", &error.to_string());
    assert!(app
        .scope_review()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("source"));
    assert!(app.scope_review().unwrap().form.is_some());
}

#[test]
fn scope_review_files_are_paged_and_completion_never_reopens_a_closed_surface() {
    let (root, mut app) = fixture();
    app.set_shell_view(ShellView::Workbench);
    let update = press(&mut app, KeyCode::Char('f'));
    press(&mut app, KeyCode::Esc);
    finish(&mut app, root.path(), update).unwrap();
    assert!(!app.scope_review().unwrap().open);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(
        app.scope_review()
            .unwrap()
            .files
            .as_ref()
            .unwrap()
            .page
            .total,
        2
    );
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    assert!(app.scope_review().is_none());
}

#[test]
fn scope_review_reads_saved_revision_after_restart_without_model_or_scan_work() {
    let (root, app) = fixture();
    let reference = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .reference
        .clone();
    let mut restarted = ShellApp::new(V2Config::default(), None);
    restarted.set_target(Some(root.path().into()));
    let effects = restarted.open_scope_review();
    finish(
        &mut restarted,
        root.path(),
        InputUpdate::handled_with_effects(effects),
    )
    .unwrap();
    assert_eq!(
        restarted
            .scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .reference,
        reference
    );
}

#[test]
fn scope_review_viewports_keep_controls_and_plain_output_keeps_recorded_source() {
    let (_, mut app) = fixture();
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("SCOPES"), "{width}x{height}");
        assert!(text.contains("Enter menu · Esc"), "{width}x{height}");
        assert!(text.contains("Tab read"), "{width}x{height}");
        assert!(text.contains("Enter menu"), "{width}x{height}");
        assert!(text.contains("p plan"), "{width}x{height}");
        assert!(text.contains("a accept"), "{width}x{height}");
        assert!(text.contains("f files"), "{width}x{height}");
        press(&mut app, KeyCode::Char('a'));
        terminal
            .draw(|frame| crate::render_app(frame, &app))
            .unwrap();
        press(&mut app, KeyCode::Esc);
    }
    let plain = crate::render_plain_app(&app, 40);
    assert!(plain.contains("Recorded Git SHA"));
    let text = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(text.contains("Scope acceptance does not approve jobs or spending"));
    assert!(!plain.contains('\x1b'));
}

#[test]
fn scope_review_modal_keys_outrank_hidden_catalog_navigation() {
    let (root, mut app) = fixture();
    let update = press(&mut app, KeyCode::Char('f'));
    finish(&mut app, root.path(), update).unwrap();
    app.set_shell_view(ShellView::Catalog);
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.scope_review().unwrap().files.is_none());
    app.reduce_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert!(app.scope_review().unwrap().accepting);
    assert_eq!(app.shell_view(), ShellView::Catalog);
}

#[test]
fn scope_review_named_split_preserves_parent_dependencies_and_open_questions() {
    let (root, mut app) = fixture();
    let mut draft = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .record
        .draft
        .clone();
    let mut shared = draft.scopes[0].clone();
    shared.id = "shared".into();
    shared.name = "Shared authentication context".into();
    shared.paths = vec!["auth".into()];
    draft.shared_scope = Some(shared);
    draft.scopes[0].shared_dependencies = vec!["shared".into()];
    draft.scopes[0].open_questions = vec!["Which calls cross the shared boundary?".into()];
    let update = app.dispatch_scope_request(json!({"operation":"create", "draft":draft}));
    finish(&mut app, root.path(), update).unwrap();
    split(&mut app, root.path());
    let review = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(review.coverage.context_members["shared"].total, 1);
    for scope in &review.record.draft.scopes {
        assert_eq!(scope.shared_dependencies, vec!["shared"]);
        assert_eq!(
            scope.open_questions,
            vec!["Which calls cross the shared boundary?"]
        );
    }
}

#[test]
fn scope_review_acceptance_paging_reads_the_visible_detail_without_toggling_approval() {
    let (_, mut app) = fixture();
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.open_scope_acceptance();
    let before = app.scope_review().unwrap().acknowledgements.clone();
    app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
    assert!(app.scope_review().unwrap().scroll > 0);
    assert_eq!(app.scope_review().unwrap().acknowledgements, before);
    app.reduce_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
    assert_eq!(app.scope_review().unwrap().scroll, 0);
}

#[test]
fn scope_review_yields_rendering_and_input_to_the_session_exit_confirmation() {
    let (_, mut app) = fixture();
    app.set_input("unsent command");
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    assert!(!app.scope_review_is_visible());
    assert!(app
        .handle_scope_review_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE))
        .is_none());
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, &app))
        .unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("CONFIRM SESSION EXIT"), "{text}");
    assert!(!text.contains("DRAFT SCOPES"));
    app.set_shell_view(ShellView::Workbench);
    assert!(app.scope_review_is_visible());
}

#[test]
fn scope_review_opens_and_refreshes_history_through_background_prepared_dispatch() {
    let (root, mut app) = fixture();
    let before = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .reference
        .clone();
    app.set_input("held operator draft");
    let update = press(&mut app, KeyCode::Char('r'));
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("refresh must use background dispatch")
    };
    assert_eq!(
        serde_json::from_str::<Value>(request.input.as_ref().unwrap()).unwrap()["operation"],
        "latest"
    );
    assert!(app.scope_review().unwrap().pending.is_some());
    assert_eq!(app.input(), "held operator draft");
    finish(&mut app, root.path(), update).unwrap();
    assert_eq!(
        app.scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .reference,
        before
    );
    assert_eq!(app.input(), "held operator draft");
}

#[test]
fn scope_review_cancellation_clears_pending_work_and_allows_a_specific_retry() {
    let (_, mut app) = fixture();
    let before = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .reference
        .clone();
    let update = press(&mut app, KeyCode::Char('r'));
    assert!(!update.effects.is_empty());
    app.scope_review_failed(
        "pack:scopes",
        "Operator canceled while another process held the lock",
    );
    let state = app.scope_review().unwrap();
    assert!(state.pending.is_none());
    assert_eq!(state.review.as_ref().unwrap().reference, before);
    assert!(state.notice.as_ref().unwrap().contains("Action stopped"));
    assert!(!press(&mut app, KeyCode::Char('r')).effects.is_empty());
}

#[test]
fn canceled_scope_tool_event_settles_the_pending_overlay_and_durable_run() {
    use crate::app::{EffectRuntime, ToolEvent};
    use kuzushi_core::run_artifacts::{
        load_run_summary, try_record_tool_run_started_with_reproducibility, ToolRunRecord,
    };
    let (root, mut app) = fixture();
    let update = press(&mut app, KeyCode::Char('r'));
    assert!(!update.effects.is_empty());
    let run_id = "scope-canceled-history";
    try_record_tool_run_started_with_reproducibility(
        ToolRunRecord::new(root.path(), run_id, "tool", "pack:scopes"),
        &json!({"operation":"latest"}),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    app.set_active_tool_run_id_for_test(run_id);
    app.set_running_tool_for_test("pack:scopes");
    app.set_tool_abort_requested_for_test(true);
    let effects = app.apply_tool_event(ToolEvent::Failed {
        tool_name: "pack:scopes".into(),
        error: "lock acquisition was canceled".into(),
    });
    EffectRuntime::execute(&mut app, effects);
    assert!(app.scope_review().unwrap().pending.is_none());
    assert!(app
        .scope_review()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Action stopped"));
    assert_eq!(
        load_run_summary(root.path(), run_id).unwrap().status,
        "canceled"
    );
}
