use crate::app::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn editor() -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Navigate);
    app.set_input("retained composer");
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert!(app.router.report().editing_path());
    app
}

#[test]
fn report_navigation_retires_review_success_but_preserves_errors_and_other_results() {
    for (source, severity, retained) in [
        ("review", NoticeSeverity::Success, false),
        ("review", NoticeSeverity::Error, true),
        ("review", NoticeSeverity::Warn, true),
        ("navigate", NoticeSeverity::Info, false),
        ("background", NoticeSeverity::Success, true),
    ] {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.advisory_mut().notice = Some(Notice {
            source: source.into(),
            message: "Recorded result".into(),
            severity,
            since: std::time::Instant::now(),
        });
        app.open_report_from_current_origin();
        assert_eq!(app.advisory().notice.is_some(), retained);
        assert_eq!(app.shell_view(), ShellView::Report);
    }
}

fn press(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) {
    let update = app.reduce_key(KeyEvent::new(code, modifiers));
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.input(), "retained composer");
    assert!(!app.has_running_work());
}

fn hydrate_workspace_report(app: &ShellApp) {
    let workspace = kuzushi_core::WorkspaceTarget::new(app.target().unwrap()).unwrap();
    let _store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    let watermark = app.findings_read_watermark();
    let summary =
        kuzushi_core::workspace::load_workspace_review_summary(&workspace, watermark).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key: ViewHydrationKey::WorkspaceReportReview {
                findings_watermark: watermark,
            },
            value: ViewHydrationValue::WorkspaceReportReview(Ok(summary)),
        });
}

#[test]
fn report_hydration_keys_follow_durable_review_watermark() {
    let root = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    for explicit in [false, true] {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.open_report_from_current_origin();
        if explicit {
            app.router.report_mut().set_study(Some(ReportStudyRef {
                campaign_id: "owned-study".into(),
                plan_sha256: "a".repeat(64),
            }));
        }
        app.set_findings_read_watermark(Some(1));
        let old = app.report_hydration_key();
        app.workbench_cache()
            .borrow_mut()
            .apply_view_hydration(ViewHydrationResult {
                target: root.path().into(),
                key: old.clone(),
                value: ViewHydrationValue::InvestigationReport(Err(
                    "obsolete review projection".into()
                )),
            });
        app.set_findings_read_watermark(Some(2));
        let current = app.report_hydration_key();
        assert_ne!(
            old, current,
            "A saved decision must invalidate the cached report conditions"
        );
        assert!(!matches!(
            app.workbench_cache()
                .borrow()
                .cached_selected_report(Some(root.path()), &current),
            ViewDataState::Ready(_)
        ));
        // A late result for the old watermark cannot be shown as current.
        app.workbench_cache()
            .borrow_mut()
            .apply_view_hydration(ViewHydrationResult {
                target: root.path().into(),
                key: old,
                value: ViewHydrationValue::InvestigationReport(Ok(None)),
            });
        assert!(!matches!(
            app.workbench_cache()
                .borrow()
                .cached_selected_report(Some(root.path()), &current),
            ViewDataState::Ready(_)
        ));
    }
}

#[test]
fn report_scope_and_provenance_preserve_composer_and_saved_destination() {
    let mut app = editor();
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    let path = app.router.report().path_draft().to_string();
    press(&mut app, KeyCode::Char('s'), KeyModifiers::NONE);
    press(&mut app, KeyCode::Char('p'), KeyModifiers::NONE);
    assert!(app.router.report().workspace_history());
    assert!(app.router.report().provenance_details());
    assert_eq!(app.router.report().path_draft(), path);
    press(&mut app, KeyCode::Char('s'), KeyModifiers::NONE);
    assert!(!app.router.report().workspace_history());
}

#[test]
fn report_loading_refuses_export_until_explicit_history_has_a_current_read() {
    let target = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_report_from_current_origin();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    assert!(app
        .router
        .report()
        .reveal_error()
        .unwrap()
        .contains("loading"));
    app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    hydrate_workspace_report(&app);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::ExportReport(ReportExport {
            campaign_id: None,
            ..
        })]
    ));
}

#[test]
fn damaged_scope_evidence_blocks_export_until_chosen_history_has_a_current_read() {
    let target = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_report_from_current_origin();
    let error = "study report's accepted scope evidence is unavailable";
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().to_path_buf(),
            key: ViewHydrationKey::InvestigationReport {
                run_refs: app.report_scan_run_refs(),
                findings_watermark: app.findings_read_watermark(),
            },
            value: ViewHydrationValue::InvestigationReport(Err(error.into())),
        });
    let lines = crate::ui_view_models::report_investigation_lines(&app).join("\n");
    assert!(lines.contains("Scope: study receipt unavailable"));
    assert!(lines.contains(error));
    assert!(lines.contains("s selects workspace history"));
    let path = app.router.report().path_draft().to_string();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    let refusal = app.router.report().reveal_error().unwrap();
    assert!(refusal.contains(error) && refusal.contains("Press s"));
    assert_eq!(app.router.report().path_draft(), path);
    app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    hydrate_workspace_report(&app);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::ExportReport(ReportExport {
            campaign_id: None,
            ..
        })]
    ));
}

#[test]
fn report_destination_cursor_delete_and_escape_restore_saved_path() {
    let mut app = editor();
    let original = app.router.report().path_draft().to_string();
    press(&mut app, KeyCode::Home, KeyModifiers::NONE);
    press(&mut app, KeyCode::Char('界'), KeyModifiers::SHIFT);
    assert_eq!(app.router.report().path_draft(), format!("界{original}"));
    press(&mut app, KeyCode::Delete, KeyModifiers::NONE);
    assert_eq!(
        app.router.report().path_draft(),
        format!("界{}", &original[1..])
    );
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(app.router.report().path_draft(), original);
    assert!(!app.router.report().editing_path());
}

#[test]
fn report_destination_paste_and_save_stay_in_the_field() {
    let mut app = editor();
    press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    assert_eq!(app.router.report().path_draft(), "");
    let update = app.reduce_paste(".kuzushi/reports/review, 界.json");
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.input(), "retained composer");
    assert_eq!(
        app.router.report().path_draft(),
        ".kuzushi/reports/review, 界.json"
    );
    press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert!(!app.router.report().editing_path());
    assert_eq!(
        app.router.report().path_draft(),
        ".kuzushi/reports/review, 界.json"
    );
}

#[test]
fn report_destination_invalid_draft_stays_editable_and_can_be_canceled() {
    for draft in ["", "one\ntwo", "bad\0path"] {
        let mut app = editor();
        let original = app.router.report().path_draft().to_string();
        press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
        app.router.report_mut().insert_path_text(draft);
        press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.router.report().editing_path());
        assert!(app.router.report().path_error().is_some());
        assert_eq!(app.router.report().path_draft(), draft);
        press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(app.router.report().path_draft(), original);
    }
}

#[test]
fn report_destination_formats_preserve_their_saved_paths() {
    let mut app = editor();
    press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    app.reduce_paste(".kuzushi/reports/my review.sarif");
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    app.router.report_mut().move_format(1);
    assert_eq!(app.router.report().path_draft(), ".kuzushi/reports/report/");
    app.router.report_mut().move_format(-1);
    assert_eq!(
        app.router.report().path_draft(),
        ".kuzushi/reports/my review.sarif"
    );
}

#[test]
fn report_destination_quit_and_stay_preserve_the_unsaved_field() {
    let mut app = editor();
    app.set_input("");
    app.router.report_mut().insert_path_text(" unsaved 界");
    app.reduce_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    let field = app.router.report().path_edit().unwrap().clone();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    let warning = crate::ui_view_models::quit_confirm_model(&app);
    assert!(format!("{warning:?}").contains("report destination draft"));
    assert!(!format!("{warning:?}").contains("unsaved 界"));
    app.reduce_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.router.report().path_edit(), Some(&field));
    assert!(!app.should_quit());
}

#[test]
fn report_refresh_keeps_scope_reading_choices_and_composer_without_starting_work() {
    let mut app = editor();
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    press(&mut app, KeyCode::Char('s'), KeyModifiers::NONE);
    press(&mut app, KeyCode::Down, KeyModifiers::NONE);
    app.router.default_scroll_mut().scroll_down(5);
    let format = app.router.report().format();
    let path = app.router.report().path_draft().to_owned();
    let cursor = app.cursor();
    press(&mut app, KeyCode::Char('r'), KeyModifiers::NONE);
    assert!(app.router.report().workspace_history());
    assert_eq!(app.router.report().format(), format);
    assert_eq!(app.router.report().path_draft(), path);
    assert_eq!(app.router.default_scroll().offset(), 5);
    assert_eq!(app.cursor(), cursor);
    assert_eq!(app.shell_view(), ShellView::Report);
}

#[test]
fn report_destination_editor_owns_refresh_letters() {
    let mut app = editor();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert!(app.router.report().editing_path());
    assert_eq!(app.input(), "retained composer");
    assert!(!app.has_running_work());
}

#[test]
fn report_paging_is_visible_and_preserves_choices_and_draft_at_every_viewport() {
    use ratatui::{backend::TestBackend, Terminal};
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.open_report_from_current_origin();
        app.router.report_mut().toggle_scope();
        hydrate_workspace_report(&app);
        app.set_input("retained composer");
        app.reduce_resize(width, height);
        app.router.report_mut().set_reveal_error(Some(format!(
            "{} END_OF_RECORDED_REPORT_ERROR",
            "Labeled report read failure remains available for inspection. ".repeat(300)
        )));
        let choices = app.router.report().captured_choices("/owned".into());
        let cursor = app.cursor();
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
        assert!(text.contains("PgUp/PgDn read"), "{width}x{height}: {text}");
        assert!(!text.contains("END_OF_RECORDED_REPORT_ERROR"));
        let mut reached_end = false;
        for _ in 0..512 {
            press(&mut app, KeyCode::PageDown, KeyModifiers::NONE);
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
            assert!(text.contains("PgUp/PgDn read"));
            if text.contains("END_OF_RECORDED_REPORT_ERROR") {
                reached_end = true;
                break;
            }
        }
        assert!(
            reached_end,
            "{width}x{height}: paging must reach all recorded error text"
        );
        assert!(app.router.default_scroll().offset() > 0);
        assert_eq!(
            app.router.report().captured_choices("/owned".into()),
            choices
        );
        assert_eq!(app.cursor(), cursor);
        press(&mut app, KeyCode::Home, KeyModifiers::NONE);
        assert_eq!(app.router.default_scroll().offset(), 0);
    }
}
