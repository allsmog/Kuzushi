use super::*;
use crate::app::{InputMode, ShellView, ViewHydrationKey, ViewHydrationResult, ViewHydrationValue};
use kuzushi_core::{V2Config, WorkspaceTarget};

fn workspace_app(root: &std::path::Path) -> ShellApp {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(root.into()));
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Navigate);
    app.router.report_mut().toggle_scope();
    app
}

fn cache_summary(app: &ShellApp, result: Result<WorkspaceReviewSummary, String>) {
    let key = ViewHydrationKey::WorkspaceReportReview {
        findings_watermark: app.findings_read_watermark(),
    };
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key,
            value: ViewHydrationValue::WorkspaceReportReview(result),
        });
}

#[test]
fn previous_counts_remain_labeled_and_readable_while_export_waits_for_current_data() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let root = tempfile::tempdir().unwrap();
    let mut app = workspace_app(root.path());
    cache_summary(
        &app,
        Ok(WorkspaceReviewSummary {
            finding_count: 3,
            ..Default::default()
        }),
    );
    assert_eq!(report_export_campaign(&app).unwrap(), None);
    app.set_input("held operator draft");
    app.router.default_scroll_mut().set(2);
    let choices = app
        .router
        .report()
        .captured_choices(root.path().to_path_buf());
    app.open_report_from_current_origin();
    assert!(report_is_refreshing(&app));
    assert!(report_review_summary(&app).contains("3 findings"));
    assert!(report_review_summary(&app).contains("previous read"));
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("Refreshing"), "{plain}");
    assert!(!plain.contains("Loading report findings"));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(
        update.effects.is_empty(),
        "previous presentation cannot export"
    );
    assert_eq!(
        app.router
            .report()
            .captured_choices(root.path().to_path_buf()),
        choices
    );
    assert_eq!(app.input(), "held operator draft");
    assert_eq!(app.router.default_scroll().offset(), 2);
    cache_summary(
        &app,
        Ok(WorkspaceReviewSummary {
            finding_count: 4,
            ..Default::default()
        }),
    );
    assert!(!report_is_refreshing(&app));
    assert!(report_review_summary(&app).contains("4 findings"));
    assert!(report_export_campaign(&app).is_ok());
    assert!(crate::ui_view_models::report_action_error(&app).is_none());
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(!plain.contains("Report action:"), "{plain}");
}

#[test]
fn failed_refresh_hides_previous_counts_and_retry_keeps_the_error_honest() {
    let root = tempfile::tempdir().unwrap();
    let mut app = workspace_app(root.path());
    cache_summary(
        &app,
        Ok(WorkspaceReviewSummary {
            finding_count: 7,
            ..Default::default()
        }),
    );
    app.open_report_from_current_origin();
    assert!(report_is_refreshing(&app));
    let update = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::empty(),
    ));
    assert!(update.effects.is_empty());
    cache_summary(&app, Err("Owned missing review ledger".into()));
    assert!(!report_is_refreshing(&app));
    assert!(report_review_summary(&app).contains("unavailable"));
    assert!(!report_review_summary(&app).contains("7 findings"));
    assert!(report_export_campaign(&app).is_err());
    assert!(crate::ui_view_models::report_action_error(&app)
        .unwrap()
        .contains("Owned missing review ledger"));
    app.open_report_from_current_origin();
    assert!(!report_is_refreshing(&app));
    assert!(report_review_summary(&app).contains("Loading"));
}

fn study_document(root: &std::path::Path) -> InvestigationReportDocument {
    use kuzushi_core::capabilities::campaign::{
        compile_scan_batch_plan, ScanBatchGatePolicy, ScanBatchPlanSpec,
    };
    std::fs::write(
        root.join("README.md"),
        "Owned report reader fixture. No target execution.\n",
    )
    .unwrap();
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root,
        batch_id: Some("owned-report-reader".into()),
        trials: 3,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: serde_json::json!({"taskMode":"manual","tasks":["license-scan"]}),
        config: &V2Config::default(),
        registry: &kuzushi_core::ModuleRegistry::with_v2_builtins(),
    })
    .unwrap();
    kuzushi_core::workspace::load_investigation_report_document(
        &WorkspaceTarget::new(root).unwrap(),
        "owned-report-reader",
    )
    .unwrap()
}

fn cache_document(app: &ShellApp, document: InvestigationReportDocument) {
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key: app.report_hydration_key(),
            value: ViewHydrationValue::InvestigationReport(Ok(Some(document))),
        });
}

#[test]
fn failed_study_reader_replaces_previous_content_and_requires_explicit_retry() {
    let root = tempfile::tempdir().unwrap();
    let document = study_document(root.path());
    let mut app = workspace_app(root.path());
    app.router.report_mut().toggle_scope();
    cache_document(&app, document);
    assert_eq!(
        report_export_campaign(&app).unwrap().as_deref(),
        Some("owned-report-reader")
    );
    app.open_report_from_current_origin();
    assert!(report_is_refreshing(&app));
    let failure = crate::app::ViewHydrationFailure {
        target: root.path().into(),
        key: app.report_hydration_key(),
    };
    app.workbench_cache()
        .borrow_mut()
        .clear_failed_view_hydrations(&[failure]);
    assert!(matches!(
        report_document_view(&app),
        ReportReadView::Failed(_)
    ));
    assert!(report_export_campaign(&app).is_err());
    assert!(!report_is_refreshing(&app));
    app.open_report_from_current_origin();
    assert!(matches!(
        report_document_view(&app),
        ReportReadView::Loading
    ));
}
