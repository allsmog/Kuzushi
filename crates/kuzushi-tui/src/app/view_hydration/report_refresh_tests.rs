use super::*;
use crate::ui_view_models::{
    report_export_campaign, report_investigation_state, report_is_refreshing,
};
use kuzushi_core::workspace::InvestigationReportDocument;
use kuzushi_core::{V2Config, WorkspaceTarget};

#[test]
fn scope_overlay_keeps_selected_study_hydration_after_tool_completion_changes_the_view() {
    let root = tempfile::tempdir().unwrap();
    let mut app = workspace_app(root.path());
    app.router.report_mut().toggle_scope();
    app.router
        .report_mut()
        .set_study(Some(crate::app::ReportStudyRef {
            campaign_id: "owned-study".into(),
            plan_sha256: "owned-digest".into(),
        }));
    app.set_shell_view(ShellView::Module);
    *app.router.scope_review_mut() = Some(crate::app::ScopeReviewState::new(
        app.target_owned().unwrap(),
    ));
    let expected = app.report_hydration_key();
    assert!(requests::active_view_hydration_keys(&app).contains(&expected));
    app.router.scope_review_mut().as_mut().unwrap().open = false;
    assert!(!requests::active_view_hydration_keys(&app).contains(&expected));
}

fn workspace_app(root: &std::path::Path) -> ShellApp {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(root.into()));
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Navigate);
    app.router.report_mut().toggle_scope();
    app
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

#[derive(Debug)]
struct DelayedReportReader {
    document: InvestigationReportDocument,
    entered: std::sync::atomic::AtomicBool,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}

impl crate::app::ViewArtifactReader for DelayedReportReader {
    fn read(&self, _target: &std::path::Path, _key: &ViewHydrationKey) -> ViewHydrationValue {
        self.entered
            .store(true, std::sync::atomic::Ordering::Release);
        let _ = self
            .wake
            .wait_timeout_while(
                self.released.lock().unwrap(),
                std::time::Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap();
        ViewHydrationValue::InvestigationReport(Ok(Some(self.document.clone())))
    }
}

fn delayed_report_app(
    root: &Path,
) -> (
    ShellApp,
    Arc<DelayedReportReader>,
    Arc<InvestigationReportDocument>,
) {
    let document = study_document(root);
    let mut app = workspace_app(root);
    app.router.report_mut().toggle_scope();
    cache_document(&app, document.clone());
    let ViewDataState::Ready(Ok(Some(before))) = report_investigation_state(&app) else {
        panic!("ready document")
    };
    let reader = Arc::new(DelayedReportReader {
        document,
        entered: std::sync::atomic::AtomicBool::new(false),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    app.set_view_artifact_reader_for_test(reader.clone());
    app.set_input("held investigation draft");
    app.router.default_scroll_mut().set(3);
    app.open_report_from_current_origin();
    app.schedule_view_hydration_keys(root.into(), vec![app.report_hydration_key()]);
    (app, reader, before)
}

fn wait_for_delayed_read(reader: &DelayedReportReader) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !reader.entered.load(std::sync::atomic::Ordering::Acquire) {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn assert_pending_report(app: &ShellApp, before: &Arc<InvestigationReportDocument>) {
    assert!(report_is_refreshing(app));
    let previous = app
        .workbench_cache()
        .borrow()
        .cached_previous_selected_report(app.target().unwrap(), &app.report_hydration_key())
        .unwrap();
    assert!(Arc::ptr_eq(before, &previous));
    for width in [40, 60, 80, 96, 120, 160] {
        let text = crate::renderer::render_plain_app(app, width);
        assert!(text.contains("Refreshing"), "{width}: {text}");
        assert!(!text.contains("Loading report findings"));
        assert!(!text.contains('\x1b'));
    }
    assert!(report_export_campaign(app).is_err());
    assert_eq!(app.router.default_scroll().offset(), 3);
    assert_eq!(app.input(), "held investigation draft");
}

fn finish_delayed_report(app: &mut ShellApp, reader: &DelayedReportReader) {
    *reader.released.lock().unwrap() = true;
    reader.wake.notify_all();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while report_is_refreshing(app) {
        assert!(std::time::Instant::now() < deadline);
        app.apply_view_hydration_results();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(matches!(
        report_investigation_state(app),
        ViewDataState::Ready(Ok(Some(_)))
    ));
    assert!(report_export_campaign(app).is_ok());
    assert_eq!(app.router.default_scroll().offset(), 3);
    assert_eq!(app.input(), "held investigation draft");
}

#[test]
fn delayed_study_read_preserves_visible_bytes_navigation_and_composer() {
    let root = tempfile::tempdir().unwrap();
    let (mut app, reader, before) = delayed_report_app(root.path());
    wait_for_delayed_read(&reader);
    assert_pending_report(&app, &before);
    finish_delayed_report(&mut app, &reader);
}
