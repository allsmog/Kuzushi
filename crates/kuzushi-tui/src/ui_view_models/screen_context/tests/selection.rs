use super::*;
use crate::app::WorkbenchPage;
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed_with_v2, PhaseAttemptCompleted, PhaseAttemptOutcome,
    PhaseTargetSnapshot,
};
use kuzushi_core::{WorkflowPhase, WorkspaceTarget};
use serde_json::json;

fn finding_app(root: &std::path::Path) -> ShellApp {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(root.into()));
    app.engagement
        .planning_picker_mut()
        .set_return_to_setup(false);
    let finding = Finding::new_tool(
        "owned",
        "owned.rule",
        "owned.rs",
        4,
        None,
        Severity::High,
        "Pinned review item",
    );
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);
    app.set_input("preserved operator draft");
    app.set_shell_view(ShellView::Workbench);
    app
}

fn record_attempt(root: &std::path::Path, phase: WorkflowPhase, runs: &[&str], selected: bool) {
    for run in runs {
        crate::test_support::record_indexed_run(root, run, "sast:scan", json!({"ok":true}));
    }
    let completed = PhaseAttemptCompleted::new(
        phase,
        runs.iter().map(|run| (*run).into()).collect(),
        PhaseTargetSnapshot::capture(root),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new().to_string());
    append_phase_attempt_completed_with_v2(root, completed.clone()).unwrap();
    if selected {
        crate::test_support::select_typed_attempt(root, &completed);
    }
}

#[test]
fn pinned_finding_is_attached_only_while_its_page_is_visible() {
    let root = tempfile::tempdir().unwrap();
    let mut app = finding_app(root.path());
    let original = app.selected_finding().clone();
    for page in [WorkbenchPage::Map, WorkbenchPage::Scan] {
        app.set_workbench_page(page);
        assert_no_finding_context(&app);
        assert_eq!(
            screen_context_model(&app).displayed_phase.as_deref(),
            Some(page.title().to_ascii_lowercase().as_str())
        );
    }
    for view in [
        ShellView::Report,
        ShellView::Setup,
        ShellView::Config,
        ShellView::Logs,
    ] {
        app.set_shell_view(view);
        assert_no_finding_context(&app);
    }
    app.set_shell_view(ShellView::Workbench);
    app.set_workbench_page(WorkbenchPage::Review);
    let context = screen_context_model(&app);
    assert_eq!(context.selected_item.unwrap().title, "Pinned review item");
    assert_eq!(context.visible_rows.len(), 1);
    assert_eq!(context.finding_summary.unwrap().total, 1);
    assert_eq!(app.selected_finding(), &original);
    assert_eq!(app.input(), "preserved operator draft");
}

fn assert_no_finding_context(app: &ShellApp) {
    let context = screen_context_model(app);
    assert!(context.selected_item.is_none());
    assert!(context.finding_summary.is_none());
    assert!(context.visible_rows.is_empty());
    let json = context.to_prompt_json();
    assert!(!json.contains("Pinned review item"));
    assert!(!context.scope_chip().unwrap().contains("F-0001"));
}

#[test]
fn viewed_page_and_report_are_separate_from_workflow_reality() {
    let root = tempfile::tempdir().unwrap();
    record_attempt(root.path(), WorkflowPhase::Map, &["map"], true);
    record_attempt(root.path(), WorkflowPhase::Scan, &["scan"], true);
    let mut app = finding_app(root.path());
    app.refresh_phase_attempt_projection();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(crate::app::ViewHydrationResult {
            target: root.path().into(),
            key: crate::app::ViewHydrationKey::GitMetadata,
            value: crate::app::ViewHydrationValue::GitMetadata(Some(
                kuzushi_core::RunTargetGitMetadata {
                    sha: "current-checkout".into(),
                    branch: Some("main".into()),
                    dirty: true,
                },
            )),
        });
    app.set_workbench_page(WorkbenchPage::Map);
    let map = screen_context_model(&app);
    assert_eq!(map.active_phase.as_deref(), Some("scan"));
    assert_eq!(map.displayed_phase.as_deref(), Some("map"));
    assert!(map.scope_chip().unwrap().contains(" · Map"));
    app.set_workbench_page(WorkbenchPage::Scan);
    let scan = screen_context_model(&app);
    assert_eq!(scan.active_phase, map.active_phase);
    assert_eq!(scan.displayed_phase.as_deref(), Some("scan"));
    assert_eq!(
        scan.selected_revision.as_ref().unwrap().sha,
        "current-checkout"
    );
    assert!(scan.scope_chip().unwrap().contains(" · Scan"));
    assert!(scan
        .to_prompt_json()
        .contains("\"displayedPhase\": \"scan\""));
    app.set_shell_view(ShellView::Report);
    let report = screen_context_model(&app);
    assert_eq!(report.active_phase, map.active_phase);
    assert_eq!(report.displayed_phase.as_deref(), Some("report"));
    assert!(report.selected_revision.is_none());
    assert!(report.scope_chip().unwrap().ends_with(" · Report"));
    assert!(report.selected_run.is_none());
}

#[test]
fn grouped_run_prompt_context_is_bounded_and_discloses_omissions() {
    let root = tempfile::tempdir().unwrap();
    let runs = (0..13)
        .map(|n| format!("owned-run-{n:02}"))
        .collect::<Vec<_>>();
    let names = runs.iter().map(String::as_str).collect::<Vec<_>>();
    record_attempt(root.path(), WorkflowPhase::Scan, &names, true);
    let mut app = finding_app(root.path());
    app.refresh_phase_attempt_projection();
    app.set_workbench_page(WorkbenchPage::Scan);
    let context = screen_context_model(&app);
    assert_eq!(context.selected_run_count, 13);
    assert_eq!(context.selected_runs.len(), SCREEN_CONTEXT_LIST_LIMIT);
    assert!(context.selected_run.is_none());
    let value: serde_json::Value = serde_json::from_str(&context.to_prompt_json()).unwrap();
    assert_eq!(value["selectedRunCount"], 13);
    assert_eq!(value["selectedRunsTruncated"], true);
    assert!(!context.to_prompt_json().contains("owned-run-12"));
}

#[test]
fn run_context_tracks_the_displayed_attempt_and_keeps_review_on_its_accepted_scan() {
    let root = tempfile::tempdir().unwrap();
    record_attempt(root.path(), WorkflowPhase::Map, &["map"], true);
    record_attempt(root.path(), WorkflowPhase::Scan, &["scan"], true);
    let mut app = finding_app(root.path());
    record_attempt(
        root.path(),
        WorkflowPhase::Scan,
        &["pending-a", "pending-b"],
        false,
    );
    app.refresh_phase_attempt_projection();
    app.set_workbench_page(WorkbenchPage::Scan);
    let context = screen_context_model(&app);
    assert_eq!(context.selected_runs, ["pending-a", "pending-b"]);
    assert!(
        context.selected_run.is_none(),
        "a group has no single selected run"
    );
    app.set_workbench_page(WorkbenchPage::Review);
    let context = screen_context_model(&app);
    assert_eq!(context.selected_runs, ["scan"]);
    assert_eq!(context.selected_run.as_deref(), Some("scan"));
    app.set_workbench_page(WorkbenchPage::Map);
    assert_eq!(screen_context_model(&app).selected_runs, ["map"]);
    assert_eq!(app.input(), "preserved operator draft");
}

#[test]
fn empty_report_and_settings_do_not_reuse_a_previous_scan_run() {
    let root = tempfile::tempdir().unwrap();
    let mut app = finding_app(root.path());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("unrelated-transient-run".into()),
        target: root.path().into(),
        stage: "done".into(),
        findings_count: 1,
        running: false,
        abort_requested: false,
        error: None,
    }));
    for view in [
        ShellView::Report,
        ShellView::Setup,
        ShellView::Config,
        ShellView::Help,
    ] {
        app.set_shell_view(view);
        let context = screen_context_model(&app);
        assert!(context.selected_run.is_none());
        assert!(context.selected_runs.is_empty());
        assert!(!context.to_prompt_json().contains("unrelated-transient-run"));
    }
}

#[test]
fn report_run_context_uses_only_its_matching_hydrated_document() {
    use crate::app::{ViewHydrationResult, ViewHydrationValue};
    use kuzushi_core::workspace::InvestigationReportDocument;
    let root = tempfile::tempdir().unwrap();
    let mut app = finding_app(root.path());
    app.set_shell_view(ShellView::Report);
    let key = app.report_hydration_key();
    let document = report_document(root.path());
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: root.path().into(),
            key: key.clone(),
            value: ViewHydrationValue::InvestigationReport(Ok(Some(
                InvestigationReportDocument::Study(document),
            ))),
        });
    assert_eq!(
        screen_context_model(&app).selected_runs,
        ["recorded-a", "recorded-canceled"]
    );
    assert!(screen_context_model(&app).selected_run.is_none());
    app.router.report_mut().toggle_scope();
    assert!(screen_context_model(&app).selected_runs.is_empty());
    app.router.report_mut().toggle_scope();
    assert_eq!(screen_context_model(&app).selected_runs.len(), 2);
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: root.path().into(),
            key,
            value: ViewHydrationValue::InvestigationReport(
                Err("Owned unavailable document".into()),
            ),
        });
    assert!(screen_context_model(&app).selected_runs.is_empty());
    assert_eq!(app.input(), "preserved operator draft");
}

fn report_document(root: &std::path::Path) -> kuzushi_core::workspace::InvestigationReportReceipt {
    use kuzushi_core::capabilities::campaign::{
        compile_scan_batch_plan, ScanBatchGatePolicy, ScanBatchPlanSpec,
    };
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root,
        batch_id: Some("screen-context".into()),
        trials: 3,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({"taskMode":"manual","tasks":["license-scan"]}),
        config: &V2Config::default(),
        registry: &kuzushi_core::ModuleRegistry::with_v2_builtins(),
    })
    .unwrap();
    let mut document = kuzushi_core::workspace::load_investigation_report(
        &WorkspaceTarget::new(root).unwrap(),
        "screen-context",
    )
    .unwrap();
    document.attempts = ["recorded-a", "recorded-canceled"]
        .into_iter()
        .map(|run| kuzushi_core::workspace::InvestigationAttemptReceipt {
            run_id: run.into(),
            run_status: None,
            source_identity: kuzushi_core::workflow_attempts::TargetContentIdentity::Unavailable {
                reason: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                    "Owned screen-only receipt fixture",
                ),
            },
            scan: None,
        })
        .collect();
    document
}
