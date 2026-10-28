use super::*;
use crate::app::{ShellView, WorkbenchPage};

#[test]
fn report_from_case_review_keeps_the_exact_study_instead_of_another_scan_attempt() {
    let (_root, mut app, _) = review_fixture();
    app.router.default_scroll_mut().set(17);
    let origin = app.router.workbench().clone();
    app.set_input("held multiline\noperator draft");
    app.set_cursor(4);
    app.open_report_from_current_origin();
    let study = app.router.report().study().unwrap();
    assert_eq!(study.campaign_id, "matrix-ui");
    assert_eq!(study.plan_sha256, "a".repeat(64));
    assert!(!app.router.report().workspace_history());
    assert_eq!(app.router.default_scroll().offset(), 0);
    assert!(
        matches!(app.report_hydration_key(), ViewHydrationKey::InvestigationStudyReport { campaign_id,plan_sha256,.. } if campaign_id=="matrix-ui" && plan_sha256=="a".repeat(64))
    );
    app.open_report_from_current_origin();
    assert!(app.router.report().study().is_some());
    app.close_report_to_origin();
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench(), &origin);
    assert!(app.matrix_observation_return_is_available());
    assert_eq!(
        (app.input(), app.cursor()),
        ("held multiline\noperator draft", 4)
    );
}

#[test]
fn failed_study_report_does_not_export_workspace_history_without_its_explicit_switch() {
    let (_root, mut app, _) = review_fixture();
    app.open_report_from_current_origin();
    let study = app.router.report().study().cloned();
    assert!(study.is_some());
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key: app.report_hydration_key(),
            value: ViewHydrationValue::InvestigationReport(Err("Owned saved plan changed".into())),
        });
    assert!(crate::ui_view_models::report_export_campaign(&app).is_err());
    assert_eq!(app.router.report().study().cloned(), study);
    app.router.report_mut().toggle_scope();
    app.open_report_from_current_origin();
    assert!(app.router.report().workspace_history());
    assert!(crate::ui_view_models::report_export_campaign(&app).is_err());
    let workspace = WorkspaceTarget::new(app.target().unwrap()).unwrap();
    let watermark = app.findings_read_watermark();
    let summary =
        kuzushi_core::workspace::load_workspace_review_summary(&workspace, watermark).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key: ViewHydrationKey::WorkspaceReportReview {
                findings_watermark: watermark,
            },
            value: ViewHydrationValue::WorkspaceReportReview(Ok(summary)),
        });
    assert_eq!(
        crate::ui_view_models::report_export_campaign(&app).unwrap(),
        None
    );
    assert_eq!(app.router.report().study().cloned(), study);
    app.router.report_mut().toggle_scope();
    assert!(crate::ui_view_models::report_export_campaign(&app).is_err());
}

#[test]
fn report_from_another_phase_does_not_inherit_a_retained_matrix_review_origin() {
    let (_root, mut app, _) = review_fixture();
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Map));
    app.open_report_from_current_origin();
    assert!(app.router.report().study().is_none());
    assert!(
        matches!(app.report_hydration_key(),ViewHydrationKey::InvestigationReport { run_refs,.. } if run_refs==["unrelated-scan"])
    );
}
