use super::*;
use crate::app::{ShellView, WorkbenchPage};
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot};
use std::sync::Arc;

fn snapshot() -> AllowanceSnapshot {
    AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "matrix-accounting".into(),
        revision: 1,
        model: "operator:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: 7,
            protected_review_calls: 2,
        },
        committed_calls: 5,
        review_calls: 0,
        unresolved_calls: 1,
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    }
}

fn seed(
    app: &ShellApp,
    key: ViewHydrationKey,
    value: crate::app::view_hydration::InvestigationAllowanceRead,
) {
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key,
            value: ViewHydrationValue::InvestigationAllowance(value),
        });
}

#[test]
fn recorded_case_review_keeps_its_study_allowance_instead_of_the_selected_scan_attempt() {
    let (_root, mut app, expected) = review_fixture();
    assert_eq!(app.investigation_allowance_key(), Some(expected.clone()));
    seed(&app, expected.clone(), Ok(Some(Arc::new(snapshot()))));
    let held = app.router.campaign().matrix_observation_origin.clone();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let frame = super::super::reading::page(&app);
        assert!(frame.contains("calls 5/7"), "{width}x{height}: {frame}");
    }
    let model = crate::ui_view_models::investigation_allowance_model(&app).unwrap();
    assert!(model.rows.contains(&"Study: matrix-ui".into()));
    assert!(model.rows.contains(&"2 Review protected".into()));
    assert!(model.rows.contains(&"1 unsettled".into()));
    assert!(!model.rows.iter().any(|row| row.contains("$0")));
    assert_eq!(app.router.campaign().matrix_observation_origin, held);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Scan));
    assert_eq!(
        app.investigation_allowance_key(),
        Some(ViewHydrationKey::InvestigationAllowance {
            run_refs: vec!["unrelated-scan".into()]
        })
    );
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    assert_eq!(app.investigation_allowance_key(), Some(expected.clone()));
    app.go_back();
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.investigation_allowance_key(), Some(expected));
}

#[test]
fn missing_and_failed_bound_allowance_never_show_unrelated_or_zero_session_spending() {
    let (_root, app, expected) = review_fixture();
    for (value, label) in [
        (Ok(None), "calls unapproved"),
        (Err("Owned ledger failure".into()), "calls unavailable"),
    ] {
        seed(&app, expected.clone(), value);
        assert_eq!(app.investigation_allowance_key(), Some(expected.clone()));
        let model = crate::ui_view_models::investigation_allowance_model(&app).unwrap();
        assert_eq!(model.calls, label);
        assert!(model.rows.contains(&"Study: matrix-ui".into()));
        let rail = crate::ui_view_models::rail_sections(&app, 40);
        assert!(!rail.iter().any(|section| section.title == "SESSION COST"));
        assert!(rail
            .iter()
            .any(|section| section.title == "INVESTIGATION ALLOWANCE"));
    }
}

#[test]
fn leaving_review_or_switching_target_drops_the_matrix_allowance_binding() {
    let (_root, mut app, expected) = review_fixture();
    assert_eq!(app.investigation_allowance_key(), Some(expected.clone()));
    for view in [ShellView::Replay, ShellView::Report, ShellView::Home] {
        app.set_shell_view(view);
        assert!(app.investigation_allowance_key().is_none());
    }
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    assert_eq!(app.investigation_allowance_key(), Some(expected));
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    assert!(app.router.campaign().matrix_observation_origin.is_none());
    assert!(app.investigation_allowance_key().is_none());
}
