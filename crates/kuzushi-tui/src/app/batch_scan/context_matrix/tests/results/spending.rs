use super::*;
use kuzushi_core::{
    allowance::{AllowanceLimits, AllowanceSnapshot},
    runtime::RuntimeCostReport,
};
use std::sync::Arc;

fn seed(app: &ShellApp, value: crate::app::view_hydration::InvestigationAllowanceRead) {
    let key = app.investigation_allowance_key().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key,
            value: ViewHydrationValue::InvestigationAllowance(value),
        });
}

#[test]
fn case_and_finding_pages_keep_current_consumption_visible_across_all_viewports() {
    let (_root, mut app) = result_fixture();
    app.set_input("kept draft");
    app.set_cursor(3);
    let snapshot = AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "accounting".into(),
        revision: 2,
        model: "operator:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: 7,
            protected_review_calls: 2,
        },
        committed_calls: 5,
        review_calls: 0,
        unresolved_calls: 1,
        cost: RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    };
    seed(&app, Ok(Some(Arc::new(snapshot))));
    let before = app.router.campaign().batch_scan_config.clone();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        for findings in [false, true] {
            if findings {
                app.handle_matrix_result_key(KeyCode::Char('f'));
            }
            let frame = super::reading::page(&app);
            for expected in ["Calls 5/7", "Review 2 protected", "1 unsettled"] {
                assert!(frame.contains(expected), "{width}x{height}: {frame}");
            }
            assert!(!frame.contains("$0"), "{frame}");
            app.handle_matrix_result_key(KeyCode::End);
            assert!(super::reading::page(&app).contains("Calls 5/7"));
            app.handle_matrix_result_key(KeyCode::Home);
            if findings {
                app.handle_matrix_result_key(KeyCode::Esc);
            }
        }
    }
    assert_eq!(app.router.campaign().batch_scan_config, before);
    assert_eq!((app.input(), app.cursor()), ("kept draft", 3));
    let plain = crate::ui_view_models::matrix_plain_lines(&app, 120)
        .unwrap()
        .join("\n");
    assert!(plain.contains("1 unsettled") && plain.contains("cost not recorded"));
}

#[test]
fn failed_unapproved_and_loading_allowance_reads_stay_distinct_without_resetting_saved_spending() {
    let (_root, mut app) = result_fixture();
    let key = app.investigation_allowance_key().unwrap();
    assert!(matches!(key, ViewHydrationKey::StudyAllowance { .. }));
    assert!(super::reading::page(&app).contains("Allowance loading"));
    let before = app.router.campaign().batch_scan_config.clone();
    seed(&app, Ok(None));
    assert!(super::reading::page(&app).contains("Allowance not approved"));
    seed(&app, Err("Owned ledger read failure".into()));
    assert!(super::reading::page(&app).contains("Allowance unavailable"));
    let plain = crate::ui_view_models::matrix_plain_lines(&app, 120)
        .unwrap()
        .join("\n");
    assert!(plain.contains("Owned ledger read failure"));
    assert_eq!(app.router.campaign().batch_scan_config, before);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .matrix
        .receipt
        .as_mut()
        .unwrap()
        .plan_sha256 = "b".repeat(64);
    assert_ne!(app.investigation_allowance_key(), Some(key));
    assert!(super::reading::page(&app).contains("Allowance loading"));
    app.set_shell_view(ShellView::Replay);
    assert!(app.investigation_allowance_key().is_none());
}
