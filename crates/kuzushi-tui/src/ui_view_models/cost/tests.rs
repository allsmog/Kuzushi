use super::*;
use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
use kuzushi_core::V2Config;

#[test]
fn missing_and_unmetered_costs_never_render_as_measured_budget_shares() {
    for report in [
        RuntimeCostReport::UNAVAILABLE,
        RuntimeCostReport::INCOMPLETE_ZERO,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.session_mut().set_session_cost_report_for_test(report);
        app.session_mut().set_session_budget_usd(Some(5.0));
        let model = cost_model(&app);
        let row = &model.budget_rows[0];
        assert!(row.fill.is_none());
        assert_eq!(row.cells[3], "unknown");
        assert_ne!(row.cells[1], "$0.00");
        assert!(!row.cells[1].contains("$0.00"));
        assert_eq!(model.budget_status.unwrap().cells[1], "unknown");
    }
}

#[test]
fn estimated_budget_shares_keep_the_estimate_qualifier() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let estimate = RuntimeCost::from_usd(0.5, "fixture").unwrap();
    app.session_mut().set_session_cost_report_for_test(
        RuntimeCostReport::INCOMPLETE_ZERO.with_unmetered_estimate(Some(estimate)),
    );
    app.session_mut().set_session_budget_usd(Some(1.0));
    let model = cost_model(&app);
    assert_eq!(model.budget_rows[0].cells[1], "~$0.50 (estimated)");
    assert_eq!(model.budget_rows[0].cells[3], "~50%");
    assert_eq!(model.budget_status.unwrap().cells[1], "~50%");
}

#[test]
fn accounting_errors_do_not_draw_a_percentage_or_zero_bar() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(2.0));
    app.session_mut()
        .mark_cost_accounting_error("unreadable receipt");
    let model = cost_model(&app);
    assert!(model.budget_rows[0].fill.is_none());
    assert_eq!(model.budget_rows[0].cells[1], "cost accounting error");
    assert_eq!(model.budget_rows[0].cells[3], "unknown");
}

#[test]
fn known_zero_stays_an_exact_zero_and_the_cost_log_uses_qualified_text() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    let model = cost_model(&app);
    assert_eq!(model.budget_rows[0].fill, Some(0));
    assert_eq!(model.budget_rows[0].cells[1], "$0.00");
    app.record_cost_report(RuntimeCostReport::INCOMPLETE_ZERO);
    app.show_cost_status();
    assert_eq!(app.shell_view(), crate::ShellView::Cost);
    assert!(cost_model(&app).auth_spend_cells[0].contains("metering incomplete"));
}

#[test]
fn cost_model_does_not_invent_a_budget_when_unset() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = cost_model(&app);

    assert!(model.budget_rows.is_empty());
    assert!(model
        .spend_rows
        .iter()
        .any(|row| { row.cells == ["observed stop".to_string(), "not enforced".to_string(),] }));
    assert_eq!(model.auth_spend_cells[1], "\u{2014}");
    assert!(model.budget_status.is_none());
}

#[test]
fn cost_model_reports_last_tool_and_budget_status() {
    let mut config = V2Config::default();
    config.operator.spend_hard_ceiling_usd = Some(25.0);
    let mut app = ShellApp::new(config, None);
    app.session_mut().set_session_cost_usd_for_test(1.42);
    app.session_mut()
        .set_last_tool_cost_usd_for_test(Some(0.18));
    app.session_mut().set_session_budget_usd(Some(5.0));

    let model = cost_model(&app);

    assert_eq!(model.budget_rows.len(), 2);
    assert_eq!(model.budget_rows[0].cells[3], " 28%");
    assert_eq!(model.budget_rows[1].cells[3], "  4%");
    assert_eq!(
        model.auth_spend_cells,
        ["$1.42".to_string(), "$0.1800".to_string()]
    );
    assert!(model
        .spend_rows
        .iter()
        .any(|row| row.cells == ["observed stop".to_string(), "$5.00".to_string()]));
    assert!(model
        .spend_rows
        .iter()
        .any(|row| { row.cells == ["max stop setting".to_string(), "$25.00".to_string()] }));
    assert_eq!(
        model.budget_status,
        Some(CostBudgetStatus {
            tone: CostTone::Success,
            cells: ["$5.00".to_string(), "28%".to_string()],
        })
    );
}
