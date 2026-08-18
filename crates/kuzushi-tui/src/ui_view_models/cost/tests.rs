use super::*;
use kuzushi_core::V2Config;

#[test]
fn cost_model_does_not_invent_a_budget_when_unset() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = cost_model(&app);

    assert!(model.budget_rows.is_empty());
    assert!(model
        .spend_rows
        .iter()
        .any(|row| { row.cells == ["budget".to_string(), "not enforced".to_string(),] }));
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
        .any(|row| row.cells == ["budget".to_string(), "$5.00".to_string()]));
    assert!(model
        .spend_rows
        .iter()
        .any(|row| { row.cells == ["hard ceiling".to_string(), "$25.00".to_string()] }));
    assert_eq!(
        model.budget_status,
        Some(CostBudgetStatus {
            tone: CostTone::Success,
            cells: ["$5.00".to_string(), "28%".to_string()],
        })
    );
}
