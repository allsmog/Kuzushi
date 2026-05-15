use super::*;
use kuzushi_core::V2Config;

#[test]
fn cost_model_uses_default_budget_when_unset() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = cost_model(&app);

    assert_eq!(model.budget_rows.len(), 1);
    assert_eq!(model.budget_rows[0].label, "this session    ");
    assert_eq!(model.budget_rows[0].cap, 5.0);
    assert_eq!(model.budget_rows[0].percent, 0);
    assert_eq!(model.budget_text, "unset");
    assert_eq!(model.last_tool_text, "\u{2014}");
    assert!(model.budget_status.is_none());
}

#[test]
fn cost_model_reports_last_tool_and_budget_status() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_cost_usd = 1.42;
    app.last_tool_cost_usd = Some(0.18);
    app.session_budget_usd = Some(5.0);

    let model = cost_model(&app);

    assert_eq!(model.budget_rows.len(), 2);
    assert_eq!(model.budget_rows[0].percent, 28);
    assert_eq!(model.budget_rows[1].percent, 4);
    assert_eq!(model.session_text, "$1.42");
    assert_eq!(model.last_tool_text, "$0.1800");
    assert_eq!(model.budget_text, "$5.00");
    assert_eq!(
        model.budget_status,
        Some(CostBudgetStatus {
            budget_text: "$5.00".to_string(),
            percent: 28,
        })
    );
}
