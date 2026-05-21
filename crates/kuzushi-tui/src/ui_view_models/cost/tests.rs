use super::*;
use kuzushi_core::V2Config;

#[test]
fn cost_model_uses_default_budget_when_unset() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = cost_model(&app);

    assert_eq!(model.budget_rows.len(), 1);
    assert_eq!(model.budget_rows[0].cells[0], "this session    ");
    assert_eq!(model.budget_rows[0].cells[2], "$  5.00");
    assert_eq!(model.budget_rows[0].cells[3], "  0%");
    assert_eq!(model.budget_rows[0].tone, CostTone::Success);
    assert!(model.spend_rows.iter().any(|row| {
        row.cells
            == [
                "budget".to_string(),
                "unset (default $5.00 soft cap shown above)".to_string(),
            ]
    }));
    assert_eq!(model.auth_spend_cells[1], "\u{2014}");
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
    assert_eq!(
        model.budget_status,
        Some(CostBudgetStatus {
            tone: CostTone::Success,
            cells: ["$5.00".to_string(), "28%".to_string()],
        })
    );
}
