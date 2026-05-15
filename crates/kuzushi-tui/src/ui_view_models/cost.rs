use super::format_session_cost;
use crate::ShellApp;

const DEFAULT_SESSION_BUDGET_USD: f64 = 5.0;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CostModel {
    pub(crate) budget_rows: Vec<CostBudgetRow>,
    pub(crate) session_text: String,
    pub(crate) last_tool_text: String,
    pub(crate) budget_text: String,
    pub(crate) budget_status: Option<CostBudgetStatus>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CostBudgetRow {
    pub(crate) label: &'static str,
    pub(crate) used: f64,
    pub(crate) cap: f64,
    pub(crate) percent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CostBudgetStatus {
    pub(crate) budget_text: String,
    pub(crate) percent: usize,
}

pub(crate) fn cost_model(app: &ShellApp) -> CostModel {
    let cap = app.session_budget_usd.unwrap_or(DEFAULT_SESSION_BUDGET_USD);
    CostModel {
        budget_rows: cost_budget_rows(app.session_cost_usd, app.last_tool_cost_usd, cap),
        session_text: format_session_cost(app.session_cost_usd),
        last_tool_text: last_tool_text(app.last_tool_cost_usd),
        budget_text: budget_text(app.session_budget_usd),
        budget_status: budget_status(app.session_cost_usd, app.session_budget_usd),
    }
}

fn cost_budget_rows(session: f64, last_tool: Option<f64>, cap: f64) -> Vec<CostBudgetRow> {
    let mut rows = vec![cost_budget_row("this session    ", session, cap)];
    if let Some(last) = last_tool {
        rows.push(cost_budget_row("last tool       ", last, cap));
    }
    rows
}

fn cost_budget_row(label: &'static str, used: f64, cap: f64) -> CostBudgetRow {
    CostBudgetRow {
        label,
        used,
        cap,
        percent: capped_percent(used, cap),
    }
}

fn capped_percent(used: f64, cap: f64) -> usize {
    if cap > 0.0 {
        ((used / cap).clamp(0.0, 1.0) * 100.0).round() as usize
    } else {
        0
    }
}

fn last_tool_text(last_tool: Option<f64>) -> String {
    last_tool
        .map(|cost| format!("${cost:.4}"))
        .unwrap_or_else(|| "\u{2014}".to_string())
}

fn budget_text(budget: Option<f64>) -> String {
    budget
        .map(|value| format!("${value:.2}"))
        .unwrap_or_else(|| "unset".to_string())
}

fn budget_status(session_cost: f64, budget: Option<f64>) -> Option<CostBudgetStatus> {
    let budget = budget?;
    Some(CostBudgetStatus {
        budget_text: format!("${budget:.2}"),
        percent: uncapped_percent(session_cost, budget),
    })
}

fn uncapped_percent(used: f64, cap: f64) -> usize {
    if cap > 0.0 {
        (used / cap * 100.0).round() as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests;
