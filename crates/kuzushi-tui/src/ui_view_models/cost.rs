use super::format_session_cost;
use crate::ShellApp;

const DEFAULT_SESSION_BUDGET_USD: f64 = 5.0;
const COST_BAR_WIDTH: usize = 30;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CostModel {
    pub(crate) budget_rows: Vec<CostBudgetRow>,
    pub(crate) spend_rows: Vec<CostSpendRow>,
    pub(crate) auth_spend_cells: [String; 2],
    pub(crate) budget_status: Option<CostBudgetStatus>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CostBudgetRow {
    pub(crate) tone: CostTone,
    pub(crate) fill: usize,
    pub(crate) empty: usize,
    pub(crate) cells: [String; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CostBudgetStatus {
    pub(crate) tone: CostTone,
    pub(crate) cells: [String; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CostSpendRow {
    pub(crate) cells: [String; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CostTone {
    Success,
    Warn,
    Danger,
}

pub(crate) fn cost_model(app: &ShellApp) -> CostModel {
    let cap = app.session_budget_usd.unwrap_or(DEFAULT_SESSION_BUDGET_USD);
    let session_text = format_session_cost(app.session_cost_usd);
    let last_tool_text = last_tool_text(app.last_tool_cost_usd);
    let budget_text = budget_text(app.session_budget_usd);
    CostModel {
        budget_rows: cost_budget_rows(app.session_cost_usd, app.last_tool_cost_usd, cap),
        spend_rows: cost_spend_rows(
            session_text.clone(),
            last_tool_text.clone(),
            budget_text.clone(),
        ),
        auth_spend_cells: [session_text, last_tool_text],
        budget_status: budget_status(app.session_cost_usd, app.session_budget_usd),
    }
}

fn cost_spend_rows(session: String, last_tool: String, budget: String) -> Vec<CostSpendRow> {
    vec![
        cost_spend_row("session", session),
        cost_spend_row("last tool", last_tool),
        cost_spend_row("budget", budget),
    ]
}

fn cost_spend_row(label: &str, value: String) -> CostSpendRow {
    CostSpendRow {
        cells: [label.to_string(), value],
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
    let percent = capped_percent(used, cap);
    let fill = bar_fill(percent);
    CostBudgetRow {
        tone: cost_tone(percent),
        fill,
        empty: COST_BAR_WIDTH.saturating_sub(fill),
        cells: [
            label.to_string(),
            format!("${used:>6.2}"),
            format!("${cap:>6.2}"),
            format!("{percent:>3}%"),
        ],
    }
}

fn bar_fill(percent: usize) -> usize {
    ((COST_BAR_WIDTH as f64 * percent as f64 / 100.0).round() as usize).min(COST_BAR_WIDTH)
}

fn cost_tone(percent: usize) -> CostTone {
    if percent >= 100 {
        CostTone::Danger
    } else if percent >= 85 {
        CostTone::Warn
    } else {
        CostTone::Success
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
        .unwrap_or_else(|| "unset (default $5.00 soft cap shown above)".to_string())
}

fn budget_status(session_cost: f64, budget: Option<f64>) -> Option<CostBudgetStatus> {
    let budget = budget?;
    let percent = uncapped_percent(session_cost, budget);
    Some(CostBudgetStatus {
        tone: cost_tone(percent),
        cells: [format!("${budget:.2}"), format!("{percent}%")],
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
