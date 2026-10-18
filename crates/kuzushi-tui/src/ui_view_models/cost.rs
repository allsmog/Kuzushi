use super::{format_runtime_cost, format_session_cost};
use crate::ShellApp;
use kuzushi_core::runtime::RuntimeCostReport;

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
    pub(crate) fill: Option<usize>,
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
    let session = app.session();
    let budget = session.session_budget_usd();
    let (session_text, last_tool_text) = cost_texts(app);
    let budget_text = budget_text(session.session_budget_usd());
    let hard_ceiling_text = hard_ceiling_text(app.config().operator.spend_hard_ceiling_usd);
    CostModel {
        budget_rows: budget.map_or_else(Vec::new, |cap| {
            cost_budget_rows(
                session.session_cost_report(),
                session.last_tool_cost_report(),
                cap,
                session.cost_accounting_error(),
            )
        }),
        spend_rows: cost_spend_rows(
            session_text.clone(),
            last_tool_text.clone(),
            budget_text.clone(),
            hard_ceiling_text,
        ),
        auth_spend_cells: [session_text, last_tool_text],
        budget_status: budget_status(
            session.session_cost_report(),
            budget,
            session.cost_accounting_error(),
        ),
    }
}

fn cost_texts(app: &ShellApp) -> (String, String) {
    let session = app.session();
    let accounting_error = session.cost_accounting_error();
    let session_text = if session.cost_accounting_is_complete() {
        format_session_cost(session.session_cost_usd())
    } else {
        format_runtime_cost(session.session_cost_report(), accounting_error)
    };
    let last_tool_text = session
        .last_tool_cost_report()
        .map(|report| format_last_tool_cost(report, accounting_error))
        .unwrap_or_else(|| "\u{2014}".to_string());
    (session_text, last_tool_text)
}

fn format_last_tool_cost(
    report: kuzushi_core::runtime::RuntimeCostReport,
    accounting_error: Option<&str>,
) -> String {
    if report.is_complete() && accounting_error.is_none() {
        format!("${:.4}", report.observed_usd())
    } else {
        format_runtime_cost(report, accounting_error)
    }
}

fn cost_spend_rows(
    session: String,
    last_tool: String,
    budget: String,
    hard_ceiling: String,
) -> Vec<CostSpendRow> {
    vec![
        cost_spend_row("session", session),
        cost_spend_row("last tool", last_tool),
        cost_spend_row("observed stop", budget),
        cost_spend_row("max stop setting", hard_ceiling),
    ]
}

fn cost_spend_row(label: &str, value: String) -> CostSpendRow {
    CostSpendRow {
        cells: [label.to_string(), value],
    }
}

fn cost_budget_rows(
    session: RuntimeCostReport,
    last_tool: Option<RuntimeCostReport>,
    cap: f64,
    accounting_error: Option<&str>,
) -> Vec<CostBudgetRow> {
    let mut rows = vec![cost_budget_row(
        "this session",
        session,
        cap,
        accounting_error,
    )];
    if let Some(last) = last_tool {
        rows.push(cost_budget_row("last tool", last, cap, accounting_error));
    }
    rows
}

fn cost_budget_row(
    label: &str,
    report: RuntimeCostReport,
    cap: f64,
    accounting_error: Option<&str>,
) -> CostBudgetRow {
    let percent = reliable_estimate(report, accounting_error).map(|used| capped_percent(used, cap));
    let fill = percent.map(bar_fill);
    CostBudgetRow {
        tone: percent.map_or(CostTone::Danger, cost_tone),
        fill,
        empty: fill.map_or(0, |fill| COST_BAR_WIDTH.saturating_sub(fill)),
        cells: [
            label.to_string(),
            format_runtime_cost(report, accounting_error),
            format!("${cap:.2}"),
            percentage_label(percent, report.is_estimated()),
        ],
    }
}

fn reliable_estimate(report: RuntimeCostReport, accounting_error: Option<&str>) -> Option<f64> {
    accounting_error
        .is_none()
        .then(|| report.estimated_total_usd())
        .flatten()
}

fn percentage_label(percent: Option<usize>, estimated: bool) -> String {
    match (percent, estimated) {
        (Some(percent), true) => format!("~{percent}%"),
        (Some(percent), false) => format!("{percent:>3}%"),
        (None, _) => "unknown".to_string(),
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

fn budget_text(budget: Option<f64>) -> String {
    budget
        .map(|value| format!("${value:.2}"))
        .unwrap_or_else(|| "not enforced".to_string())
}

fn hard_ceiling_text(ceiling: Option<f64>) -> String {
    ceiling
        .map(|value| format!("${value:.2}"))
        .unwrap_or_else(|| "not configured".to_string())
}

fn budget_status(
    report: RuntimeCostReport,
    budget: Option<f64>,
    accounting_error: Option<&str>,
) -> Option<CostBudgetStatus> {
    let budget = budget?;
    let percent =
        reliable_estimate(report, accounting_error).map(|used| uncapped_percent(used, budget));
    Some(CostBudgetStatus {
        tone: percent.map_or(CostTone::Danger, cost_tone),
        cells: [
            format!("${budget:.2}"),
            percentage_label(percent, report.is_estimated())
                .trim()
                .to_string(),
        ],
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
