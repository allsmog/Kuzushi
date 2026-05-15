use super::*;
use crate::ui_view_models::{
    auth_provider_rows, config_model, cost_model, ConfigModel, CostBudgetStatus, CostModel,
};

pub(crate) fn auth_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let config = config_model(app);
    let cost = cost_model(app);
    lines.push(blank());
    push_auth_provider_section(&mut lines, app, area);
    push_auth_model_section(&mut lines, &config, area);
    push_auth_spend_section(&mut lines, &cost, area);
    push_auth_commands(&mut lines, area);
    lines
}

fn push_auth_provider_section(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    lines.push(divider("PROVIDERS", area.width));
    let providers = auth_provider_rows(app);
    for row in &providers {
        lines.push(auth_provider_line(row));
    }
    lines.push(blank());
}

fn push_auth_model_section(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(divider("MODEL · effective", area.width));
    lines.push(auth_current_model_line(&model.model, &model.backend));
    if let Some(reasoning) = model.reasoning_override.as_deref() {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled("reasoning ", theme::muted()),
            Span::styled(reasoning.to_string(), theme::primary()),
        ]));
    }
    lines.push(blank());
}

fn auth_current_model_line(model: &str, backend: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled("current  ", theme::muted()),
        Span::styled(model.to_string(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("backend ", theme::muted()),
        Span::styled(backend.to_string(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("routing ", theme::muted()),
        Span::styled("direct", theme::primary()),
    ])
}

fn push_auth_spend_section(lines: &mut Vec<Line<'static>>, model: &CostModel, area: Rect) {
    lines.push(divider("SPEND · this session", area.width));
    lines.push(auth_spend_line(
        model.session_text.clone(),
        model.last_tool_text.clone(),
    ));
    if let Some(budget) = &model.budget_status {
        lines.push(auth_budget_line(budget));
    }
    lines.push(blank());
}

fn auth_spend_line(session_cost: String, last_tool: String) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled("session   ", theme::muted()),
        Span::styled(session_cost, theme::primary()),
        Span::styled("   · ", theme::subtle()),
        Span::styled("last tool ", theme::muted()),
        Span::styled(last_tool, theme::primary()),
    ])
}

fn auth_budget_line(budget: &CostBudgetStatus) -> Line<'static> {
    let pct_style = if budget.percent >= 85 {
        theme::warn()
    } else {
        theme::muted()
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled("budget    ", theme::muted()),
        Span::styled(budget.budget_text.clone(), theme::primary()),
        Span::styled("   · ", theme::subtle()),
        Span::styled(format!("{}%", budget.percent), pct_style),
    ])
}

fn push_auth_commands(lines: &mut Vec<Line<'static>>, area: Rect) {
    lines.push(command_list_line(
        &[
            "auth login openai",
            "auth login anthropic",
            "model <provider:id>",
            "config",
            "back",
        ],
        area.width as usize,
    ));
}
