use super::*;
use crate::ui_view_models::{
    auth_login_model, auth_provider_rows, config_model, cost_model, AuthLoginModel, ConfigModel,
    CostBudgetStatus, CostModel, CostTone,
};

pub(crate) fn auth_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let config = config_model(app);
    let cost = cost_model(app);
    lines.push(blank());
    push_auth_provider_section(&mut lines, app, area);
    push_auth_login_section(&mut lines, auth_login_model(app).as_ref(), area);
    push_auth_model_section(&mut lines, &config, area);
    push_auth_spend_section(&mut lines, &cost, area);
    push_auth_rotate_section(&mut lines, area);
    push_auth_commands(&mut lines, area);
    lines
}

fn push_auth_login_section(
    lines: &mut Vec<Line<'static>>,
    model: Option<&AuthLoginModel>,
    area: Rect,
) {
    let Some(login) = model else {
        return;
    };
    lines.push(divider("OAUTH · latest flow", area.width));
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("provider  ", theme::muted()),
        Span::styled(login.provider.clone(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("method ", theme::muted()),
        Span::styled(login.method.clone(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("status ", theme::muted()),
        Span::styled(login.status.clone(), auth_login_status_style(&login.status)),
    ]));
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("flow      ", theme::muted()),
        Span::styled(login.flow.clone(), theme::primary()),
    ]));
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("store     ", theme::muted()),
        Span::styled(login.store_path.clone(), theme::primary()),
        Span::styled(" · values hidden", theme::muted()),
    ]));
    lines.push(blank());
}

fn auth_login_status_style(status: &str) -> ratatui::style::Style {
    match status {
        "connected" => theme::success(),
        "failed" => theme::danger(),
        "waiting" | "starting" => theme::warn(),
        _ => theme::muted(),
    }
}

fn push_auth_rotate_section(lines: &mut Vec<Line<'static>>, area: Rect) {
    // M3 §3.4: rotate/clear hints. Operators rotating keys mid-session
    // need to know which env var to update and how to re-auth without
    // restarting the shell. Surfaced inline so the path stays
    // self-documenting.
    lines.push(divider("ROTATE · clear & re-auth", area.width));
    for hint in [
        "unset env: `unset ANTHROPIC_API_KEY` (host shell) then re-launch kuzushi",
        "clear oauth: `auth login anthropic` or `auth login openai` to refresh",
        "switch model: `model <provider:id>` (e.g. `model anthropic:claude-opus-4-7`)",
    ] {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled("• ", theme::muted()),
            Span::styled(
                fit(hint, area.width.saturating_sub(3) as usize),
                theme::primary(),
            ),
        ]));
    }
    lines.push(blank());
}
fn push_auth_provider_section(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    let providers = auth_provider_rows(app);
    let (backend_rows, provider_rows): (Vec<_>, Vec<_>) = providers
        .iter()
        .partition(|row| row.cells[0] == "LangGraph");
    if !backend_rows.is_empty() {
        lines.push(divider("BACKEND", area.width));
        for row in &backend_rows {
            lines.push(auth_provider_line(row));
        }
        lines.push(blank());
    }
    lines.push(divider("PROVIDERS", area.width));
    for row in &provider_rows {
        lines.push(auth_provider_line(row));
    }
    lines.push(blank());
}

fn push_auth_model_section(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(divider("MODEL · effective", area.width));
    lines.push(auth_current_model_line(&model.model, &model.backend));
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("reasoning ", theme::muted()),
        Span::styled(model.reasoning.clone(), theme::primary()),
    ]));
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
        model.auth_spend_cells[0].clone(),
        model.auth_spend_cells[1].clone(),
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
    let pct_style = auth_budget_tone_style(budget.tone);
    Line::from(vec![
        Span::raw(" "),
        Span::styled("budget    ", theme::muted()),
        Span::styled(budget.cells[0].clone(), theme::primary()),
        Span::styled("   · ", theme::subtle()),
        Span::styled(budget.cells[1].clone(), pct_style),
    ])
}

fn auth_budget_tone_style(tone: CostTone) -> ratatui::style::Style {
    match tone {
        CostTone::Success => theme::muted(),
        CostTone::Warn | CostTone::Danger => theme::warn(),
    }
}

fn push_auth_commands(lines: &mut Vec<Line<'static>>, area: Rect) {
    lines.push(command_list_line(
        &[
            "auth login openai browser",
            "auth login openai headless",
            "auth login anthropic",
            "auth login github-copilot",
            "model <provider:id>",
            "config",
            "back",
        ],
        area.width as usize,
    ));
}
