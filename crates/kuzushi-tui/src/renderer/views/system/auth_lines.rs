use super::*;

pub(crate) fn auth_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    push_auth_provider_section(&mut lines, app, area);
    push_auth_model_section(&mut lines, app, area);
    push_auth_spend_section(&mut lines, app, area);
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

fn push_auth_model_section(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    lines.push(divider("MODEL · effective", area.width));
    let model = app
        .config
        .model
        .as_deref()
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string());
    let backend = crate::app::runtime_backend_label(&app.config);
    lines.push(auth_current_model_line(&model, backend));
    if let Some(reasoning) = app.session_thinking_level.as_deref() {
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

fn push_auth_spend_section(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    lines.push(divider("SPEND · this session", area.width));
    let session_cost = format_session_cost(app.session_cost_usd);
    let last_tool = app
        .last_tool_cost_usd
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "—".to_string());
    lines.push(auth_spend_line(session_cost, last_tool));
    if let Some(budget) = app.session_budget_usd {
        lines.push(auth_budget_line(app.session_cost_usd, budget));
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

fn auth_budget_line(session_cost_usd: f64, budget: f64) -> Line<'static> {
    let pct = if budget > 0.0 {
        (session_cost_usd / budget * 100.0).round() as usize
    } else {
        0
    };
    let pct_style = if pct >= 85 {
        theme::warn()
    } else {
        theme::muted()
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled("budget    ", theme::muted()),
        Span::styled(format!("${budget:.2}"), theme::primary()),
        Span::styled("   · ", theme::subtle()),
        Span::styled(format!("{pct}%"), pct_style),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthProviderState {
    Connected,
    Missing,
    Inactive,
}

pub(crate) struct AuthProviderRow {
    pub(in crate::renderer::views) name: &'static str,
    pub(in crate::renderer::views) state: AuthProviderState,
    pub(in crate::renderer::views) detail: String,
}
