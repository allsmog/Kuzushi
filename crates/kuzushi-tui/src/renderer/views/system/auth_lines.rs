use super::*;

pub(crate) fn auth_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    // PROVIDERS section --------------------------------------------------
    lines.push(divider("PROVIDERS", area.width));
    let providers = auth_provider_rows(app);
    for row in &providers {
        lines.push(auth_provider_line(row));
    }
    lines.push(blank());

    // MODEL · effective section -----------------------------------------
    lines.push(divider("MODEL · effective", area.width));
    let model = app.config.model.as_deref().unwrap_or("unconfigured");
    let backend = crate::app::runtime_backend_label(&app.config);
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("current  ", theme::muted()),
        Span::styled(model.to_string(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("backend ", theme::muted()),
        Span::styled(backend.to_string(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("routing ", theme::muted()),
        Span::styled("direct", theme::primary()),
    ]));
    if let Some(reasoning) = app.session_thinking_level.as_deref() {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled("reasoning ", theme::muted()),
            Span::styled(reasoning.to_string(), theme::primary()),
        ]));
    }
    lines.push(blank());

    // SPEND section ------------------------------------------------------
    lines.push(divider("SPEND · this session", area.width));
    let session_cost = format_session_cost(app.session_cost_usd);
    let last_tool = app
        .last_tool_cost_usd
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "—".to_string());
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("session   ", theme::muted()),
        Span::styled(session_cost, theme::primary()),
        Span::styled("   · ", theme::subtle()),
        Span::styled("last tool ", theme::muted()),
        Span::styled(last_tool, theme::primary()),
    ]));
    if let Some(budget) = app.session_budget_usd {
        let pct = if budget > 0.0 {
            (app.session_cost_usd / budget * 100.0).round() as usize
        } else {
            0
        };
        let pct_style = if pct >= 85 {
            theme::warn()
        } else {
            theme::muted()
        };
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled("budget    ", theme::muted()),
            Span::styled(format!("${budget:.2}"), theme::primary()),
            Span::styled("   · ", theme::subtle()),
            Span::styled(format!("{pct}%"), pct_style),
        ]));
    }
    lines.push(blank());

    // CTA row
    lines.push(command_list_line(
        &[
            "auth login openai-codex",
            "auth login anthropic",
            "model <provider:id>",
            "config",
            "back",
        ],
        area.width as usize,
    ));
    lines
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
