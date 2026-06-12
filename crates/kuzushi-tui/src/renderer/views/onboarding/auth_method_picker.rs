use super::*;

pub(crate) fn auth_method_picker_lines(
    app: &ShellApp,
    area: Rect,
    provider: &str,
) -> Vec<Line<'static>> {
    let rows = auth_method_rows(provider);
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(divider("CHOOSE AUTH METHOD", area.width));
    lines.push(blank());
    lines.push(muted(&format!(
        "Provider {provider} supports multiple auth methods. Pick one to continue.",
    )));
    lines.push(blank());
    for (idx, row) in rows.iter().enumerate() {
        lines.push(auth_row_line(app, idx, row, area.width));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "move"),
        ("Enter", "confirm"),
        ("Esc/q", "defer"),
    ]));
    lines
}

pub(crate) fn auth_method_rows(provider: &str) -> Vec<AuthMethodRow> {
    match provider {
        "anthropic" => vec![
            AuthMethodRow {
                label: "API key (ANTHROPIC_API_KEY)",
                hint: "set ANTHROPIC_API_KEY in your shell, then Enter",
            },
            AuthMethodRow {
                label: "Claude.ai OAuth login",
                hint: "opens a browser flow (or headless link in non-TTY)",
            },
        ],
        "openai" | "openai-codex" => vec![
            AuthMethodRow {
                label: "API key (OPENAI_API_KEY)",
                hint: "set OPENAI_API_KEY in your shell, then Enter",
            },
            AuthMethodRow {
                label: "OpenAI OAuth login",
                hint: "opens a browser flow (or headless link in non-TTY)",
            },
        ],
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthMethodRow {
    pub label: &'static str,
    pub hint: &'static str,
}

fn auth_row_line(app: &ShellApp, idx: usize, row: &AuthMethodRow, width: u16) -> Line<'static> {
    let marker = if idx == app.auth_picker_cursor {
        ">"
    } else {
        " "
    };
    let body = format!(
        "  {marker} {label}   ·   {hint}",
        label = row.label,
        hint = row.hint
    );
    let style = if idx == app.auth_picker_cursor {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(fit(&body, width as usize), style)
}
