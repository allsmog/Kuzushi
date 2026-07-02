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
    if app.auth_picker_cursor == 0 {
        lines.extend(api_key_draft_lines(app, provider, area.width));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "move"),
        (":", "type a command"),
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
                hint: "paste key here, Enter accepts for this session",
            },
            AuthMethodRow {
                label: "Claude.ai OAuth login",
                hint: "opens a browser flow (or headless link in non-TTY)",
            },
        ],
        "openai" | "openai-codex" => vec![
            AuthMethodRow {
                label: "API key (OPENAI_API_KEY)",
                hint: "paste key here, Enter accepts for this session",
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

fn api_key_draft_lines(app: &ShellApp, provider: &str, width: u16) -> Vec<Line<'static>> {
    let env_var = match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        _ => "OPENAI_API_KEY",
    };
    let draft_chars = app.auth_key_draft.chars().count();
    let draft = if draft_chars == 0 {
        "no key pasted yet".to_string()
    } else {
        format!("{draft_chars} chars entered · value hidden")
    };
    vec![
        blank(),
        muted(&fit(
            &format!("Paste {env_var}; Enter stores it for this session only. {draft}."),
            width as usize,
        )),
        muted(&fit(
            "Backspace edits · Delete clears · OAuth row avoids API keys entirely.",
            width as usize,
        )),
    ]
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
