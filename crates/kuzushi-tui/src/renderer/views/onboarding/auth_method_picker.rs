use super::*;
use crate::app::{auth_method_rows, AuthMethodRow, AuthMethodRowKind};

pub(crate) fn auth_method_picker_lines(
    app: &ShellApp,
    area: Rect,
    provider: &str,
) -> Vec<Line<'static>> {
    if let Some(snapshot) = app.auth_screen_snapshot() {
        return auth_snapshot_lines(snapshot.clone(), area.width as usize);
    }

    let rows = auth_method_rows(provider);
    let mut lines = auth_picker_intro(provider, area.width);
    lines.extend(auth_picker_rows(app, &rows, area.width));
    if app.router.auth_picker().is_api_key_row() {
        lines.extend(api_key_draft_lines(app, provider, area.width));
    }
    lines.extend(auth_picker_footer(area.width));
    lines
}

fn auth_picker_intro(provider: &str, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![divider("CHOOSE AUTH METHOD", width), blank()];
    lines.extend(
        wrap_text(
            &format!(
                "Provider {provider} needs credentials. Paste a key, sign in, or try the demo."
            ),
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines.push(blank());
    lines
}

fn auth_picker_rows(app: &ShellApp, rows: &[AuthMethodRow], width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if row.kind == AuthMethodRowKind::OfflineDemo {
            lines.extend(offline_demo_lead(width));
        }
        lines.push(auth_row_line(app, index, row, width));
    }
    lines
}

fn offline_demo_lead(width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![blank()];
    lines.extend(
        wrap_text(
            "No key yet? Try the offline demo (no key/model/binary):",
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines
}

fn auth_picker_footer(width: u16) -> Vec<Line<'static>> {
    vec![
        blank(),
        responsive_keybind_hint_line(
            width as usize,
            &[
                ("↑/↓/j/k", "move"),
                ("d", "offline fixture"),
                (":", "type a command"),
                ("Enter", "confirm"),
                ("Esc/q", "defer"),
            ],
            &[
                ("↑/↓", "move"),
                ("Enter", "select"),
                ("d", "demo"),
                ("Esc", "defer"),
            ],
        ),
    ]
}

fn api_key_draft_lines(app: &ShellApp, provider: &str, width: u16) -> Vec<Line<'static>> {
    let env_var = match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        _ => "OPENAI_API_KEY",
    };
    let draft_chars = app.router.auth_picker().key_draft().chars().count();
    let draft = if draft_chars == 0 {
        "no key pasted yet".to_string()
    } else {
        format!("{draft_chars} chars entered · value hidden")
    };
    let mut lines = vec![blank()];
    lines.extend(
        wrap_text(
            &format!("Paste {env_var}; Enter stores it for this session only. {draft}."),
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines.extend(
        wrap_text(
            "Backspace edits · Delete clears · OAuth row avoids API keys entirely.",
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines
}

fn auth_row_line(app: &ShellApp, idx: usize, row: &AuthMethodRow, width: u16) -> Line<'static> {
    let body = format!("{label}   ·   {hint}", label = row.label, hint = row.hint);
    selection_band(
        &body,
        idx == app.router.auth_picker().cursor(),
        width as usize,
    )
}
