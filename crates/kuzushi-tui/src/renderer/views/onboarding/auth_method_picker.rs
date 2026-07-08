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
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(divider("CHOOSE AUTH METHOD", area.width));
    lines.push(blank());
    lines.push(muted(&format!(
        "Provider {provider} needs credentials. Paste a key, sign in, or try the demo.",
    )));
    lines.push(blank());
    for (idx, row) in rows.iter().enumerate() {
        // Promote the keyless escape hatch: set the demo row apart with a
        // blank line + a "No key yet?" lead so it reads as a distinct offer,
        // not a third undifferentiated auth method.
        if row.kind == AuthMethodRowKind::OfflineDemo {
            lines.push(blank());
            lines.push(muted("No key yet? Try the offline demo (no key/model/binary):"));
        }
        lines.push(auth_row_line(app, idx, row, area.width));
    }
    if app.router.auth_picker().is_api_key_row() {
        lines.extend(api_key_draft_lines(app, provider, area.width));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "move"),
        ("d", "offline fixture"),
        (":", "type a command"),
        ("Enter", "confirm"),
        ("Esc/q", "defer"),
    ]));
    lines
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
    let marker = if idx == app.router.auth_picker().cursor() {
        ">"
    } else {
        " "
    };
    let body = format!(
        "  {marker} {label}   ·   {hint}",
        label = row.label,
        hint = row.hint
    );
    let style = if idx == app.router.auth_picker().cursor() {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(fit(&body, width as usize), style)
}
