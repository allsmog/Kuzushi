use super::*;
use crate::app::{
    auth_method_rows, auth_provider_label, credential_recovery_rows, AuthMethodRow,
    AuthMethodRowKind,
};

type HintBinding = (&'static str, &'static str);

const API_KEY_WIDE_HINTS: &[HintBinding] = &[
    ("↑/↓", "move"),
    ("type", "API key"),
    ("Enter", "accept key"),
    ("Esc", "back"),
];
const API_KEY_NARROW_HINTS: &[HintBinding] =
    &[("↑/↓", "move"), ("Enter", "accept"), ("Esc", "back")];
const AUTH_METHOD_WIDE_HINTS: &[HintBinding] = &[
    ("↑/↓", "move"),
    ("type", "a command"),
    ("Enter", "confirm"),
    ("Esc", "back"),
];
const AUTH_METHOD_NARROW_HINTS: &[HintBinding] =
    &[("↑/↓", "move"), ("Enter", "select"), ("Esc", "back")];

pub(crate) fn auth_method_picker_lines(
    app: &ShellApp,
    area: Rect,
    provider: &str,
) -> Vec<Line<'static>> {
    if let Some(snapshot) = app.auth_screen_snapshot() {
        return auth_snapshot_lines(snapshot.clone(), area.width as usize);
    }

    let rows = if app.router.auth_picker().is_recovery() {
        credential_recovery_rows(provider)
    } else {
        auth_method_rows(provider)
    };
    let lines = expanded_auth_picker_lines(app, area, provider, &rows);
    if lines.len() > area.height as usize {
        return compact_auth_picker_lines(app, area, provider, &rows);
    }
    lines
}

fn expanded_auth_picker_lines(
    app: &ShellApp,
    area: Rect,
    provider: &str,
    rows: &[AuthMethodRow],
) -> Vec<Line<'static>> {
    let mut lines = auth_picker_intro(app, provider, area.width);
    lines.extend(auth_picker_rows(app, rows, area.width));
    if app.router.auth_picker().is_api_key_row() {
        lines.extend(api_key_draft_lines(app, provider, area.width));
    }
    lines.extend(auth_picker_footer(app, area.width));
    lines
}

fn compact_auth_picker_lines(
    app: &ShellApp,
    area: Rect,
    provider: &str,
    rows: &[AuthMethodRow],
) -> Vec<Line<'static>> {
    let mut lines = compact_auth_intro(app, provider, area.width);
    let footer = compact_auth_footer(app);
    let fixed_rows = lines.len() + footer.len() + 1;
    let candidate_budget = (area.height as usize).saturating_sub(fixed_rows).max(1);
    let show_window_label = rows.len() > candidate_budget;
    let row_budget = candidate_budget
        .saturating_sub(usize::from(show_window_label))
        .max(1);
    let range = visible_auth_range(rows.len(), app.router.auth_picker().cursor(), row_budget);
    if show_window_label {
        lines.push(auth_window_label(
            range.start,
            range.end,
            rows.len(),
            area.width,
        ));
    }
    lines.extend(range.map(|index| auth_row_line(app, index, &rows[index], area.width)));
    lines.push(compact_auth_detail(app, provider, area.width));
    lines.extend(footer);
    lines
}

fn compact_auth_intro(app: &ShellApp, provider: &str, width: u16) -> Vec<Line<'static>> {
    let provider = auth_provider_label(provider);
    let mut lines = vec![divider("CHOOSE AUTH METHOD", width)];
    lines.extend(confirmed_target_line(app, width as usize));
    lines.push(muted(&fit(
        &format!("{provider}: paste a key, use OAuth, or run the offline demo"),
        width as usize,
    )));
    lines
}

fn compact_auth_footer(app: &ShellApp) -> Vec<Line<'static>> {
    if app.advisory().notice.is_some() {
        return picker_notice_footer_lines(false);
    }
    if app.picker_prompt_focused() {
        return picker_prompt_footer_lines(false);
    }
    if app.router.auth_picker().is_api_key_row() {
        return vec![
            muted(" type/paste key · ↑/↓ move · Enter accept"),
            muted(" Esc back · : command"),
        ];
    }
    vec![
        muted(" ↑/↓ move · type a command · Enter select"),
        muted(" Esc back · q Setup · : command"),
    ]
}

fn visible_auth_range(total: usize, cursor: usize, row_budget: usize) -> std::ops::Range<usize> {
    let visible = row_budget.min(total).max(1);
    let centered = cursor.saturating_sub(visible / 2);
    let start = centered.min(total.saturating_sub(visible));
    start..(start + visible).min(total)
}

fn auth_window_label(start: usize, end: usize, total: usize, width: u16) -> Line<'static> {
    muted(&fit(
        &format!(" methods {}-{} of {total} · ↑/↓ scroll", start + 1, end),
        width as usize,
    ))
}

fn compact_auth_detail(app: &ShellApp, provider: &str, width: u16) -> Line<'static> {
    let detail = match app.router.auth_picker().selected_kind() {
        Some(AuthMethodRowKind::ApiKey) => compact_api_key_detail(app, provider),
        Some(AuthMethodRowKind::OAuth) => "Enter starts the OAuth login flow".to_string(),
        Some(AuthMethodRowKind::OfflineDemo) => {
            "Enter runs the offline demo · no key, model, or binary".to_string()
        }
        None => "No authentication method selected".to_string(),
    };
    muted(&fit(&format!(" {detail}"), width as usize))
}

fn compact_api_key_detail(app: &ShellApp, provider: &str) -> String {
    let env_var = match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        _ => "OPENAI_API_KEY",
    };
    let count = app.router.auth_picker().key_draft().chars().count();
    if count == 0 {
        format!("Paste {env_var}; Enter stores it for this session")
    } else {
        format!("{count} key chars entered · hidden · Enter accepts")
    }
}

fn auth_picker_intro(app: &ShellApp, provider: &str, width: u16) -> Vec<Line<'static>> {
    let provider = auth_provider_label(provider);
    let mut lines = vec![divider("CHOOSE AUTH METHOD", width)];
    if let Some(target) = confirmed_target_line(app, width as usize) {
        lines.push(target);
    }
    lines.push(blank());
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

fn auth_picker_footer(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    if app.advisory().notice.is_some() {
        return picker_notice_footer_lines(true);
    }
    if app.picker_prompt_focused() {
        return picker_prompt_footer_lines(true);
    }
    let (wide, narrow) = auth_picker_footer_bindings(app);
    vec![
        blank(),
        responsive_keybind_hint_line(width as usize, wide, narrow),
    ]
}

fn auth_picker_footer_bindings(app: &ShellApp) -> (&'static [HintBinding], &'static [HintBinding]) {
    if app.router.auth_picker().is_api_key_row() {
        return (API_KEY_WIDE_HINTS, API_KEY_NARROW_HINTS);
    }
    (AUTH_METHOD_WIDE_HINTS, AUTH_METHOD_NARROW_HINTS)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn footer_text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn api_key_footer_uses_only_non_conflicting_controls() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("anthropic".to_string());
        let text = auth_picker_footer(&app, 120)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(text.contains("Esc back"), "{text}");
        assert!(text.contains("Enter accept key"), "{text}");
        assert!(!text.contains("j/k"), "{text}");
        assert!(!text.contains("d offline"), "{text}");
        assert!(!text.contains("q leave setup"), "{text}");
    }

    #[test]
    fn visible_notice_footer_advertises_dismissal_before_auth_navigation() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("anthropic".to_string());
        app.set_warn_notice("onboarding", "API key is empty");
        app.router
            .auth_picker_mut()
            .set_focus(crate::app::PickerFocus::Prompt);

        let text = footer_text(&compact_auth_footer(&app));

        assert!(text.contains("Esc dismiss notice"), "{text}");
        assert!(!text.contains("Esc return to picker"), "{text}");
        assert!(!text.contains("Esc back"), "{text}");
    }

    #[test]
    fn prompt_focused_auth_footer_advertises_first_escape_behavior() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("anthropic".to_string());
        app.router
            .auth_picker_mut()
            .set_focus(crate::app::PickerFocus::Prompt);

        let text = footer_text(&auth_picker_footer(&app, 120));

        assert!(text.contains("Esc return to picker"), "{text}");
        assert!(text.contains("Enter run"), "{text}");
        assert!(!text.contains("Esc back"), "{text}");
    }

    #[test]
    fn non_editor_footer_reserves_plain_letters_for_commands() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("anthropic".to_string());
        app.router.auth_picker_mut().set_cursor(1);
        let text = auth_picker_footer(&app, 120)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(text.contains("Esc back"), "{text}");
        assert!(text.contains("type a command"), "{text}");
        assert!(!text.contains("q "), "{text}");
    }

    #[test]
    fn word_edited_api_key_draft_renders_only_the_remaining_length() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("anthropic".to_string());
        app.router.auth_picker_mut().push_key_str("alpha beta");
        app.router.auth_picker_mut().delete_key_word_left();

        let text = api_key_draft_lines(&app, "anthropic", 120)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(text.contains("6 chars entered · value hidden"), "{text}");
        assert!(!text.contains("alpha"), "{text}");
        assert!(!text.contains("beta"), "{text}");
    }

    #[test]
    fn openai_oauth_model_id_renders_as_the_public_provider_name() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let text = auth_picker_intro(&app, "openai-codex", 120)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(text.contains("Provider openai needs credentials"), "{text}");
        assert!(!text.contains("openai-codex"), "{text}");
    }
}
