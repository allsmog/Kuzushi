use super::*;
use crate::app::{
    auth_method_rows, auth_provider_label, credential_recovery_rows,
    oauth_model_switch_for_provider, AuthMethodRow, AuthMethodRowKind,
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

    let recovery = app.router.auth_picker().is_recovery();
    let rows = if recovery {
        credential_recovery_rows(provider)
    } else {
        auth_method_rows(provider)
    };
    let lines = expanded_auth_picker_lines(app, area, provider, &rows, recovery);
    if lines.len() > area.height as usize {
        return compact_auth_picker_lines(app, area, provider, &rows, recovery);
    }
    lines
}

fn expanded_auth_picker_lines(
    app: &ShellApp,
    area: Rect,
    provider: &str,
    rows: &[AuthMethodRow],
    recovery: bool,
) -> Vec<Line<'static>> {
    let mut lines = auth_picker_intro(app, provider, area.width, recovery);
    lines.extend(auth_picker_rows(app, provider, rows, area.width));
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
    recovery: bool,
) -> Vec<Line<'static>> {
    let mut lines = compact_auth_intro(app, provider, area.width, recovery);
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
    lines.extend(range.map(|index| auth_row_line(app, provider, index, &rows[index], area.width)));
    lines.push(compact_auth_detail(app, provider, area.width));
    lines.extend(footer);
    lines
}

fn compact_auth_intro(
    app: &ShellApp,
    provider: &str,
    width: u16,
    recovery: bool,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider("CHOOSE AUTH METHOD", width)];
    lines.extend(confirmed_target_line(app, width as usize));
    lines.push(muted(&fit(
        &compact_auth_intro_text(app, provider, recovery),
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
            muted(" Esc back"),
        ];
    }
    vec![
        muted(" ↑/↓ move · type a command · Enter select"),
        muted(" Esc back"),
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
        Some(AuthMethodRowKind::OAuth) => compact_oauth_detail(app, provider),
        Some(AuthMethodRowKind::OfflineDemo) => {
            "Enter runs the offline demo · no key, model, or binary".to_string()
        }
        None => "No authentication method selected".to_string(),
    };
    muted(&fit(&format!(" {detail}"), width as usize))
}

fn compact_oauth_detail(app: &ShellApp, provider: &str) -> String {
    let stored = oauth_ready_for_scene_provider(app, provider);
    let action = if app.pending_oauth_reconnect_required() {
        oauth_sign_in_action(provider, true)
    } else if stored {
        "reuses the stored connection"
    } else {
        oauth_sign_in_action(provider, false)
    };
    let Some(selection) = oauth_model_switch_for_provider(provider) else {
        return format!("Enter {action}");
    };
    let model = crate::app::display_model_selector(&selection.model);
    let scope = auth_model_switch_scope(app);
    let resume = app
        .router
        .auth_picker()
        .is_recovery()
        .then_some(" and resumes Scan")
        .unwrap_or_default();
    format!("Enter {action}; switches {scope} to {model}{resume}")
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

fn auth_picker_intro(
    app: &ShellApp,
    provider: &str,
    width: u16,
    recovery: bool,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider("CHOOSE AUTH METHOD", width)];
    if let Some(target) = confirmed_target_line(app, width as usize) {
        lines.push(target);
    }
    lines.push(blank());
    lines.extend(
        wrap_text(&auth_intro_text(app, provider, recovery), width as usize)
            .into_iter()
            .map(|line| muted(&line)),
    );
    lines.push(blank());
    lines
}

fn auth_picker_rows(
    app: &ShellApp,
    provider: &str,
    rows: &[AuthMethodRow],
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if row.kind == AuthMethodRowKind::OfflineDemo {
            lines.extend(offline_demo_lead(width));
        }
        lines.push(auth_row_line(app, provider, index, row, width));
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

fn auth_row_line(
    app: &ShellApp,
    provider: &str,
    idx: usize,
    row: &AuthMethodRow,
    width: u16,
) -> Line<'static> {
    let hint = auth_row_hint(app, provider, row);
    let body = format!("{}   ·   {hint}", row.label);
    selection_band(
        &body,
        idx == app.router.auth_picker().cursor(),
        width as usize,
    )
}

fn auth_row_hint(app: &ShellApp, provider: &str, row: &AuthMethodRow) -> String {
    if row.kind == AuthMethodRowKind::ApiKey && app.pending_api_key_replacement_required() {
        return "previous key rejected; paste a replacement to continue".to_string();
    }
    if row.kind == AuthMethodRowKind::OAuth && app.pending_oauth_reconnect_required() {
        return format!(
            "previous OAuth rejected; Enter {}",
            oauth_sign_in_action(provider, true)
        );
    }
    if row.kind != AuthMethodRowKind::OAuth || !oauth_ready_for_scene_provider(app, provider) {
        return row.hint.to_string();
    }
    oauth_model_switch_for_provider(provider)
        .map(|selection| {
            format!(
                "connection ready; Enter switches {} to {}",
                auth_model_switch_scope(app),
                crate::app::display_model_selector(&selection.model)
            )
        })
        .unwrap_or_else(|| "stored connection ready; Enter reuses it".to_string())
}

fn oauth_ready_for_scene_provider(app: &ShellApp, provider: &str) -> bool {
    if app.pending_oauth_reconnect_required() {
        return false;
    }
    crate::app::AuthProvider::from_scene_provider(provider)
        .map(crate::app::AuthProvider::oauth_credential_key)
        .is_some_and(|oauth| crate::app::oauth_credential_is_ready(app.config(), oauth))
}

fn auth_intro_text(app: &ShellApp, provider: &str, recovery: bool) -> String {
    if provider == "openai" {
        return openai_auth_intro(app, recovery);
    }
    if provider == "openai-codex" {
        return openai_oauth_auth_intro(app, recovery);
    }
    let oauth_ready = oauth_ready_for_scene_provider(app, provider);
    let provider = auth_provider_label(provider);
    if oauth_ready {
        return stored_oauth_intro(&provider, recovery);
    }
    missing_credentials_intro(&provider, recovery)
}

fn missing_credentials_intro(provider: &str, recovery: bool) -> String {
    if recovery {
        return format!(
            "Provider {provider} needs credentials to resume the preserved Scan. Choose a compatible method below."
        );
    }
    format!("Provider {provider} needs credentials. Paste a key, sign in, or try the demo.")
}

/// A provider whose OAuth connection is already stored does not "need
/// credentials": lead with the stored state and offer the other methods as
/// alternatives rather than presenting a first-run gate.
fn stored_oauth_intro(provider: &str, recovery: bool) -> String {
    let outcome = if recovery {
        "Choose it to resume the preserved Scan"
    } else {
        "Choose it to reuse the connection"
    };
    format!("A {provider} OAuth connection is already stored. {outcome}, or paste a key instead.")
}

fn openai_oauth_auth_intro(app: &ShellApp, recovery: bool) -> String {
    let model = credential_model_label(app, "OpenAI OAuth model");
    let connection = if app.pending_oauth_reconnect_required() {
        "The previous OAuth connection was rejected; sign in again."
    } else if oauth_ready_for_scene_provider(app, "openai-codex") {
        "A reusable OpenAI OAuth connection is ready."
    } else {
        "OpenAI browser sign-in is available."
    };
    let outcome = if recovery {
        "Choose OAuth to resume the preserved Scan."
    } else {
        "Choose OAuth, or run the offline demo."
    };
    format!("{model} requires OpenAI OAuth. {connection} {outcome}")
}

fn openai_auth_intro(app: &ShellApp, recovery: bool) -> String {
    let selected = credential_model_label(app, "OpenAI API model");
    let connection = if app.pending_api_key_replacement_required() {
        "The previous API key was rejected; paste a replacement or choose OAuth."
    } else if oauth_ready_for_scene_provider(app, "openai") {
        "A reusable OpenAI OAuth connection is ready."
    } else {
        "OpenAI browser sign-in is available."
    };
    let target = openai_oauth_switch_target();
    let switch = if app.pending_auth_switch_is_step_scoped() {
        format!("OAuth asks before switching only the paused step to {target}.")
    } else {
        format!("OAuth asks before changing the configured model to {target}.")
    };
    let outcome = if recovery {
        "Choose the API key or OAuth to resume the preserved Scan."
    } else {
        "Choose the API key, OAuth, or the offline demo."
    };
    format!("{selected} requires OPENAI_API_KEY. {connection} {switch} {outcome}")
}

fn compact_auth_intro_text(app: &ShellApp, provider: &str, recovery: bool) -> String {
    match provider {
        "openai" => compact_openai_api_intro(app, recovery),
        "openai-codex" => compact_openai_oauth_intro(app, recovery),
        _ => compact_other_auth_intro(app, provider, recovery),
    }
}

fn compact_openai_api_intro(app: &ShellApp, recovery: bool) -> String {
    let model = credential_model_label(app, "OpenAI API model");
    let scope = auth_model_switch_scope(app);
    let target = openai_oauth_switch_target();
    let detail = format!("{model} needs API key · OAuth asks to switch {scope} to {target}");
    recovery
        .then(|| format!("Scan preserved · {detail}"))
        .unwrap_or(detail)
}

fn compact_openai_oauth_intro(app: &ShellApp, recovery: bool) -> String {
    let model = credential_model_label(app, "OpenAI OAuth model");
    let action = if app.pending_oauth_reconnect_required() {
        "OAuth reconnect required"
    } else {
        "OAuth required"
    };
    let detail = format!("{model} · {action}");
    recovery
        .then(|| format!("Scan preserved · {detail}"))
        .unwrap_or(detail)
}

fn compact_other_auth_intro(app: &ShellApp, provider: &str, recovery: bool) -> String {
    let label = auth_provider_label(provider);
    if oauth_ready_for_scene_provider(app, provider) {
        return format!("{label}: OAuth stored · reuse it or paste a key");
    }
    if recovery {
        return format!("{label}: credentials needed · Scan preserved");
    }
    format!("{label}: paste a key, use OAuth, or run the offline demo")
}

fn credential_model_label<'a>(app: &'a ShellApp, fallback: &'a str) -> &'a str {
    app.engagement
        .pending_credential_continuation()
        .map(|pending| pending.model.as_str())
        .or(app.config().model.as_deref())
        .unwrap_or(fallback)
}

fn oauth_sign_in_action(provider: &str, reconnect: bool) -> &'static str {
    match (provider, reconnect) {
        ("anthropic", true) => "reconnects Anthropic OAuth",
        ("anthropic", false) => "opens Anthropic sign-in",
        (_, true) => "reconnects OpenAI OAuth",
        (_, false) => "opens OpenAI sign-in",
    }
}

fn openai_oauth_switch_target() -> String {
    crate::app::oauth_model_switch_target_label("openai")
        .unwrap_or_else(|| "an OpenAI OAuth model".to_string())
}

fn auth_model_switch_scope(app: &ShellApp) -> &'static str {
    if app.pending_auth_switch_is_step_scoped() {
        "the paused step"
    } else {
        "the configured model"
    }
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
    fn recovery_notice_footer_advertises_dismissal_before_returning_to_scan() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_credential_recovery("openai".to_string());
        app.set_warn_notice("onboarding", "OAuth login did not complete");

        let text = footer_text(&compact_auth_footer(&app));

        assert!(text.contains("Esc dismiss notice"), "{text}");
        assert!(!text.contains("Esc return to preserved Scan"), "{text}");
    }

    #[test]
    fn openai_recovery_shows_api_key_and_explicit_oauth_switch_without_demo() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());
        config.runtime.anthropic_oauth = Some(kuzushi_core::AnthropicOauthConfig {
            credentials_path: Some(temp.path().join("missing-oauth.json")),
            allow_env_token: false,
        });
        let mut app = ShellApp::new(config, None);
        app.open_credential_recovery("openai".to_string());

        let text = footer_text(&auth_method_picker_lines(
            &app,
            Rect::new(0, 0, 120, 40),
            "openai",
        ));

        assert!(text.contains("API key (OPENAI_API_KEY)"), "{text}");
        assert!(text.contains("Use OpenAI OAuth (switch model)"), "{text}");
        assert!(text.contains("openai-oauth:gpt-5.6-terra"), "{text}");
        assert!(text.contains("preserved Scan"), "{text}");
        assert!(!text.contains("Offline demo"), "{text}");
    }

    #[test]
    fn stored_anthropic_oauth_is_not_presented_as_missing_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let credentials = temp.path().join("oauth-credentials.json");
        let far_future_ms = 4_102_444_800_000_u64; // 2100-01-01
        std::fs::write(
            &credentials,
            format!(r#"{{"anthropic":{{"refresh":"r","access":"a","expires":{far_future_ms}}}}}"#),
        )
        .unwrap();
        let mut config = kuzushi_core::V2Config::default();
        config.runtime.anthropic_oauth = Some(kuzushi_core::AnthropicOauthConfig {
            credentials_path: Some(credentials),
            allow_env_token: false,
        });
        let app = ShellApp::new(config, None);

        let intro = auth_intro_text(&app, "anthropic", false);
        assert!(!intro.contains("needs credentials"), "{intro}");
        assert!(intro.contains("already stored"), "{intro}");
        let compact = compact_auth_intro_text(&app, "anthropic", false);
        assert!(compact.contains("OAuth stored"), "{compact}");
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
        let text = auth_picker_intro(&app, "openai-codex", 120, false)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(
            text.contains("OpenAI OAuth model requires OpenAI OAuth"),
            "{text}"
        );
        assert!(!text.contains("openai-codex"), "{text}");
    }
}
