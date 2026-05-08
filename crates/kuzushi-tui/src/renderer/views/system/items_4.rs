use super::*;

pub(crate) fn auth_provider_rows(app: &ShellApp) -> Vec<AuthProviderRow> {
    let api_key_env = app.config.runtime.api_key_env.clone();
    let env_set = std::env::var_os(api_key_env.as_str()).is_some();
    let anthropic_set = std::env::var_os("ANTHROPIC_API_KEY").is_some();
    let codex_oauth = crate::app::oauth_provider_status("openai-codex");
    let anthropic_oauth = crate::app::oauth_provider_status("anthropic");

    let env_state = if env_set {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Missing
    };
    let env_detail = if env_set {
        format!("{api_key_env}=set; value hidden")
    } else {
        format!("{api_key_env}=missing")
    };

    let anthropic_state = if anthropic_set || anthropic_oauth == "ok" {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Missing
    };
    let anthropic_detail = format!(
        "ANTHROPIC_API_KEY={}; oauth {}",
        if anthropic_set { "set" } else { "missing" },
        anthropic_oauth
    );

    let codex_state = if codex_oauth == "ok" {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Inactive
    };
    let codex_detail = format!("oauth {codex_oauth}");

    vec![
        AuthProviderRow {
            name: "pi-agent-core",
            state: env_state,
            detail: env_detail,
        },
        AuthProviderRow {
            name: "anthropic",
            state: anthropic_state,
            detail: anthropic_detail,
        },
        AuthProviderRow {
            name: "openai-codex",
            state: codex_state,
            detail: codex_detail,
        },
    ]
}

pub(crate) fn auth_provider_line(row: &AuthProviderRow) -> Line<'static> {
    let (glyph, glyph_style, label_style) = match row.state {
        AuthProviderState::Connected => (" ✓ ", theme::success(), theme::success()),
        AuthProviderState::Missing => (" ✗ ", theme::danger(), theme::danger()),
        AuthProviderState::Inactive => (" · ", theme::subtle(), theme::muted()),
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, glyph_style),
        Span::raw(" "),
        Span::styled(format!("{:14}", row.name), theme::accent()),
        Span::styled(format!("{:11}", row.state.label()), label_style),
        Span::styled(row.detail.clone(), theme::muted()),
    ])
}

impl AuthProviderState {
    pub(in crate::renderer::views) fn label(self) -> &'static str {
        match self {
            AuthProviderState::Connected => "connected",
            AuthProviderState::Missing => "missing",
            AuthProviderState::Inactive => "inactive",
        }
    }
}
