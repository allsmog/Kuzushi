use super::*;

pub(crate) fn auth_provider_rows(app: &ShellApp) -> Vec<AuthProviderRow> {
    vec![
        runtime_env_row(app),
        anthropic_auth_row(),
        openai_oauth_row(),
    ]
}

fn runtime_env_row(app: &ShellApp) -> AuthProviderRow {
    let api_key_env = app.config.runtime.api_key_env.clone();
    let env_set = std::env::var_os(api_key_env.as_str()).is_some();
    let env_detail = if env_set {
        format!("{api_key_env}=set; value hidden")
    } else {
        format!("{api_key_env}=missing")
    };
    AuthProviderRow {
        name: "pi-agent-core",
        state: connected_or_missing(env_set),
        detail: env_detail,
    }
}

fn anthropic_auth_row() -> AuthProviderRow {
    let anthropic_set = std::env::var_os("ANTHROPIC_API_KEY").is_some();
    let anthropic_oauth = crate::app::oauth_provider_status("anthropic");
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
    AuthProviderRow {
        name: "anthropic",
        state: anthropic_state,
        detail: anthropic_detail,
    }
}

fn openai_oauth_row() -> AuthProviderRow {
    let openai_oauth = crate::app::oauth_provider_status("openai-codex");
    let openai_state = if openai_oauth == "ok" {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Inactive
    };
    let openai_detail = format!("oauth {openai_oauth}");
    AuthProviderRow {
        name: "openai",
        state: openai_state,
        detail: openai_detail,
    }
}

fn connected_or_missing(connected: bool) -> AuthProviderState {
    if connected {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Missing
    }
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
