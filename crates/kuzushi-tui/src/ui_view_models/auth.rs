use crate::ShellApp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthProviderState {
    Connected,
    Missing,
    Inactive,
}

impl AuthProviderState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            AuthProviderState::Connected => "connected",
            AuthProviderState::Missing => "missing",
            AuthProviderState::Inactive => "inactive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthProviderRow {
    pub(crate) name: &'static str,
    pub(crate) state: AuthProviderState,
    pub(crate) detail: String,
}

pub(crate) fn auth_provider_rows(app: &ShellApp) -> Vec<AuthProviderRow> {
    vec![
        runtime_env_row(app),
        anthropic_auth_row(),
        openai_oauth_row(),
    ]
}

pub(crate) fn model_auth_status(choice: &crate::app::ModelChoice) -> String {
    match choice.provider {
        "openai" => env_key_status("OPENAI_API_KEY"),
        "openai-codex" => oauth_status("openai-codex"),
        "anthropic" => anthropic_auth_status(),
        _ => choice.auth.to_string(),
    }
}

fn runtime_env_row(app: &ShellApp) -> AuthProviderRow {
    let api_key_env = app.config.runtime.api_key_env.as_str();
    let env_set = std::env::var_os(api_key_env).is_some();
    AuthProviderRow {
        name: "pi-agent-core",
        state: connected_or_missing(env_set),
        detail: runtime_env_detail(api_key_env, env_set),
    }
}

fn runtime_env_detail(api_key_env: &str, env_set: bool) -> String {
    if env_set {
        format!("{api_key_env}=set; value hidden")
    } else {
        format!("{api_key_env}=missing")
    }
}

fn anthropic_auth_row() -> AuthProviderRow {
    let env_set = std::env::var_os("ANTHROPIC_API_KEY").is_some();
    let oauth = crate::app::oauth_provider_status("anthropic");
    AuthProviderRow {
        name: "anthropic",
        state: connected_or_missing(env_set || oauth == "ok"),
        detail: format!(
            "ANTHROPIC_API_KEY={}; oauth {oauth}",
            if env_set { "set" } else { "missing" }
        ),
    }
}

fn openai_oauth_row() -> AuthProviderRow {
    let oauth = crate::app::oauth_provider_status("openai-codex");
    AuthProviderRow {
        name: "openai",
        state: if oauth == "ok" {
            AuthProviderState::Connected
        } else {
            AuthProviderState::Inactive
        },
        detail: format!("oauth {oauth}"),
    }
}

fn connected_or_missing(connected: bool) -> AuthProviderState {
    if connected {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Missing
    }
}

fn env_key_status(key: &str) -> String {
    if std::env::var_os(key).is_some() {
        format!("{key} set")
    } else {
        format!("{key} missing")
    }
}

fn oauth_status(provider: &str) -> String {
    if crate::app::oauth_provider_status(provider).starts_with("stored") {
        "OAuth ready".to_string()
    } else {
        "OAuth missing".to_string()
    }
}

fn anthropic_auth_status() -> String {
    auth_pair_status(
        std::env::var_os("ANTHROPIC_API_KEY").is_some(),
        crate::app::oauth_provider_status("anthropic").starts_with("stored"),
    )
    .to_string()
}

fn auth_pair_status(env_ready: bool, oauth_ready: bool) -> &'static str {
    match (env_ready, oauth_ready) {
        (true, true) => "ANTHROPIC_API_KEY/OAuth ready",
        (true, false) => "ANTHROPIC_API_KEY set",
        (false, true) => "OAuth ready",
        (false, false) => "ANTHROPIC auth missing",
    }
}

#[cfg(test)]
mod tests;
