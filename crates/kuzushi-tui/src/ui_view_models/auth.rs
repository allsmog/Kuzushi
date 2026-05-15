use crate::ShellApp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthProviderTone {
    Connected,
    Missing,
    Inactive,
}

impl AuthProviderTone {
    fn label(self) -> &'static str {
        match self {
            AuthProviderTone::Connected => "connected",
            AuthProviderTone::Missing => "missing",
            AuthProviderTone::Inactive => "inactive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthProviderRow {
    pub(crate) tone: AuthProviderTone,
    pub(crate) cells: [String; 3],
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

pub(crate) fn auth_env_summary(app: &ShellApp) -> String {
    let api_key_env = app.config.runtime.api_key_env.as_str();
    let auth_status = hidden_env_status(api_key_env);
    let anthropic_status = hidden_env_status("ANTHROPIC_API_KEY");
    format!("{api_key_env} ({auth_status}); ANTHROPIC_API_KEY ({anthropic_status})")
}

pub(crate) fn oauth_summary() -> String {
    format!(
        "openai {}; anthropic {}",
        crate::app::oauth_provider_status("openai-codex"),
        crate::app::oauth_provider_status("anthropic")
    )
}

fn runtime_env_row(app: &ShellApp) -> AuthProviderRow {
    let api_key_env = app.config.runtime.api_key_env.as_str();
    let env_set = std::env::var_os(api_key_env).is_some();
    auth_provider_row(
        "pi-agent-core",
        connected_or_missing(env_set),
        runtime_env_detail(api_key_env, env_set),
    )
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
    auth_provider_row(
        "anthropic",
        connected_or_missing(env_set || oauth == "ok"),
        format!(
            "ANTHROPIC_API_KEY={}; oauth {oauth}",
            if env_set { "set" } else { "missing" }
        ),
    )
}

fn openai_oauth_row() -> AuthProviderRow {
    let oauth = crate::app::oauth_provider_status("openai-codex");
    auth_provider_row(
        "openai",
        if oauth == "ok" {
            AuthProviderTone::Connected
        } else {
            AuthProviderTone::Inactive
        },
        format!("oauth {oauth}"),
    )
}

fn auth_provider_row(name: &str, tone: AuthProviderTone, detail: String) -> AuthProviderRow {
    AuthProviderRow {
        tone,
        cells: [name.to_string(), tone.label().to_string(), detail],
    }
}

fn connected_or_missing(connected: bool) -> AuthProviderTone {
    if connected {
        AuthProviderTone::Connected
    } else {
        AuthProviderTone::Missing
    }
}

fn env_key_status(key: &str) -> String {
    if std::env::var_os(key).is_some() {
        format!("{key} set")
    } else {
        format!("{key} missing")
    }
}

fn hidden_env_status(name: &str) -> &'static str {
    if std::env::var_os(name).is_some() {
        "set; value hidden"
    } else {
        "missing"
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
