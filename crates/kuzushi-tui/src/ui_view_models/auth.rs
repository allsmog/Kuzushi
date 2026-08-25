use crate::app::{env_credential_is_ready, OauthCredentialStatus};
use crate::ShellApp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthProviderTone {
    Connected,
    Missing,
    Refreshable,
    Incomplete,
}

impl AuthProviderTone {
    fn label(self) -> &'static str {
        match self {
            AuthProviderTone::Connected => "connected",
            AuthProviderTone::Missing => "missing",
            AuthProviderTone::Refreshable => "refreshable",
            AuthProviderTone::Incomplete => "incomplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthProviderRow {
    pub(crate) tone: AuthProviderTone,
    pub(crate) cells: [String; 3],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthLoginModel {
    pub(crate) provider: String,
    pub(crate) method: String,
    pub(crate) status: String,
    pub(crate) flow: String,
    pub(crate) store_path: String,
}

pub(crate) fn auth_provider_rows(app: &ShellApp) -> Vec<AuthProviderRow> {
    vec![
        runtime_env_row(app),
        anthropic_auth_row(app),
        openai_oauth_row(app),
        github_copilot_auth_row(app),
    ]
}

pub(crate) fn auth_login_model(app: &ShellApp) -> Option<AuthLoginModel> {
    app.router.auth().login().map(|login| AuthLoginModel {
        provider: login.provider.clone(),
        method: login.method.clone(),
        status: login.status.clone(),
        flow: login.detail.clone(),
        store_path: login.store_path.clone(),
    })
}

pub(crate) fn model_auth_status(app: &ShellApp, choice: &crate::app::ModelChoice) -> String {
    match choice.provider {
        "openai" => env_key_status("OPENAI_API_KEY"),
        "openai-codex" => oauth_status(app, "openai-codex"),
        "anthropic" => anthropic_auth_status(app),
        _ => choice.auth.to_string(),
    }
}

pub(crate) fn auth_env_summary(app: &ShellApp) -> String {
    let api_key_env = app.config().runtime.api_key_env.as_str();
    let auth_status = hidden_env_status(api_key_env);
    let anthropic_status = hidden_env_status("ANTHROPIC_API_KEY");
    format!("{api_key_env} ({auth_status}); ANTHROPIC_API_KEY ({anthropic_status})")
}

pub(crate) fn oauth_summary(app: &ShellApp) -> String {
    format!(
        "openai={} · anthropic={} · github-copilot={}",
        oauth_short_status(crate::app::oauth_provider_status(
            app.config(),
            "openai-codex"
        )),
        oauth_short_status(crate::app::oauth_provider_status(app.config(), "anthropic")),
        oauth_short_status(crate::app::oauth_provider_status(
            app.config(),
            "github-copilot"
        ))
    )
}

fn oauth_short_status(status: OauthCredentialStatus) -> String {
    match status {
        OauthCredentialStatus::Ready => "✓ stored".to_string(),
        OauthCredentialStatus::Refreshable => "! refreshable".to_string(),
        OauthCredentialStatus::Environment => "✓ environment".to_string(),
        OauthCredentialStatus::Missing => "○ missing".to_string(),
        OauthCredentialStatus::Invalid => "! invalid".to_string(),
    }
}

fn runtime_env_row(app: &ShellApp) -> AuthProviderRow {
    let api_key_env = app.config().runtime.api_key_env.as_str();
    let env_set = env_credential_is_ready(api_key_env);
    auth_provider_row(
        "LangGraph",
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

fn anthropic_auth_row(app: &ShellApp) -> AuthProviderRow {
    let env_set = env_credential_is_ready("ANTHROPIC_API_KEY");
    let oauth = crate::app::oauth_provider_status(app.config(), "anthropic");
    auth_provider_row(
        "anthropic",
        if env_set {
            AuthProviderTone::Connected
        } else {
            oauth_tone(oauth)
        },
        format!(
            "ANTHROPIC_API_KEY={}; oauth {}",
            if env_set { "set" } else { "missing" },
            oauth.label()
        ),
    )
}

fn openai_oauth_row(app: &ShellApp) -> AuthProviderRow {
    let oauth = crate::app::oauth_provider_status(app.config(), "openai-codex");
    auth_provider_row(
        "openai",
        oauth_tone(oauth),
        format!("oauth {}", oauth.label()),
    )
}

fn github_copilot_auth_row(app: &ShellApp) -> AuthProviderRow {
    let oauth = crate::app::oauth_provider_status(app.config(), "github-copilot");
    auth_provider_row(
        "github-copilot",
        oauth_tone(oauth),
        format!("oauth {}", oauth.label()),
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

fn oauth_tone(status: OauthCredentialStatus) -> AuthProviderTone {
    match status {
        OauthCredentialStatus::Ready => AuthProviderTone::Connected,
        OauthCredentialStatus::Refreshable => AuthProviderTone::Refreshable,
        OauthCredentialStatus::Environment => AuthProviderTone::Connected,
        OauthCredentialStatus::Missing => AuthProviderTone::Missing,
        OauthCredentialStatus::Invalid => AuthProviderTone::Incomplete,
    }
}

fn env_key_status(key: &str) -> String {
    if env_credential_is_ready(key) {
        format!("{key} set")
    } else {
        format!("{key} missing")
    }
}

fn hidden_env_status(name: &str) -> &'static str {
    if env_credential_is_ready(name) {
        "set; value hidden"
    } else {
        "missing"
    }
}

fn oauth_status(app: &ShellApp, provider: &str) -> String {
    oauth_model_status(crate::app::oauth_provider_status(app.config(), provider)).to_string()
}

fn anthropic_auth_status(app: &ShellApp) -> String {
    let env_ready = env_credential_is_ready("ANTHROPIC_API_KEY");
    let oauth = crate::app::oauth_provider_status(app.config(), "anthropic");
    anthropic_model_auth_status(env_ready, oauth).to_string()
}

fn anthropic_model_auth_status(env_ready: bool, oauth: OauthCredentialStatus) -> &'static str {
    match (env_ready, oauth_model_status(oauth)) {
        (true, "OAuth ready") => "ANTHROPIC_API_KEY/OAuth ready",
        (true, _) => "ANTHROPIC_API_KEY set",
        (false, "OAuth missing") => "ANTHROPIC auth missing",
        (false, status) => status,
    }
}

fn oauth_model_status(status: OauthCredentialStatus) -> &'static str {
    match status {
        OauthCredentialStatus::Ready => "OAuth ready",
        OauthCredentialStatus::Refreshable => "OAuth ready (refreshes on use)",
        OauthCredentialStatus::Environment => "OAuth ready (environment token)",
        OauthCredentialStatus::Invalid => "OAuth invalid",
        OauthCredentialStatus::Missing => "OAuth missing",
    }
}

#[cfg(test)]
mod tests;
