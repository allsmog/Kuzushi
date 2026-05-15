pub(crate) fn model_auth_status(choice: &crate::app::ModelChoice) -> String {
    match choice.provider {
        "openai" => env_key_status("OPENAI_API_KEY"),
        "openai-codex" => oauth_status("openai-codex"),
        "anthropic" => anthropic_auth_status(),
        _ => choice.auth.to_string(),
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
