use super::*;

pub(crate) fn apply_env_overrides(config: &mut V2Config) {
    if let Some(model) = first_env(&["KUZUSHI_MODEL", "KUZUSHI_V2_MODEL"]) {
        let trimmed = model.trim();
        config.model = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if let Some(api_key_env) = first_env(&["KUZUSHI_API_KEY_ENV", "KUZUSHI_V2_API_KEY_ENV"]) {
        if !api_key_env.trim().is_empty() {
            config.runtime.api_key_env = api_key_env.trim().to_string();
        }
    }

    if let Some(base_url) = first_env(&["KUZUSHI_BASE_URL", "KUZUSHI_V2_BASE_URL"]) {
        let trimmed = base_url.trim();
        config.runtime.base_url = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if let Some(command) = first_env(&["KUZUSHI_AGENT_BRIDGE", "KUZUSHI_V2_AGENT_BRIDGE"]) {
        let parts = shell_words(&command);
        if !parts.is_empty() {
            config.runtime.agent_bridge_command = Some(parts);
        }
    }

    // KUZUSHI_ANTHROPIC_OAUTH=1 enables the OAuth declaration with defaults.
    // KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS=<path> sets the credentials file.
    let env_enable = first_env(&["KUZUSHI_ANTHROPIC_OAUTH"])
        .map(|value| matches!(value.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let env_path = first_env(&["KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS"])
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);

    if env_enable || env_path.is_some() {
        let cfg = config
            .runtime
            .anthropic_oauth
            .get_or_insert_with(AnthropicOauthConfig::default);
        if let Some(path) = env_path {
            cfg.credentials_path = Some(path);
        }
    }
}

pub(crate) fn first_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| env::var(name).ok())
}

pub(crate) fn validate_config(config: &V2Config) -> Result<()> {
    if let Some(model) = &config.model {
        if !model.contains(':') {
            anyhow::bail!("model must use provider:model syntax, got {model:?}");
        }
    }

    if config.runtime.api_key_env.trim().is_empty() {
        anyhow::bail!("runtime.api_key_env must not be empty");
    }

    if let Some(command) = &config.runtime.agent_bridge_command {
        if command.is_empty() || command[0].trim().is_empty() {
            anyhow::bail!("runtime.agent_bridge_command must start with an executable");
        }
    }

    Ok(())
}

pub(crate) fn shell_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}
