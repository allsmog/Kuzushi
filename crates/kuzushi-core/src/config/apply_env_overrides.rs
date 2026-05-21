use super::*;

pub(crate) fn apply_env_overrides(config: &mut V2Config) {
    apply_model_env(config);
    apply_api_key_env(config);
    apply_base_url_env(config);
    apply_agent_bridge_env(config);
    apply_anthropic_oauth_env(config);
}

fn apply_model_env(config: &mut V2Config) {
    if let Some(model) = first_env(&["KUZUSHI_MODEL", "KUZUSHI_V2_MODEL"]) {
        config.model = non_empty_trimmed(model);
    }
}

fn apply_api_key_env(config: &mut V2Config) {
    if let Some(api_key_env) = first_env(&["KUZUSHI_API_KEY_ENV", "KUZUSHI_V2_API_KEY_ENV"]) {
        if let Some(api_key_env) = non_empty_trimmed(api_key_env) {
            config.runtime.api_key_env = api_key_env;
        }
    }
}

fn apply_base_url_env(config: &mut V2Config) {
    if let Some(base_url) = first_env(&["KUZUSHI_BASE_URL", "KUZUSHI_V2_BASE_URL"]) {
        config.runtime.base_url = non_empty_trimmed(base_url);
    }
}

fn apply_agent_bridge_env(config: &mut V2Config) {
    if let Some(command) = first_env(&["KUZUSHI_AGENT_BRIDGE", "KUZUSHI_V2_AGENT_BRIDGE"]) {
        let parts = agent_bridge_command_from_env(&command);
        if !parts.is_empty() {
            config.runtime.agent_bridge_command = Some(parts);
        }
    }
}

fn apply_anthropic_oauth_env(config: &mut V2Config) {
    let env_enable = first_env(&["KUZUSHI_ANTHROPIC_OAUTH"])
        .map(|value| matches!(value.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let env_path = first_env(&["KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS"])
        .and_then(non_empty_trimmed)
        .map(PathBuf::from);

    if !env_enable && env_path.is_none() {
        return;
    }

    let cfg = config
        .runtime
        .anthropic_oauth
        .get_or_insert_with(AnthropicOauthConfig::default);
    if let Some(path) = env_path {
        cfg.credentials_path = Some(path);
    }
}

pub(crate) fn first_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| env::var(name).ok())
}

pub(crate) fn validate_config(config: &V2Config) -> Result<()> {
    validate_model(&config.model)?;
    validate_runtime(&config.runtime)?;
    validate_operator(&config.operator)?;
    Ok(())
}

pub(crate) fn normalize_config(config: &mut V2Config) -> Result<()> {
    if let Some(model) = config.model.as_deref() {
        config.model = Some(crate::runtime::canonical_model_spec(model)?);
    }
    Ok(())
}

fn validate_optional_usd(name: &str, value: Option<f64>) -> Result<()> {
    if let Some(value) = value {
        if !value.is_finite() || value < 0.0 {
            anyhow::bail!("{name} must be a finite non-negative number");
        }
    }
    Ok(())
}

fn validate_model(model: &Option<String>) -> Result<()> {
    if let Some(model) = model {
        crate::runtime::validate_model_spec(model)?;
    }
    Ok(())
}

fn validate_runtime(runtime: &RuntimeConfig) -> Result<()> {
    validate_api_key_env(&runtime.api_key_env)?;
    validate_agent_bridge_command(&runtime.agent_bridge_command)?;
    validate_thinking_level(&runtime.thinking_level)
}

fn validate_operator(operator: &OperatorConfig) -> Result<()> {
    validate_optional_usd("operator.session_budget_usd", operator.session_budget_usd)?;
    validate_optional_usd(
        "operator.spend_hard_ceiling_usd",
        operator.spend_hard_ceiling_usd,
    )?;
    validate_trusted_modules(&operator.trusted_modules)
}

fn validate_api_key_env(api_key_env: &str) -> Result<()> {
    if api_key_env.trim().is_empty() {
        anyhow::bail!("runtime.api_key_env must not be empty");
    }
    Ok(())
}

fn validate_agent_bridge_command(command: &Option<Vec<String>>) -> Result<()> {
    if command
        .as_ref()
        .is_some_and(|command| command.is_empty() || command[0].trim().is_empty())
    {
        anyhow::bail!("runtime.agent_bridge_command must start with an executable");
    }
    Ok(())
}

fn validate_thinking_level(thinking_level: &Option<String>) -> Result<()> {
    if thinking_level
        .as_deref()
        .is_some_and(|level| !is_supported_thinking_level(level))
    {
        anyhow::bail!("runtime.thinking_level must be one of low|medium|high|xhigh");
    }
    Ok(())
}

fn validate_trusted_modules(specifiers: &[String]) -> Result<()> {
    if specifiers.iter().any(|specifier| specifier.trim().is_empty()) {
        anyhow::bail!("operator.trusted_modules entries must not be empty");
    }
    Ok(())
}

fn is_supported_thinking_level(level: &str) -> bool {
    matches!(
        level.trim().to_ascii_lowercase().as_str(),
        "low" | "medium" | "high" | "xhigh"
    )
}

fn non_empty_trimmed(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub(crate) fn shell_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn agent_bridge_command_from_env(value: &str) -> Vec<String> {
    let parts = shell_words(value);
    if is_bare_node_bridge_script(&parts) {
        return vec!["node".to_string(), parts[0].clone()];
    }
    parts
}

fn is_bare_node_bridge_script(parts: &[String]) -> bool {
    parts.len() == 1 && parts[0].ends_with(".mjs")
}
