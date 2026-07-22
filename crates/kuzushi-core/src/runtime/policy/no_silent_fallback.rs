use anyhow::{Context, Result};

pub fn validate_model_spec(model: &str) -> Result<()> {
    normalize_model_spec(model)?;
    Ok(())
}

pub fn canonical_model_spec(model: &str) -> Result<String> {
    normalize_model_spec(model)
}

pub fn validate_model_api_key_env(model: &str, api_key_env: &str) -> Result<()> {
    let canonical = normalize_model_spec(model)?;
    let provider_default = supported_bridge_api_key_env(model_provider(&canonical))?;
    let configured = api_key_env.trim();
    validate_api_key_env_name(configured)?;
    require_provider_default_api_key_env(&canonical, configured, provider_default)?;
    Ok(())
}

pub fn bridge_api_key_env_for_model(model: &str, configured_api_key_env: &str) -> Result<String> {
    let canonical = normalize_model_spec(model)?;
    let provider_default = supported_bridge_api_key_env(model_provider(&canonical))?;
    let configured = configured_api_key_env.trim();
    validate_api_key_env_name(configured)?;
    require_provider_default_api_key_env(&canonical, configured, provider_default)?;
    Ok(provider_default.to_string())
}

pub fn require_configured_model(tool_name: &str, config_model: Option<&str>) -> Result<String> {
    let model = config_model
        .map(str::trim)
        .map(str::to_string)
        .with_context(|| config_model_error(tool_name))?;
    normalize_model_spec(&model)
        .with_context(|| format!("{tool_name} received an invalid configured model"))
}

pub fn resolve_explicit_model(
    tool_name: &str,
    input_model: Option<String>,
    config_model: Option<&str>,
) -> Result<String> {
    let model = input_model
        .or_else(|| config_model.map(str::to_string))
        .map(|model| model.trim().to_string())
        .with_context(|| tool_input_model_error(tool_name))?;
    normalize_model_spec(&model).with_context(|| format!("{tool_name} received an invalid model"))
}

fn normalize_model_spec(model: &str) -> Result<String> {
    let model = model.trim();
    let Some((provider, model_id)) = model.split_once(':') else {
        anyhow::bail!("model must use provider:model syntax, got {model:?}");
    };
    let provider = provider.trim();
    let model_id = model_id.trim();
    if provider.is_empty() || model_id.is_empty() {
        anyhow::bail!("model must include both provider and model id, got {model:?}");
    }
    Ok(format!("{provider}:{model_id}"))
}

fn model_provider(model: &str) -> &str {
    model
        .split_once(':')
        .map(|(provider, _)| provider)
        .unwrap_or(model)
}

fn supported_bridge_api_key_env(provider: &str) -> Result<&'static str> {
    match provider {
        "anthropic" => Ok("ANTHROPIC_API_KEY"),
        // Claude via Google Vertex AI: the secret is GCP Application Default
        // Credentials, so the credential env carries the project id instead
        // of a token. The bridge resolves a missing project id from ADC.
        "vertex-anthropic" => Ok("ANTHROPIC_VERTEX_PROJECT_ID"),
        "openai" | "openai-codex" => Ok("OPENAI_API_KEY"),
        _ => anyhow::bail!(
            "LangGraph bridge does not support model provider {provider:?}; use anthropic:*, vertex-anthropic:*, openai:*, or openai-codex:*"
        ),
    }
}

fn validate_api_key_env_name(api_key_env: &str) -> Result<()> {
    if api_key_env.trim().is_empty() {
        anyhow::bail!("runtime.api_key_env must not be empty");
    }
    Ok(())
}

fn require_provider_default_api_key_env(
    model: &str,
    configured: &str,
    provider_default: &str,
) -> Result<()> {
    if configured != provider_default {
        anyhow::bail!(
            "model {model} requires {provider_default}, but runtime.api_key_env is {configured}; Kuzushi will not silently switch provider credentials"
        );
    }
    Ok(())
}

fn config_model_error(tool_name: &str) -> String {
    format!(
        "{tool_name} requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model"
    )
}

fn tool_input_model_error(tool_name: &str) -> String {
    format!(
        "{tool_name} requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model"
    )
}
