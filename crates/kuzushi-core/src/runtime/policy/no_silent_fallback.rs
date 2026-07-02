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
    let provider = model_provider(&canonical);
    let expected = expected_api_key_env(provider)?;
    let actual = api_key_env.trim();
    if actual == expected {
        return Ok(());
    }
    anyhow::bail!(
        "model provider {provider:?} is incompatible with runtime.api_key_env={actual:?}; set runtime.api_key_env = {expected:?} or choose a {expected_provider} model",
        expected_provider = expected_model_provider(expected),
    )
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

fn expected_api_key_env(provider: &str) -> Result<&'static str> {
    match provider {
        "anthropic" => Ok("ANTHROPIC_API_KEY"),
        "openai" | "openai-codex" => Ok("OPENAI_API_KEY"),
        _ => anyhow::bail!(
            "LangGraph bridge does not support model provider {provider:?}; use anthropic:*, openai:*, or openai-codex:*"
        ),
    }
}

fn expected_model_provider(api_key_env: &str) -> &'static str {
    match api_key_env {
        "ANTHROPIC_API_KEY" => "anthropic:*",
        "OPENAI_API_KEY" => "openai:* or openai-codex:*",
        _ => "matching",
    }
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
