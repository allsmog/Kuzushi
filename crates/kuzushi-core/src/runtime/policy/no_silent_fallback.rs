use anyhow::{Context, Result};

pub fn validate_model_spec(model: &str) -> Result<()> {
    normalize_model_spec(model)?;
    Ok(())
}

pub fn canonical_model_spec(model: &str) -> Result<String> {
    normalize_model_spec(model)
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
