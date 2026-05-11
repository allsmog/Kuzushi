pub(crate) fn validate_shell_model_id(model: &str) -> std::result::Result<(), String> {
    if model.is_empty() {
        return Err("model cannot be empty. Next: model, or model provider:model-id".to_string());
    }
    let Some((provider, model_id)) = model.split_once(':') else {
        return Err(format!(
            "model must use provider:model syntax, got {model:?}. Next: model, or model openai:gpt-5.5"
        ));
    };
    if provider.trim().is_empty() || model_id.trim().is_empty() {
        return Err(format!(
            "model must include both provider and model id, got {model:?}. Next: model, or model openai:gpt-5.5"
        ));
    }
    Ok(())
}
