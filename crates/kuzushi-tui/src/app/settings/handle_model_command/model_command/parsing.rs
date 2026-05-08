use super::*;

pub(super) fn parse_model_command(raw: Option<String>) -> Option<ModelCommand> {
    let mut parts = model_command_parts(raw)?;
    if model_catalog_requested(parts.first().map(String::as_str)) {
        return None;
    }
    let scope = take_model_command_scope(&mut parts);
    model_command_from_parts(scope, &parts)
}

fn model_command_parts(raw: Option<String>) -> Option<Vec<String>> {
    let raw = raw
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    Some(raw.split_whitespace().map(ToString::to_string).collect())
}

#[derive(Clone, Copy)]
struct ModelCommandScope {
    force_global: bool,
    force_module: bool,
}

fn take_model_command_scope(parts: &mut Vec<String>) -> ModelCommandScope {
    let scope = model_command_scope(parts.first().map(String::as_str));
    if scope.force_global || scope.force_module {
        parts.remove(0);
    }
    scope
}

fn model_command_scope(first: Option<&str>) -> ModelCommandScope {
    ModelCommandScope {
        force_global: matches!(first, Some("global") | Some("session")),
        force_module: matches!(first, Some("module")),
    }
}

fn model_command_from_parts(scope: ModelCommandScope, parts: &[String]) -> Option<ModelCommand> {
    Some(ModelCommand {
        force_global: scope.force_global,
        force_module: scope.force_module,
        selector: parts.first()?.clone(),
        explicit_effort: parts.get(1).cloned(),
    })
}

fn model_catalog_requested(first: Option<&str>) -> bool {
    matches!(first, Some("list") | Some("models") | Some("choices"))
}

pub(super) fn resolve_model_command_selection(
    command: &ModelCommand,
) -> Result<(String, Option<String>), String> {
    let (model, default_effort) = resolve_model_command_choice(&command.selector)?;
    let effort = resolve_model_command_effort(command.explicit_effort.as_deref(), default_effort)?;
    Ok((model, effort))
}

fn resolve_model_command_choice(selector: &str) -> Result<(String, Option<&'static str>), String> {
    if let Some(choice) = resolve_model_selector(selector) {
        return Ok((choice.id.to_string(), Some(choice.thinking_level)));
    }
    if selector.contains(':') {
        return Ok((selector.to_string(), None));
    }
    Err(format!(
        "unknown model choice {selector:?}. Next: model, or model provider:model-id"
    ))
}

fn resolve_model_command_effort(
    explicit_effort: Option<&str>,
    default_effort: Option<&'static str>,
) -> Result<Option<String>, String> {
    let Some(effort) = explicit_effort.or(default_effort) else {
        return Ok(None);
    };
    normalized_model_command_effort(effort, explicit_effort)
}

fn normalized_model_command_effort(
    effort: &str,
    explicit_effort: Option<&str>,
) -> Result<Option<String>, String> {
    if let Some(level) = normalize_thinking_level(effort) {
        return Ok(Some(level.to_string()));
    }
    Err(format!(
        "unknown reasoning effort {:?}. Valid: low, medium, high, xhigh",
        explicit_effort.unwrap_or_default()
    ))
}
