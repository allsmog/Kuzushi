use super::*;

pub(crate) fn options_filter_label(filter: OptionsFilter) -> &'static str {
    match filter {
        OptionsFilter::Standard => "options",
        OptionsFilter::Advanced => "advanced options",
        OptionsFilter::Missing => "missing options",
    }
}

pub(crate) fn find_option_spec<'a>(tool: &'a ToolDescriptor, name: &str) -> Option<&'a OptionSpec> {
    tool.options
        .iter()
        .find(|spec| spec.matches_name_or_alias(name))
}

pub(crate) fn coerce_raw_option_value(spec: &OptionSpec, raw: &str) -> Result<serde_json::Value> {
    if spec.option_type == OptionType::Json {
        anyhow::bail!(
            "this setting comes from its workflow and cannot be edited here; use the owning workflow or a file option"
        );
    }
    kuzushi_core::modules::coerce_option_text(spec, raw)
}

pub(crate) fn option_is_operator_editable(spec: &OptionSpec) -> bool {
    spec.option_type != OptionType::Json
}

pub(crate) fn option_input_kind(spec: &OptionSpec) -> &'static str {
    match spec.option_type {
        OptionType::String => "text",
        OptionType::Bool => "yes / no",
        OptionType::Int => "whole number",
        OptionType::Float => "number",
        OptionType::Path => "path",
        OptionType::Enum => "choice",
        OptionType::StringList => "comma-separated list",
        OptionType::Json => "workflow supplied",
    }
}

pub(crate) fn option_edit_hint(spec: &OptionSpec) -> String {
    match spec.option_type {
        OptionType::Bool => "Space switches between yes and no".to_string(),
        OptionType::Enum => format!("Space cycles {}", spec.choices.join(" / ")),
        OptionType::Int => bounded_number_hint(spec, "whole number"),
        OptionType::Float => "Enter edits this number".to_string(),
        OptionType::String => "Enter edits this text".to_string(),
        OptionType::Path => "Enter edits this path".to_string(),
        OptionType::StringList => "Enter edits comma-separated values".to_string(),
        OptionType::Json => "This value is supplied by its workflow".to_string(),
    }
}

fn bounded_number_hint(spec: &OptionSpec, kind: &str) -> String {
    match (spec.minimum, spec.maximum) {
        (Some(min), Some(max)) => format!("Enter edits this {kind} · {min} to {max}"),
        (Some(min), None) => format!("Enter edits this {kind} · minimum {min}"),
        (None, Some(max)) => format!("Enter edits this {kind} · maximum {max}"),
        (None, None) => format!("Enter edits this {kind}"),
    }
}

pub(crate) fn format_option_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(true) => "yes".to_string(),
        serde_json::Value::Bool(false) => "no".to_string(),
        serde_json::Value::Null => "not set".to_string(),
        serde_json::Value::Array(items) if items.iter().all(serde_json::Value::is_string) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        serde_json::Value::Array(items) => counted_label(items.len(), "workflow value"),
        serde_json::Value::Object(fields) => counted_label(fields.len(), "workflow field"),
    }
}

fn counted_label(count: usize, noun: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} {noun}{suffix}")
}

pub(crate) fn unknown_option_message(tool: &ToolDescriptor, name: &str) -> String {
    let choices = tool
        .options
        .iter()
        .flat_map(option_choice_names)
        .collect::<Vec<_>>();
    let closest = closest_option_names(name, &choices);
    let closest = if closest.is_empty() {
        "none".to_string()
    } else {
        closest.join(", ")
    };
    format!(
        "unknown option {name:?} for {}. Closest: {closest}. Next: show options {}",
        tool.name, tool.name
    )
}

fn option_choice_names(spec: &OptionSpec) -> Vec<&str> {
    std::iter::once(spec.name.as_str())
        .chain(spec.aliases.iter().map(String::as_str))
        .chain(spec.deprecated_aliases.iter().map(String::as_str))
        .collect()
}

pub(crate) fn closest_option_names(name: &str, choices: &[&str]) -> Vec<String> {
    let normalized = name.to_ascii_lowercase();
    let mut scored = choices
        .iter()
        .map(|choice| {
            let choice_lower = choice.to_ascii_lowercase();
            let score =
                if choice_lower.starts_with(&normalized) || normalized.starts_with(&choice_lower) {
                    0
                } else {
                    edit_distance(&normalized, &choice_lower)
                };
            (score, (*choice).to_string())
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    scored
        .into_iter()
        .take(3)
        .filter(|(score, _)| *score <= normalized.len().max(3))
        .map(|(_, choice)| choice)
        .collect()
}
