use super::*;

pub(in crate::modules) fn json_summary(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "<json>".to_string()),
    }
}

pub(in crate::modules) fn validate_tool_input_options(
    tool: &ToolDescriptor,
    input: Value,
) -> Result<Value> {
    let object = match input {
        Value::Null => Map::new(),
        Value::Object(object) => object,
        other => {
            anyhow::bail!(
                "{} expects a JSON object input, got {}",
                tool.name,
                json_summary(&other)
            );
        }
    };
    let mut object = canonicalize_tool_option_keys(tool, object)?;
    let mut validated = Map::new();

    for spec in &tool.options {
        match object.remove(&spec.name) {
            Some(value) => {
                let coerced = coerce_option_value(spec, value).map_err(|error| {
                    anyhow::anyhow!("{} option {}: {error}", tool.name, spec.name)
                })?;
                validated.insert(spec.name.clone(), coerced);
            }
            None if spec.required => {
                anyhow::bail!("{} requires option {}", tool.name, spec.name);
            }
            None => {
                if let Some(default) = spec.default.clone() {
                    // Defaults pass the same coercion as caller input so a
                    // mistyped descriptor default cannot inject a value the
                    // option type would have rejected.
                    let coerced = coerce_option_value(spec, default).map_err(|error| {
                        anyhow::anyhow!("{} option {} default: {error}", tool.name, spec.name)
                    })?;
                    validated.insert(spec.name.clone(), coerced);
                }
            }
        }
    }

    reject_unknown_tool_options(tool, &object)?;
    Ok(Value::Object(validated))
}

fn canonicalize_tool_option_keys(
    tool: &ToolDescriptor,
    object: Map<String, Value>,
) -> Result<Map<String, Value>> {
    let mut canonical = Map::new();
    for (name, value) in object {
        let spec = option_spec_for_input_key(tool, &name)
            .with_context(|| unknown_tool_option_message(tool, &name))?;
        if name == spec.name || !canonical.contains_key(&spec.name) {
            canonical.insert(spec.name.clone(), value);
        }
    }
    Ok(canonical)
}

fn option_spec_for_input_key<'a>(tool: &'a ToolDescriptor, name: &str) -> Option<&'a OptionSpec> {
    tool.options
        .iter()
        .find(|spec| spec.matches_name_or_alias(name))
}

/// Refuse an operator-supplied option name the tool does not declare, with
/// the same message and suggestion as unknown `--input` keys. `--option`
/// values land in the option store, whose unknown keys the prepare boundary
/// otherwise ignores (a stored `setg` value may target other tools).
pub fn ensure_declared_tool_option(tool: &ToolDescriptor, name: &str) -> Result<()> {
    match option_spec_for_input_key(tool, name) {
        Some(_) => Ok(()),
        None => anyhow::bail!("{}", unknown_tool_option_message(tool, name)),
    }
}

fn reject_unknown_tool_options(tool: &ToolDescriptor, object: &Map<String, Value>) -> Result<()> {
    if let Some(name) = object.keys().next() {
        anyhow::bail!("{}", unknown_tool_option_message(tool, name));
    }
    Ok(())
}

fn unknown_tool_option_message(tool: &ToolDescriptor, name: &str) -> String {
    let choices = option_choice_names(tool);
    let hint = option_hint(&choices);
    let suggestion = closest_option_name(name, &choices)
        .map(|choice| format!(" Did you mean `{choice}`?"))
        .unwrap_or_default();
    format!(
        "{} received unknown option {name:?}.{suggestion} Next: {hint}",
        tool.name
    )
}

fn option_choice_names(tool: &ToolDescriptor) -> Vec<&str> {
    tool.options
        .iter()
        .flat_map(|spec| {
            std::iter::once(spec.name.as_str())
                .chain(spec.aliases.iter().map(String::as_str))
                .chain(spec.deprecated_aliases.iter().map(String::as_str))
        })
        .collect::<Vec<_>>()
}

fn option_hint(choices: &[&str]) -> String {
    if choices.is_empty() {
        "no options are declared for this tool; run `tools --json` to inspect the descriptor"
            .to_string()
    } else {
        format!("use one of: {}", choices.join(", "))
    }
}

fn closest_option_name<'a>(name: &str, choices: &[&'a str]) -> Option<&'a str> {
    let needle = normalized_option_name(name);
    choices.iter().copied().find(|choice| {
        let candidate = normalized_option_name(choice);
        candidate.contains(&needle)
            || needle.contains(&candidate)
            || common_prefix_len(&needle, &candidate) >= 3
    })
}

fn normalized_option_name(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn common_prefix_len(left: &str, right: &str) -> usize {
    left.chars()
        .zip(right.chars())
        .take_while(|(left, right)| left == right)
        .count()
}

pub fn coerce_option_value(spec: &OptionSpec, value: Value) -> Result<Value> {
    match spec.option_type {
        OptionType::String | OptionType::Path => coerce_string_option(value),
        OptionType::StringList => coerce_string_list_option(value),
        OptionType::Bool => coerce_bool_option(value),
        OptionType::Int => coerce_int_option(spec, value),
        OptionType::Float => coerce_float_option(value),
        OptionType::Enum => coerce_enum_option(spec, value),
        OptionType::Json => Ok(coerce_json_option(value)),
    }
}

/// Operator surfaces (`--option key=value`, shell `set`, stored options)
/// deliver every value as text. A json option given the text of an object
/// or array means that structure; any other value passes through unchanged.
fn coerce_json_option(value: Value) -> Value {
    let Value::String(text) = &value else {
        return value;
    };
    match serde_json::from_str::<Value>(text.trim()) {
        Ok(parsed @ (Value::Object(_) | Value::Array(_))) => parsed,
        _ => value,
    }
}

pub(in crate::modules) fn coerce_string_option(value: Value) -> Result<Value> {
    match value {
        Value::String(value) => Ok(Value::String(value)),
        other => anyhow::bail!("must be a string, got {}", json_summary(&other)),
    }
}

pub(in crate::modules) fn coerce_string_list_option(value: Value) -> Result<Value> {
    match value {
        Value::String(value) => Ok(Value::Array(coerce_comma_separated_strings(&value)?)),
        Value::Array(items) => Ok(Value::Array(coerce_string_list_items(items)?)),
        other => anyhow::bail!(
            "must be a string list or comma-separated string, got {}",
            json_summary(&other)
        ),
    }
}

pub(in crate::modules) fn coerce_comma_separated_strings(value: &str) -> Result<Vec<Value>> {
    let items = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| Value::String(item.to_string()))
        .collect::<Vec<_>>();
    anyhow::ensure!(!items.is_empty(), "must contain at least one string");
    Ok(items)
}

pub(in crate::modules) fn coerce_string_list_items(items: Vec<Value>) -> Result<Vec<Value>> {
    items
        .into_iter()
        .map(|item| {
            item.as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| Value::String(value.to_string()))
                .context("must contain only non-empty strings")
        })
        .collect()
}

pub(in crate::modules) fn coerce_bool_option(value: Value) -> Result<Value> {
    match value {
        Value::Bool(value) => Ok(Value::Bool(value)),
        Value::String(value) => Ok(Value::Bool(parse_bool_option(&value)?)),
        other => anyhow::bail!("must be a boolean, got {}", json_summary(&other)),
    }
}
