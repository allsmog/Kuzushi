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
    if tool.options.is_empty() {
        return Ok(input);
    }

    let object = match input {
        Value::Null => Map::new(),
        Value::Object(object) => object,
        other => {
            anyhow::bail!(
                "{} expects a JSON object input when option metadata is declared, got {}",
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
                let coerced = coerce_option_value(spec, value)
                    .with_context(|| format!("{} option {}", tool.name, spec.name))?;
                validated.insert(spec.name.clone(), coerced);
            }
            None if spec.required => {
                anyhow::bail!("{} requires option {}", tool.name, spec.name);
            }
            None => {
                if let Some(default) = spec.default.clone() {
                    validated.insert(spec.name.clone(), default);
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

fn reject_unknown_tool_options(tool: &ToolDescriptor, object: &Map<String, Value>) -> Result<()> {
    if let Some(name) = object.keys().next() {
        anyhow::bail!("{}", unknown_tool_option_message(tool, name));
    }
    Ok(())
}

fn unknown_tool_option_message(tool: &ToolDescriptor, name: &str) -> String {
    let choices = tool
        .options
        .iter()
        .flat_map(|spec| {
            std::iter::once(spec.name.as_str()).chain(spec.aliases.iter().map(String::as_str))
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} received unknown option {name:?}. Declare it in option metadata or use one of: {choices}",
        tool.name
    )
}

pub(in crate::modules) fn coerce_option_value(spec: &OptionSpec, value: Value) -> Result<Value> {
    match spec.option_type {
        OptionType::String | OptionType::Path => coerce_string_option(value),
        OptionType::StringList => coerce_string_list_option(value),
        OptionType::Bool => coerce_bool_option(value),
        OptionType::Int => coerce_int_option(value),
        OptionType::Float => coerce_float_option(value),
        OptionType::Enum => coerce_enum_option(spec, value),
        OptionType::Json => Ok(value),
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
        Value::String(value) => Ok(Value::String(value)),
        Value::Array(items) => Ok(Value::Array(coerce_string_list_items(items)?)),
        other => anyhow::bail!(
            "must be a string list or comma-separated string, got {}",
            json_summary(&other)
        ),
    }
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
