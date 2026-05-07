use anyhow::{Context, Result};
use serde_json::{Map, Value};

use super::{OptionSpec, OptionType, ToolDescriptor};

pub(super) fn json_summary(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "<json>".to_string()),
    }
}

pub(super) fn validate_tool_input_options(tool: &ToolDescriptor, input: Value) -> Result<Value> {
    if tool.options.is_empty() {
        return Ok(input);
    }

    let mut object = match input {
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

    for spec in &tool.options {
        match object.remove(&spec.name) {
            Some(value) => {
                let coerced = coerce_option_value(spec, value)
                    .with_context(|| format!("{} option {}", tool.name, spec.name))?;
                object.insert(spec.name.clone(), coerced);
            }
            None if spec.required => {
                anyhow::bail!("{} requires option {}", tool.name, spec.name);
            }
            None => {
                if let Some(default) = spec.default.clone() {
                    object.insert(spec.name.clone(), default);
                }
            }
        }
    }

    Ok(Value::Object(object))
}

fn coerce_option_value(spec: &OptionSpec, value: Value) -> Result<Value> {
    let coerced = match spec.option_type {
        OptionType::String | OptionType::Path => match value {
            Value::String(value) => Value::String(value),
            other => anyhow::bail!("must be a string, got {}", json_summary(&other)),
        },
        OptionType::StringList => match value {
            Value::String(value) => Value::String(value),
            Value::Array(items) => {
                let values = items
                    .into_iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(|value| Value::String(value.to_string()))
                            .context("must contain only non-empty strings")
                    })
                    .collect::<Result<Vec<_>>>()?;
                Value::Array(values)
            }
            other => anyhow::bail!(
                "must be a string list or comma-separated string, got {}",
                json_summary(&other)
            ),
        },
        OptionType::Bool => match value {
            Value::Bool(value) => Value::Bool(value),
            Value::String(value) => Value::Bool(parse_bool_option(&value)?),
            other => anyhow::bail!("must be a boolean, got {}", json_summary(&other)),
        },
        OptionType::Int => match value {
            Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => {
                Value::Number(number)
            }
            Value::String(value) => {
                let parsed = value
                    .trim()
                    .parse::<i64>()
                    .with_context(|| format!("must be an integer, got {value:?}"))?;
                Value::Number(parsed.into())
            }
            other => anyhow::bail!("must be an integer, got {}", json_summary(&other)),
        },
        OptionType::Float => match value {
            Value::Number(number) if number.as_f64().is_some() => Value::Number(number),
            Value::String(value) => {
                let parsed = value
                    .trim()
                    .parse::<f64>()
                    .with_context(|| format!("must be a number, got {value:?}"))?;
                let number =
                    serde_json::Number::from_f64(parsed).context("must be a finite JSON number")?;
                Value::Number(number)
            }
            other => anyhow::bail!("must be a number, got {}", json_summary(&other)),
        },
        OptionType::Enum => match value {
            Value::String(value) => Value::String(value),
            other => anyhow::bail!("must be a string enum value, got {}", json_summary(&other)),
        },
    };

    if spec.option_type == OptionType::Enum {
        let value = coerced
            .as_str()
            .context("enum coercion produced a non-string value")?;
        if !spec.choices.iter().any(|choice| choice == value) {
            anyhow::bail!("must be one of {}, got {value:?}", spec.choices.join("|"));
        }
    }

    Ok(coerced)
}

fn parse_bool_option(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(false),
        _ => anyhow::bail!("must be a boolean (true/false/yes/no/1/0), got {value:?}"),
    }
}
