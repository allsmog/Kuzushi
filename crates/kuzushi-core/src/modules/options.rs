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
    match spec.option_type {
        OptionType::String | OptionType::Path => coerce_string_option(value),
        OptionType::StringList => coerce_string_list_option(value),
        OptionType::Bool => coerce_bool_option(value),
        OptionType::Int => coerce_int_option(value),
        OptionType::Float => coerce_float_option(value),
        OptionType::Enum => coerce_enum_option(spec, value),
    }
}

fn coerce_string_option(value: Value) -> Result<Value> {
    match value {
        Value::String(value) => Ok(Value::String(value)),
        other => anyhow::bail!("must be a string, got {}", json_summary(&other)),
    }
}

fn coerce_string_list_option(value: Value) -> Result<Value> {
    match value {
        Value::String(value) => Ok(Value::String(value)),
        Value::Array(items) => Ok(Value::Array(coerce_string_list_items(items)?)),
        other => anyhow::bail!(
            "must be a string list or comma-separated string, got {}",
            json_summary(&other)
        ),
    }
}

fn coerce_string_list_items(items: Vec<Value>) -> Result<Vec<Value>> {
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

fn coerce_bool_option(value: Value) -> Result<Value> {
    match value {
        Value::Bool(value) => Ok(Value::Bool(value)),
        Value::String(value) => Ok(Value::Bool(parse_bool_option(&value)?)),
        other => anyhow::bail!("must be a boolean, got {}", json_summary(&other)),
    }
}

fn coerce_int_option(value: Value) -> Result<Value> {
    match value {
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => {
            Ok(Value::Number(number))
        }
        Value::String(value) => {
            let parsed = value
                .trim()
                .parse::<i64>()
                .with_context(|| format!("must be an integer, got {value:?}"))?;
            Ok(Value::Number(parsed.into()))
        }
        other => anyhow::bail!("must be an integer, got {}", json_summary(&other)),
    }
}

fn coerce_float_option(value: Value) -> Result<Value> {
    match value {
        Value::Number(number) if number.as_f64().is_some() => Ok(Value::Number(number)),
        Value::String(value) => {
            let parsed = value
                .trim()
                .parse::<f64>()
                .with_context(|| format!("must be a number, got {value:?}"))?;
            let number =
                serde_json::Number::from_f64(parsed).context("must be a finite JSON number")?;
            Ok(Value::Number(number))
        }
        other => anyhow::bail!("must be a number, got {}", json_summary(&other)),
    }
}

fn coerce_enum_option(spec: &OptionSpec, value: Value) -> Result<Value> {
    let Value::String(value) = value else {
        anyhow::bail!("must be a string enum value, got {}", json_summary(&value));
    };
    if !spec.choices.iter().any(|choice| choice == &value) {
        anyhow::bail!("must be one of {}, got {value:?}", spec.choices.join("|"));
    }
    Ok(Value::String(value))
}

fn parse_bool_option(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(false),
        _ => anyhow::bail!("must be a boolean (true/false/yes/no/1/0), got {value:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{opt, tool_with_options};
    use super::*;
    use serde_json::json;

    #[test]
    fn json_summary_formats_scalar_and_structured_values() {
        assert_eq!(json_summary(&json!("text")), "text");
        assert_eq!(json_summary(&json!(42)), "42");
        assert_eq!(json_summary(&json!(true)), "true");
        assert_eq!(json_summary(&Value::Null), "null");
        assert_eq!(json_summary(&json!({"a": 1})), r#"{"a":1}"#);
    }

    #[test]
    fn validates_and_coerces_declared_tool_options() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise option validation",
            vec![
                opt("enabled", OptionType::Bool, "boolean option").default(json!(false)),
                opt("limit", OptionType::Int, "integer option").default(json!(10)),
                opt("ratio", OptionType::Float, "floating-point option"),
                opt("target", OptionType::Path, "path option").required(),
                opt("label", OptionType::String, "string option"),
                opt("tags", OptionType::StringList, "string-list option"),
                opt("mode", OptionType::Enum, "enum option")
                    .choices(&["auto", "manual"])
                    .default(json!("auto")),
            ],
        );

        let validated = validate_tool_input_options(
            &descriptor,
            json!({
                "enabled": "yes",
                "limit": "42",
                "ratio": "0.75",
                "target": "./repo",
                "label": "baseline",
                "tags": ["one", "two"],
                "mode": "manual",
                "extra": {"left": "untouched"}
            }),
        )
        .unwrap();
        assert_eq!(validated["enabled"], json!(true));
        assert_eq!(validated["limit"], json!(42));
        assert_eq!(validated["ratio"], json!(0.75));
        assert_eq!(validated["target"], json!("./repo"));
        assert_eq!(validated["label"], json!("baseline"));
        assert_eq!(validated["tags"], json!(["one", "two"]));
        assert_eq!(validated["mode"], json!("manual"));
        assert_eq!(validated["extra"], json!({"left": "untouched"}));

        let with_defaults = validate_tool_input_options(
            &descriptor,
            json!({
                "target": "./repo",
                "ratio": 1.25
            }),
        )
        .unwrap();
        assert_eq!(with_defaults["enabled"], json!(false));
        assert_eq!(with_defaults["limit"], json!(10));
        assert_eq!(with_defaults["mode"], json!("auto"));
    }

    #[test]
    fn rejects_missing_required_and_invalid_option_values() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise option validation",
            vec![
                opt("enabled", OptionType::Bool, "boolean option"),
                opt("limit", OptionType::Int, "integer option"),
                opt("ratio", OptionType::Float, "floating-point option"),
                opt("target", OptionType::Path, "path option").required(),
                opt("mode", OptionType::Enum, "enum option").choices(&["auto", "manual"]),
            ],
        );

        for (input, expected) in [
            (json!({}), "requires option target"),
            (
                json!({"target": "./repo", "enabled": "maybe"}),
                "must be a boolean",
            ),
            (
                json!({"target": "./repo", "limit": "many"}),
                "must be an integer",
            ),
            (
                json!({"target": "./repo", "ratio": "wide"}),
                "must be a number",
            ),
            (
                json!({"target": "./repo", "mode": "toggle"}),
                "must be one of auto|manual",
            ),
        ] {
            let error = validate_tool_input_options(&descriptor, input).unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains(expected),
                "expected {error:?} to contain {expected:?}"
            );
        }
    }
}
