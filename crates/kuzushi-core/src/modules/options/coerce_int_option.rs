use super::*;

pub(in crate::modules) fn coerce_int_option(value: Value) -> Result<Value> {
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

pub(in crate::modules) fn coerce_float_option(value: Value) -> Result<Value> {
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

pub(in crate::modules) fn coerce_enum_option(spec: &OptionSpec, value: Value) -> Result<Value> {
    let Value::String(value) = value else {
        anyhow::bail!("must be a string enum value, got {}", json_summary(&value));
    };
    if !spec.choices.iter().any(|choice| choice == &value) {
        anyhow::bail!("must be one of {}, got {value:?}", spec.choices.join("|"));
    }
    Ok(Value::String(value))
}

pub(in crate::modules) fn parse_bool_option(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(false),
        _ => anyhow::bail!("must be a boolean (true/false/yes/no/1/0), got {value:?}"),
    }
}
