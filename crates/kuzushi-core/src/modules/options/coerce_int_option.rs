use super::*;

pub(in crate::modules) fn coerce_int_option(spec: &OptionSpec, value: Value) -> Result<Value> {
    let value = match value {
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
    };
    validate_integer_range(spec, value)
}

fn validate_integer_range(spec: &OptionSpec, value: Value) -> Result<Value> {
    let number = integer_as_i128(&value)?;
    validate_integer_minimum(spec.minimum, number)?;
    validate_integer_maximum(spec.maximum, number)?;
    Ok(value)
}

fn integer_as_i128(value: &Value) -> Result<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
        .context("must be a JSON integer")
}

fn validate_integer_minimum(minimum: Option<i64>, value: i128) -> Result<()> {
    if let Some(minimum) = minimum {
        anyhow::ensure!(value >= i128::from(minimum), "must be at least {minimum}, got {value}");
    }
    Ok(())
}

fn validate_integer_maximum(maximum: Option<i64>, value: i128) -> Result<()> {
    if let Some(maximum) = maximum {
        anyhow::ensure!(value <= i128::from(maximum), "must be at most {maximum}, got {value}");
    }
    Ok(())
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
