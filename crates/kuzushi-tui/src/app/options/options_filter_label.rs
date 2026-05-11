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
    let raw = raw.trim();
    match spec.option_type {
        OptionType::String | OptionType::Path | OptionType::StringList => {
            Ok(raw_string_option_value(raw))
        }
        OptionType::Bool => Ok(serde_json::Value::Bool(parse_bool_option(raw)?)),
        OptionType::Int => coerce_raw_int_option(raw),
        OptionType::Float => coerce_raw_float_option(raw),
        OptionType::Enum => coerce_raw_enum_option(spec, raw),
        OptionType::Json => serde_json::from_str(raw).with_context(|| "must be valid JSON"),
    }
}

pub(crate) fn raw_string_option_value(raw: &str) -> serde_json::Value {
    serde_json::Value::String(raw.to_string())
}

pub(crate) fn coerce_raw_int_option(raw: &str) -> Result<serde_json::Value> {
    let parsed = raw
        .parse::<i64>()
        .with_context(|| format!("must be an integer, got {raw:?}"))?;
    Ok(serde_json::Value::Number(parsed.into()))
}

pub(crate) fn coerce_raw_float_option(raw: &str) -> Result<serde_json::Value> {
    let parsed = raw
        .parse::<f64>()
        .with_context(|| format!("must be a number, got {raw:?}"))?;
    let number = serde_json::Number::from_f64(parsed).context("must be a finite JSON number")?;
    Ok(serde_json::Value::Number(number))
}

pub(crate) fn coerce_raw_enum_option(spec: &OptionSpec, raw: &str) -> Result<serde_json::Value> {
    if !spec.choices.iter().any(|choice| choice == raw) {
        anyhow::bail!("must be one of {}, got {raw:?}", spec.choices.join("|"));
    }
    Ok(raw_string_option_value(raw))
}

pub(crate) fn parse_bool_option(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(false),
        _ => anyhow::bail!("must be true or false, got {value:?}"),
    }
}

pub(crate) fn format_option_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
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
