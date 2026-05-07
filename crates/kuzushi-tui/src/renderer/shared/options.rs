use super::*;

pub(in crate::renderer) fn options_filter_label(filter: crate::app::OptionsFilter) -> &'static str {
    match filter {
        crate::app::OptionsFilter::Standard => "standard",
        crate::app::OptionsFilter::Advanced => "advanced",
        crate::app::OptionsFilter::Missing => "missing required",
    }
}

pub(in crate::renderer) fn option_visible(
    spec: &OptionSpec,
    filter: crate::app::OptionsFilter,
    has_stored_value: bool,
) -> bool {
    match filter {
        crate::app::OptionsFilter::Standard => !spec.advanced && !spec.evasion,
        crate::app::OptionsFilter::Advanced => spec.advanced || spec.evasion,
        crate::app::OptionsFilter::Missing => {
            spec.required && !has_stored_value && spec.default.is_none()
        }
    }
}

pub(in crate::renderer) fn option_type_label(option_type: OptionType) -> &'static str {
    match option_type {
        OptionType::String => "string",
        OptionType::Bool => "bool",
        OptionType::Int => "int",
        OptionType::Float => "float",
        OptionType::Path => "path",
        OptionType::Enum => "enum",
        OptionType::StringList => "list",
    }
}

pub(in crate::renderer) fn option_description(spec: &OptionSpec) -> String {
    if spec.choices.is_empty() {
        spec.description.clone()
    } else {
        format!("{} Choices: {}.", spec.description, spec.choices.join("|"))
    }
}

pub(in crate::renderer) fn format_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

pub(in crate::renderer) fn option_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let option = if total < 80 { 14 } else { 16 };
    let value = if total < 80 { 10 } else { 12 };
    let default = if total < 80 { 8 } else { 10 };
    let required = if total < 80 { 5 } else { 7 };
    let kind = 6;
    let gaps = 10;
    let description = total
        .saturating_sub(option + value + default + required + kind + gaps)
        .max(12);
    vec![option, value, default, required, kind, description]
}

pub(in crate::renderer) fn sast_task_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 5;
    let id = if total < 88 { 20 } else { 24 };
    let cost = 5;
    let scan = if total < 88 { 14 } else { 18 };
    let gaps = 8;
    let notes = total
        .saturating_sub(state + id + cost + scan + gaps)
        .max(16);
    vec![state, id, cost, scan, notes]
}
