pub(in crate::renderer) use super::*;

pub(crate) fn options_filter_label(filter: crate::app::OptionsFilter) -> &'static str {
    OPTION_FILTER_LABELS
        .iter()
        .find_map(|(candidate, label)| (*candidate == filter).then_some(*label))
        .unwrap_or("options")
}

const OPTION_FILTER_LABELS: &[(crate::app::OptionsFilter, &str)] = &[
    (crate::app::OptionsFilter::Standard, "options"),
    (crate::app::OptionsFilter::Advanced, "advanced options"),
    (crate::app::OptionsFilter::Missing, "missing options"),
];

pub(crate) fn option_visible(
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

pub(crate) fn option_type_label(option_type: OptionType) -> &'static str {
    const OPTION_TYPE_LABELS: &[(OptionType, &str)] = &[
        (OptionType::String, "string"),
        (OptionType::Bool, "bool"),
        (OptionType::Int, "int"),
        (OptionType::Float, "float"),
        (OptionType::Path, "path"),
        (OptionType::Enum, "enum"),
        (OptionType::StringList, "list"),
        (OptionType::Json, "json"),
    ];
    OPTION_TYPE_LABELS
        .iter()
        .find_map(|(candidate, label)| (*candidate == option_type).then_some(*label))
        .unwrap_or("json")
}

pub(crate) fn option_description(spec: &OptionSpec) -> String {
    if spec.choices.is_empty() {
        spec.description.clone()
    } else {
        format!("{} Choices: {}.", spec.description, spec.choices.join("|"))
    }
}

pub(crate) fn option_alias_label(spec: &OptionSpec) -> String {
    let aliases = option_alias_values(spec);
    if aliases.is_empty() {
        "-".to_string()
    } else {
        aliases.join(", ")
    }
}

fn option_alias_values(spec: &OptionSpec) -> Vec<String> {
    let mut aliases = spec.aliases.clone();
    aliases.extend(
        spec.deprecated_aliases
            .iter()
            .map(|alias| format!("{alias} (deprecated)")),
    );
    aliases
}

pub(crate) fn format_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

pub(crate) fn option_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let option = if total <= 80 { 13 } else { 16 };
    let value = if total <= 80 { 8 } else { 10 };
    let default = if total <= 80 { 7 } else { 9 };
    let required = if total <= 80 { 3 } else { 5 };
    let kind = 5;
    let aliases = if total <= 80 { 10 } else { 16 };
    let gaps = 12;
    let description = total
        .saturating_sub(option + value + default + required + kind + aliases + gaps)
        .max(12);
    vec![option, value, default, required, kind, aliases, description]
}

pub(crate) fn sast_task_table_widths(width: u16) -> Vec<usize> {
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
