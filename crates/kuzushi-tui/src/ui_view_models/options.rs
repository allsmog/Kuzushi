use crate::{OptionsFilter, OptionsView, ShellApp};
use kuzushi_core::modules::{OptionSpec, OptionType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OptionsModel {
    pub(crate) tool_name: String,
    pub(crate) filter_label: &'static str,
    pub(crate) status: OptionsModelStatus,
    pub(crate) rows: Vec<OptionRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionsModelStatus {
    Ready,
    UnknownTool,
    Empty {
        message: &'static str,
        plain_message: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OptionRow {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) default_value: String,
    pub(crate) required: &'static str,
    pub(crate) option_type: &'static str,
    pub(crate) aliases: String,
    pub(crate) description: String,
    has_stored_value: bool,
}

pub(crate) fn options_model(app: &ShellApp, view: &OptionsView) -> OptionsModel {
    let Some(tool) = app.registry.resolve_tool(&view.tool_name) else {
        return options_model_status(view, OptionsModelStatus::UnknownTool, Vec::new());
    };
    let stored = app.option_store.effective_stored_values(&tool.name);
    let mut rows = tool
        .options
        .iter()
        .filter_map(|spec| option_row(spec, view.filter, stored.get(&spec.name)))
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| !row.has_stored_value);
    let status = if rows.is_empty() {
        empty_options_status(view.filter)
    } else {
        OptionsModelStatus::Ready
    };
    options_model_status(view, status, rows)
}

fn options_model_status(
    view: &OptionsView,
    status: OptionsModelStatus,
    rows: Vec<OptionRow>,
) -> OptionsModel {
    OptionsModel {
        tool_name: view.tool_name.clone(),
        filter_label: options_filter_label(view.filter),
        status,
        rows,
    }
}

fn option_row(
    spec: &OptionSpec,
    filter: OptionsFilter,
    current: Option<&serde_json::Value>,
) -> Option<OptionRow> {
    let has_stored_value = current.is_some();
    if !option_visible(spec, filter, has_stored_value) {
        return None;
    }
    Some(OptionRow {
        name: spec.name.clone(),
        value: current.map(format_json_value).unwrap_or_else(dash),
        default_value: spec
            .default
            .as_ref()
            .map(format_json_value)
            .unwrap_or_else(dash),
        required: required_label(spec, current),
        option_type: option_type_label(spec.option_type),
        aliases: option_alias_label(spec),
        description: option_description(spec),
        has_stored_value,
    })
}

fn options_filter_label(filter: OptionsFilter) -> &'static str {
    match filter {
        OptionsFilter::Standard => "options",
        OptionsFilter::Advanced => "advanced options",
        OptionsFilter::Missing => "missing options",
    }
}

fn empty_options_status(filter: OptionsFilter) -> OptionsModelStatus {
    match filter {
        OptionsFilter::Standard => OptionsModelStatus::Empty {
            message: "No standard options. Run show advanced for hidden controls.",
            plain_message: "No standard options. Next: show advanced",
        },
        OptionsFilter::Advanced => OptionsModelStatus::Empty {
            message: "No advanced options for this tool.",
            plain_message: "No advanced options for this tool.",
        },
        OptionsFilter::Missing => OptionsModelStatus::Empty {
            message: "No missing required options for this tool.",
            plain_message: "No missing required options for this tool.",
        },
    }
}

fn option_visible(spec: &OptionSpec, filter: OptionsFilter, has_stored_value: bool) -> bool {
    match filter {
        OptionsFilter::Standard => !spec.advanced && !spec.evasion,
        OptionsFilter::Advanced => spec.advanced || spec.evasion,
        OptionsFilter::Missing => spec.required && !has_stored_value && spec.default.is_none(),
    }
}

fn required_label(spec: &OptionSpec, current: Option<&serde_json::Value>) -> &'static str {
    if spec.required && current.is_none() && spec.default.is_none() {
        "missing"
    } else if spec.required {
        "yes"
    } else {
        "no"
    }
}

fn option_type_label(option_type: OptionType) -> &'static str {
    match option_type {
        OptionType::String => "string",
        OptionType::Bool => "bool",
        OptionType::Int => "int",
        OptionType::Float => "float",
        OptionType::Path => "path",
        OptionType::Enum => "enum",
        OptionType::StringList => "list",
        OptionType::Json => "json",
    }
}

fn option_description(spec: &OptionSpec) -> String {
    if spec.choices.is_empty() {
        spec.description.clone()
    } else {
        format!("{} Choices: {}.", spec.description, spec.choices.join("|"))
    }
}

fn option_alias_label(spec: &OptionSpec) -> String {
    let aliases = option_alias_values(spec);
    if aliases.is_empty() {
        dash()
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

fn format_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

fn dash() -> String {
    "-".to_string()
}

#[cfg(test)]
mod tests;
