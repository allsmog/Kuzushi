use crate::{OptionsFilter, OptionsView, ShellApp};
use kuzushi_core::modules::{OptionSpec, OptionType};
use kuzushi_core::OptionScope;

const OPTIONS_SUMMARY_COLUMN_COUNT: usize = 2;

pub(crate) fn option_display_name(name: &str) -> String {
    option_name_words(name)
        .iter()
        .enumerate()
        .map(|(index, word)| display_option_word(word, index == 0))
        .collect::<Vec<_>>()
        .join(" ")
}

fn option_name_words(name: &str) -> Vec<String> {
    let chars = name.chars().collect::<Vec<_>>();
    let mut words = Vec::new();
    let mut current = String::new();
    for (index, ch) in chars.iter().copied().enumerate() {
        if matches!(ch, '_' | '-') {
            push_option_word(&mut words, &mut current);
            continue;
        }
        let previous = index.checked_sub(1).and_then(|index| chars.get(index));
        let next = chars.get(index + 1);
        if option_word_boundary(previous, ch, next) {
            push_option_word(&mut words, &mut current);
        }
        current.push(ch);
    }
    push_option_word(&mut words, &mut current);
    words
}

fn option_word_boundary(previous: Option<&char>, current: char, next: Option<&char>) -> bool {
    (current.is_ascii_uppercase()
        && previous.is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()))
        || (current.is_ascii_uppercase()
            && previous.is_some_and(|ch| ch.is_ascii_uppercase())
            && next.is_some_and(|ch| ch.is_ascii_lowercase()))
}

fn push_option_word(words: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        words.push(std::mem::take(current));
    }
}

fn display_option_word(word: &str, first: bool) -> String {
    let lower = word.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "api" | "cve" | "id" | "json" | "llm" | "usd"
    ) {
        return lower.to_ascii_uppercase();
    }
    if first {
        let mut chars = lower.chars();
        return chars
            .next()
            .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
            .unwrap_or_default();
    }
    lower
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OptionsModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<OptionsSummaryRow>,
    pub(crate) body: OptionsBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OptionsSummaryRow {
    pub(crate) cells: [String; OPTIONS_SUMMARY_COLUMN_COUNT],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OptionsBody {
    Table(OptionsTable),
    Message {
        message: &'static str,
        plain_message: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OptionsTable {
    pub(crate) hint: &'static str,
    pub(crate) headers: [&'static str; 7],
    pub(crate) rows: Vec<OptionsTableRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OptionsTableRow {
    pub(crate) cells: [String; 7],
    has_stored_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainOptionsModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) body: PlainOptionsBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlainOptionsBody {
    Table(PlainOptionsTable),
    Message(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainOptionsTable {
    pub(crate) headers: [&'static str; 7],
    pub(crate) rows: Vec<PlainOptionRow>,
    pub(crate) note: &'static str,
    pub(crate) next_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainOptionRow {
    pub(crate) cells: [String; 7],
}

pub(crate) fn options_model(app: &ShellApp, view: &OptionsView) -> OptionsModel {
    let Some(tool) = app.registry().resolve_tool(&view.tool_name) else {
        return options_model_body(view, unknown_tool_body());
    };
    let stored = app.option_store().effective_stored_values(&tool.name);
    let mut rows = tool
        .options
        .iter()
        .filter_map(|spec| {
            option_row(
                spec,
                view.filter,
                stored.get(&spec.name),
                app.option_store()
                    .effective_stored_value_scope(&tool.name, &spec.name),
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| !row.has_stored_value);
    let body = if rows.is_empty() {
        empty_options_body(view.filter)
    } else {
        OptionsBody::Table(options_table(rows))
    };
    options_model_body(view, body)
}

pub(crate) fn plain_options_model(app: &ShellApp, view: &OptionsView) -> PlainOptionsModel {
    PlainOptionsModel::from_options_model(options_model(app, view))
}

impl PlainOptionsModel {
    fn from_options_model(model: OptionsModel) -> Self {
        let OptionsModel {
            title,
            summary_rows,
            body,
        } = model;
        PlainOptionsModel {
            title,
            summary_rows: summary_rows.into_iter().map(plain_summary_row).collect(),
            body: plain_options_body(body),
        }
    }
}

fn plain_summary_row(row: OptionsSummaryRow) -> String {
    let [label, value] = row.cells;
    format!("{label}: {value}")
}

fn plain_options_body(body: OptionsBody) -> PlainOptionsBody {
    match body {
        OptionsBody::Table(table) => PlainOptionsBody::Table(plain_options_table(table)),
        OptionsBody::Message { plain_message, .. } => {
            PlainOptionsBody::Message(vec![plain_message.to_string()])
        }
    }
}

fn plain_options_table(table: OptionsTable) -> PlainOptionsTable {
    PlainOptionsTable {
        headers: table.headers,
        rows: table.rows.into_iter().map(plain_option_row).collect(),
        note: "set is session-only (lost on exit); setg is persistent for this tool.",
        next_hint: "Next: set <key> <value>, setg <key> <value>, show advanced, show missing",
    }
}

fn plain_option_row(row: OptionsTableRow) -> PlainOptionRow {
    PlainOptionRow { cells: row.cells }
}

fn options_model_body(view: &OptionsView, body: OptionsBody) -> OptionsModel {
    let filter_label = options_filter_label(view.filter);
    OptionsModel {
        title: "OPTIONS",
        summary_rows: options_summary_rows(&view.tool_name, filter_label),
        body,
    }
}

fn options_table(rows: Vec<OptionsTableRow>) -> OptionsTable {
    OptionsTable {
        hint:
            "set <key> <value>: session-only (lost on exit); setg <key> <value>: global for this tool.",
        headers: [
            "option",
            "value · scope",
            "default",
            "req",
            "type",
            "aliases",
            "description",
        ],
        rows,
    }
}

fn options_summary_rows(tool_name: &str, filter_label: &str) -> Vec<OptionsSummaryRow> {
    vec![
        options_summary_row("tool", tool_name),
        options_summary_row("view", filter_label),
    ]
}

fn options_summary_row(label: &'static str, value: &str) -> OptionsSummaryRow {
    OptionsSummaryRow {
        cells: [label.to_string(), value.to_string()],
    }
}

fn option_row(
    spec: &OptionSpec,
    filter: OptionsFilter,
    current: Option<&serde_json::Value>,
    scope: Option<OptionScope>,
) -> Option<OptionsTableRow> {
    let has_stored_value = current.is_some();
    if !option_visible(spec, filter, has_stored_value) {
        return None;
    }
    Some(OptionsTableRow {
        cells: [
            spec.name.clone(),
            stored_value_label(current, scope),
            spec.default
                .as_ref()
                .map(format_json_value)
                .unwrap_or_else(dash),
            required_label(spec, current).to_string(),
            option_type_label(spec.option_type).to_string(),
            option_alias_label(spec),
            option_description(spec),
        ],
        has_stored_value,
    })
}

fn stored_value_label(current: Option<&serde_json::Value>, scope: Option<OptionScope>) -> String {
    let Some(current) = current else {
        return dash();
    };
    let scope = match scope {
        Some(OptionScope::Global) => "global",
        Some(OptionScope::Workspace) => "workspace",
        Some(OptionScope::Session) => "session",
        None => "unknown source",
    };
    format!("{} · {scope}", format_json_value(current))
}

fn options_filter_label(filter: OptionsFilter) -> &'static str {
    match filter {
        OptionsFilter::Standard => "options",
        OptionsFilter::Advanced => "advanced options",
        OptionsFilter::Missing => "missing options",
    }
}

fn unknown_tool_body() -> OptionsBody {
    OptionsBody::Message {
        message: "Unknown tool. Run tools to inspect the native registry.",
        plain_message: "Unknown tool. Next: tools",
    }
}

fn empty_options_body(filter: OptionsFilter) -> OptionsBody {
    match filter {
        OptionsFilter::Standard => OptionsBody::Message {
            message: "No standard options. Run show advanced for hidden controls.",
            plain_message: "No standard options. Next: show advanced",
        },
        OptionsFilter::Advanced => OptionsBody::Message {
            message: "No advanced options for this tool.",
            plain_message: "No advanced options for this tool.",
        },
        OptionsFilter::Missing => OptionsBody::Message {
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
