use super::{auth_env_summary, model_auth_status, oauth_summary};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigModel {
    pub(crate) backend: String,
    pub(crate) model: String,
    pub(crate) reasoning: String,
    pub(crate) reasoning_override: Option<String>,
    pub(crate) summary_title: &'static str,
    pub(crate) summary_rows: Vec<ConfigSummaryRow>,
    pub(crate) model_table: ConfigModelTable,
    pub(crate) commands: [&'static str; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigSummaryRow {
    pub(crate) cells: [String; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigModelRow {
    pub(crate) cells: [String; 5],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigModelTable {
    pub(crate) title: &'static str,
    pub(crate) headers: [&'static str; 5],
    pub(crate) rows: Vec<ConfigModelRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainConfigModel {
    pub(crate) summary_title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) model_table: PlainConfigModelTable,
    pub(crate) next_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainConfigModelTable {
    pub(crate) title: &'static str,
    pub(crate) headers: [&'static str; 4],
    pub(crate) rows: Vec<PlainConfigModelRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainConfigModelRow {
    pub(crate) cells: [String; 4],
}

pub(crate) fn config_model(app: &ShellApp) -> ConfigModel {
    let backend = crate::app::runtime_backend_label(app.config()).to_string();
    let model = active_model_label(app);
    let reasoning_override = app.session_thinking_level_owned();
    let reasoning = active_reasoning_label(app);
    let summary_rows = config_summary_rows(app, &backend, &model, reasoning);
    ConfigModel {
        backend,
        model,
        reasoning: reasoning.to_string(),
        reasoning_override,
        summary_title: "CONFIG",
        summary_rows,
        model_table: ConfigModelTable {
            title: "MODELS",
            headers: ["", "#", "model", "effort", "auth"],
            rows: config_model_rows(app),
        },
        commands: [
            "Up/Down select",
            "Enter choose",
            "model <n> [xhigh]",
            "auth login openai|anthropic",
        ],
    }
}

pub(crate) fn plain_config_model(app: &ShellApp) -> PlainConfigModel {
    PlainConfigModel::from_config_model(config_model(app))
}

impl PlainConfigModel {
    fn from_config_model(model: ConfigModel) -> Self {
        let ConfigModel {
            summary_title,
            summary_rows,
            model_table,
            ..
        } = model;
        PlainConfigModel {
            summary_title,
            summary_rows: plain_config_summary_rows(&summary_rows),
            model_table: PlainConfigModelTable {
                title: model_table.title,
                headers: plain_config_model_headers(model_table.headers),
                rows: plain_config_model_rows(model_table.rows),
            },
            next_hint: "Next: model <n> [xhigh], auth login openai, auth login anthropic, cost",
        }
    }
}

fn plain_config_summary_rows(summary_rows: &[ConfigSummaryRow]) -> Vec<String> {
    let mut rows = Vec::new();
    push_plain_config_summary_row(&mut rows, summary_rows, "backend", "runtime");
    push_plain_config_summary_row(&mut rows, summary_rows, "provider", "provider");
    push_plain_config_summary_row(&mut rows, summary_rows, "model", "model");
    push_plain_config_summary_row(&mut rows, summary_rows, "reasoning", "reasoning");
    push_plain_config_summary_row(&mut rows, summary_rows, "cost", "cost");
    if summary_value(summary_rows, "onboarding").is_some() {
        rows.push(
            "onboarding: model <n> selects an explicit provider:model; no fallback model is selected."
                .to_string(),
        );
    }
    rows
}

fn push_plain_config_summary_row(
    rows: &mut Vec<String>,
    summary_rows: &[ConfigSummaryRow],
    source_label: &str,
    plain_label: &str,
) {
    if let Some(value) = summary_value(summary_rows, source_label) {
        rows.push(format!("{plain_label}: {value}"));
    }
}

fn summary_value<'a>(summary_rows: &'a [ConfigSummaryRow], label: &str) -> Option<&'a str> {
    summary_rows
        .iter()
        .find(|row| row.cells[0] == label)
        .map(|row| row.cells[1].as_str())
}

fn plain_config_model_rows(rows: Vec<ConfigModelRow>) -> Vec<PlainConfigModelRow> {
    rows.into_iter()
        .map(|row| {
            let [_marker, index, model, effort, auth] = row.cells;
            PlainConfigModelRow {
                cells: [index, model, effort, auth],
            }
        })
        .collect()
}

fn plain_config_model_headers(headers: [&'static str; 5]) -> [&'static str; 4] {
    [headers[1], headers[2], headers[3], headers[4]]
}

fn config_summary_rows(
    app: &ShellApp,
    backend: &str,
    model: &str,
    reasoning: &str,
) -> Vec<ConfigSummaryRow> {
    let mut rows = vec![
        // Which binary is this? Published release and working-tree builds
        // share a version string; the sha/dirty/profile cell tells them apart.
        config_summary_row("build", crate::build_provenance::build_summary()),
        config_summary_row("backend", backend),
        config_summary_row("provider", app.provider_label()),
        config_summary_row("model", model),
        config_summary_row("reasoning", reasoning),
        config_summary_row("auth envs", auth_env_summary(app)),
        config_summary_row("oauth", oauth_summary()),
        config_summary_row("base url", base_url_detail(app)),
        config_summary_row("bridge", crate::app::bridge_command_status(app.config())),
        config_summary_row("cost", cost_detail(app)),
    ];
    if let Some(onboarding) = onboarding_detail(app) {
        rows.push(config_summary_row("onboarding", onboarding));
    }
    rows
}

fn config_summary_row(label: &'static str, value: impl Into<String>) -> ConfigSummaryRow {
    ConfigSummaryRow {
        cells: [label.to_string(), value.into()],
    }
}

fn active_model_label(app: &ShellApp) -> String {
    app.config()
        .model
        .as_deref()
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string())
}

fn active_reasoning_label(app: &ShellApp) -> &str {
    app.session_thinking_level()
        .or_else(|| {
            crate::app::model_choices()
                .get(app.router.model_catalog().selected_index())
                .map(|choice| choice.thinking_level)
        })
        .unwrap_or("default")
}

fn base_url_detail(app: &ShellApp) -> String {
    app.config()
        .runtime
        .base_url
        .as_deref()
        .unwrap_or("provider default")
        .to_string()
}

fn cost_detail(app: &ShellApp) -> String {
    let session = app.session();
    if let Some(last) = session.last_tool_cost_report() {
        if session.cost_accounting_is_complete() && last.is_complete() {
            return format!(
                "session ${:.4}; last tool ${:.4}",
                session.session_cost_usd(),
                last.observed_usd()
            );
        }
        format!(
            "session {}; last tool {}",
            super::format_runtime_cost(
                session.session_cost_report(),
                session.cost_accounting_error()
            ),
            super::format_runtime_cost(last, session.cost_accounting_error())
        )
    } else {
        "unavailable until a tool reports costUsd".to_string()
    }
}

fn onboarding_detail(app: &ShellApp) -> Option<String> {
    app.config().model.is_none().then(|| {
        "Up/Down selects a model; Enter activates it. OAuth availability is shown below."
            .to_string()
    })
}

fn config_model_rows(app: &ShellApp) -> Vec<ConfigModelRow> {
    let visible_indexes = crate::app::visible_model_choice_indexes(app.config().model.as_deref());
    let selected_index = visible_selected_model_index(
        &visible_indexes,
        app.router.model_catalog().selected_index(),
    );
    visible_indexes
        .into_iter()
        .filter_map(|index| {
            let choice = crate::app::model_choices().get(index)?;
            Some(ConfigModelRow {
                cells: [
                    selected_marker(index == selected_index).to_string(),
                    choice.index.to_string(),
                    crate::app::model_choice_display_selector(choice),
                    choice.thinking_level.to_string(),
                    model_auth_status(choice),
                ],
            })
        })
        .collect()
}

fn visible_selected_model_index(visible_indexes: &[usize], selected_model_index: usize) -> usize {
    if visible_indexes.contains(&selected_model_index) {
        return selected_model_index;
    }
    visible_indexes
        .first()
        .copied()
        .unwrap_or(selected_model_index)
}

fn selected_marker(selected: bool) -> &'static str {
    if selected {
        ">"
    } else {
        " "
    }
}

#[cfg(test)]
mod tests;
