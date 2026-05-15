use super::{auth_env_summary, model_auth_status, oauth_summary};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigModel {
    pub(crate) backend: String,
    pub(crate) model: String,
    pub(crate) reasoning_override: Option<String>,
    pub(crate) summary_title: &'static str,
    pub(crate) summary_rows: Vec<ConfigSummaryRow>,
    pub(crate) model_rows: Vec<ConfigModelRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigSummaryRow {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigModelRow {
    pub(crate) selected: bool,
    pub(crate) index: String,
    pub(crate) model: String,
    pub(crate) effort: String,
    pub(crate) auth: String,
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
    pub(crate) index: String,
    pub(crate) model: String,
    pub(crate) effort: String,
    pub(crate) auth: String,
}

pub(crate) fn config_model(app: &ShellApp) -> ConfigModel {
    let backend = crate::app::runtime_backend_label(&app.config).to_string();
    let model = active_model_label(app);
    let reasoning_override = app.session_thinking_level.clone();
    let reasoning = reasoning_override.as_deref().unwrap_or("default");
    let summary_rows = config_summary_rows(app, &backend, &model, reasoning);
    ConfigModel {
        backend,
        model,
        reasoning_override,
        summary_title: "CONFIG",
        summary_rows,
        model_rows: config_model_rows(app),
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
            model_rows,
            ..
        } = model;
        PlainConfigModel {
            summary_title,
            summary_rows: plain_config_summary_rows(&summary_rows),
            model_table: PlainConfigModelTable {
                title: "MODELS",
                headers: ["#", "model", "effort", "auth"],
                rows: plain_config_model_rows(model_rows),
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
        .find(|row| row.label == label)
        .map(|row| row.value.as_str())
}

fn plain_config_model_rows(rows: Vec<ConfigModelRow>) -> Vec<PlainConfigModelRow> {
    rows.into_iter()
        .map(|row| PlainConfigModelRow {
            index: row.index,
            model: row.model,
            effort: row.effort,
            auth: row.auth,
        })
        .collect()
}

fn config_summary_rows(
    app: &ShellApp,
    backend: &str,
    model: &str,
    reasoning: &str,
) -> Vec<ConfigSummaryRow> {
    let mut rows = vec![
        config_summary_row("backend", backend),
        config_summary_row("provider", app.provider_label()),
        config_summary_row("model", model),
        config_summary_row("reasoning", reasoning),
        config_summary_row("auth envs", auth_env_summary(app)),
        config_summary_row("oauth", oauth_summary()),
        config_summary_row("base url", base_url_detail(app)),
        config_summary_row("bridge", crate::app::bridge_command_status(&app.config)),
        config_summary_row("cost", cost_detail(app)),
    ];
    if let Some(onboarding) = onboarding_detail(app) {
        rows.push(config_summary_row("onboarding", onboarding));
    }
    rows
}

fn config_summary_row(label: &'static str, value: impl Into<String>) -> ConfigSummaryRow {
    ConfigSummaryRow {
        label,
        value: value.into(),
    }
}

fn active_model_label(app: &ShellApp) -> String {
    app.config
        .model
        .as_deref()
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string())
}

fn base_url_detail(app: &ShellApp) -> String {
    app.config
        .runtime
        .base_url
        .as_deref()
        .unwrap_or("provider default")
        .to_string()
}

fn cost_detail(app: &ShellApp) -> String {
    if let Some(last) = app.last_tool_cost_usd {
        format!(
            "session ${:.4}; last tool ${:.4}",
            app.session_cost_usd, last
        )
    } else {
        "unavailable until a tool reports costUsd".to_string()
    }
}

fn onboarding_detail(app: &ShellApp) -> Option<String> {
    app.config.model.is_none().then(|| {
        "Up/Down selects a model; Enter activates it. OAuth availability is shown below."
            .to_string()
    })
}

fn config_model_rows(app: &ShellApp) -> Vec<ConfigModelRow> {
    crate::app::model_choices()
        .iter()
        .enumerate()
        .map(|(index, choice)| ConfigModelRow {
            selected: index == app.selected_model_index,
            index: choice.index.to_string(),
            model: crate::app::model_choice_display_selector(choice),
            effort: choice.thinking_level.to_string(),
            auth: model_auth_status(choice),
        })
        .collect()
}

#[cfg(test)]
mod tests;
