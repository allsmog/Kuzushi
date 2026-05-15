use super::{auth_env_summary, model_auth_status, oauth_summary};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigModel {
    pub(crate) backend: String,
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) reasoning: String,
    pub(crate) reasoning_override: Option<String>,
    pub(crate) auth_envs: String,
    pub(crate) oauth: String,
    pub(crate) base_url: String,
    pub(crate) bridge: String,
    pub(crate) cost: String,
    pub(crate) onboarding: Option<String>,
    pub(crate) model_rows: Vec<ConfigModelRow>,
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
    ConfigModel {
        backend: crate::app::runtime_backend_label(&app.config).to_string(),
        provider: app.provider_label(),
        model: active_model_label(app),
        reasoning: app
            .session_thinking_level
            .as_deref()
            .unwrap_or("default")
            .to_string(),
        reasoning_override: app.session_thinking_level.clone(),
        auth_envs: auth_env_summary(app),
        oauth: oauth_summary(),
        base_url: base_url_detail(app),
        bridge: crate::app::bridge_command_status(&app.config).to_string(),
        cost: cost_detail(app),
        onboarding: onboarding_detail(app),
        model_rows: config_model_rows(app),
    }
}

pub(crate) fn plain_config_model(app: &ShellApp) -> PlainConfigModel {
    PlainConfigModel::from_config_model(config_model(app))
}

impl PlainConfigModel {
    fn from_config_model(model: ConfigModel) -> Self {
        PlainConfigModel {
            summary_title: "CONFIG",
            summary_rows: plain_config_summary_rows(&model),
            model_table: PlainConfigModelTable {
                title: "MODELS",
                headers: ["#", "model", "effort", "auth"],
                rows: plain_config_model_rows(model.model_rows),
            },
            next_hint: "Next: model <n> [xhigh], auth login openai, auth login anthropic, cost",
        }
    }
}

fn plain_config_summary_rows(model: &ConfigModel) -> Vec<String> {
    let mut rows = vec![
        format!("runtime: {}", model.backend),
        format!("provider: {}", model.provider),
        format!("model: {}", model.model),
        format!("reasoning: {}", model.reasoning),
        format!("cost: {}", model.cost),
    ];
    if model.onboarding.is_some() {
        rows.push(
            "onboarding: model <n> selects an explicit provider:model; no fallback model is selected."
                .to_string(),
        );
    }
    rows
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
