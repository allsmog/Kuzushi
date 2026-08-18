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
    let sources = config_source_inventory(app);
    let summary_rows = config_summary_rows(app, &backend, &model, reasoning, sources.as_ref());
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
    for (source_label, plain_label) in PLAIN_CONFIG_SUMMARY_LABELS {
        push_plain_config_summary_row(&mut rows, summary_rows, source_label, plain_label);
    }
    rows.extend(
        summary_rows
            .iter()
            .filter(|row| row.cells[0].starts_with("stored option "))
            .map(|row| format!("{}: {}", row.cells[0], row.cells[1])),
    );
    if summary_value(summary_rows, "onboarding").is_some() {
        rows.push(
            "onboarding: model <n> selects an explicit provider:model; no fallback model is selected."
                .to_string(),
        );
    }
    rows
}

const PLAIN_CONFIG_SUMMARY_LABELS: [(&str, &str); 15] = [
    ("backend", "runtime"),
    ("provider", "provider"),
    ("model", "model"),
    ("reasoning", "reasoning"),
    ("cost", "cost"),
    ("session budget", "session budget"),
    ("hard ceiling", "hard ceiling"),
    ("stop after", "stop after"),
    ("autonomy", "autonomy"),
    ("notifications", "notifications"),
    ("visualizations", "visualizations"),
    ("operator config", "operator config"),
    ("operator options", "operator options"),
    ("target config", "target config"),
    ("target options", "target options"),
];

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
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
) -> Vec<ConfigSummaryRow> {
    let mut rows = base_config_summary_rows(app, backend, model, reasoning, sources);
    rows.extend(policy_config_summary_rows(app, sources));
    if let Some(onboarding) = onboarding_detail(app) {
        rows.push(config_summary_row("onboarding", onboarding));
    }
    rows.extend(config_source_rows(app));
    rows.extend(stored_option_rows(app));
    rows
}

fn base_config_summary_rows(
    app: &ShellApp,
    backend: &str,
    model: &str,
    reasoning: &str,
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
) -> Vec<ConfigSummaryRow> {
    vec![
        config_summary_row("build", crate::build_provenance::build_summary()),
        config_summary_row(
            "backend",
            value_with_source(backend, config_source_label(sources, "runtime.kind")),
        ),
        config_summary_row(
            "provider",
            value_with_source(app.provider_label(), config_source_label(sources, "model")),
        ),
        config_summary_row(
            "model",
            value_with_source(model, config_source_label(sources, "model")),
        ),
        config_summary_row("reasoning", reasoning_detail(app, reasoning, sources)),
        config_summary_row("auth envs", auth_env_summary(app)),
        config_summary_row("oauth", oauth_summary()),
        config_summary_row(
            "base url",
            value_with_source(
                base_url_detail(app),
                config_source_label(sources, "runtime.base_url"),
            ),
        ),
        config_summary_row("bridge", crate::app::bridge_command_status(app.config())),
        config_summary_row("cost", cost_detail(app)),
    ]
}

fn policy_config_summary_rows(
    app: &ShellApp,
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
) -> Vec<ConfigSummaryRow> {
    vec![
        config_summary_row("session budget", session_budget_detail(app, sources)),
        config_summary_row("hard ceiling", hard_ceiling_detail(app, sources)),
        config_summary_row("stop after", stop_after_detail(app, sources)),
        config_summary_row("autonomy", autonomy_detail(app)),
        config_summary_row("notifications", notification_detail(app)),
        config_summary_row("visualizations", visualization_detail(app)),
    ]
}

fn config_source_inventory(app: &ShellApp) -> Option<kuzushi_core::config::ConfigSourceInventory> {
    let paths = kuzushi_core::ConfigPaths::from_target(app.target()).ok()?;
    kuzushi_core::config::ConfigSourceInventory::inspect(&paths).ok()
}

fn config_source_label(
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
    setting: &str,
) -> String {
    sources
        .and_then(|sources| sources.source_of(setting))
        .map(kuzushi_core::config::ConfigValueSource::label)
        .unwrap_or_else(|| "built-in default".to_string())
}

fn value_with_source(value: impl AsRef<str>, source: String) -> String {
    format!("{} · {source}", value.as_ref())
}

fn reasoning_detail(
    app: &ShellApp,
    reasoning: &str,
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
) -> String {
    let source = if app.session_thinking_level() == app.config().runtime.thinking_level.as_deref() {
        config_source_label(sources, "runtime.thinking_level")
    } else if app.session_thinking_level().is_some() {
        "session selection".to_string()
    } else {
        "model catalog default".to_string()
    };
    value_with_source(reasoning, source)
}

fn config_source_rows(app: &ShellApp) -> Vec<ConfigSummaryRow> {
    let Ok(paths) = kuzushi_core::ConfigPaths::from_target(app.target()) else {
        return Vec::new();
    };
    let mut rows = vec![
        config_summary_row(
            "operator config",
            path_source_detail(&paths.global_config_path()),
        ),
        config_summary_row(
            "operator options",
            path_source_detail(&paths.global_options_path()),
        ),
    ];
    if let Some(path) = paths.project_config_path() {
        rows.push(config_summary_row(
            "target config",
            path_source_detail(&path),
        ));
    }
    if let Some(path) = paths.project_options_path() {
        rows.push(config_summary_row(
            "target options",
            path_source_detail(&path),
        ));
    }
    rows
}

fn path_source_detail(path: &std::path::Path) -> String {
    let state = if path.is_file() { "loaded" } else { "absent" };
    format!("{} · {state}", path.display())
}

fn session_budget_detail(
    app: &ShellApp,
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
) -> String {
    let value = app
        .session()
        .session_budget_usd()
        .map(|budget| format!("${budget:.2}"))
        .unwrap_or_else(|| "not enforced".to_string());
    let source = if app.session().session_budget_usd() == app.config().operator.session_budget_usd {
        config_source_label(sources, "operator.session_budget_usd")
    } else {
        "session edit".to_string()
    };
    value_with_source(value, source)
}

fn hard_ceiling_detail(
    app: &ShellApp,
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
) -> String {
    let value = app
        .config()
        .operator
        .spend_hard_ceiling_usd
        .map(|ceiling| format!("${ceiling:.2}"))
        .unwrap_or_else(|| "not configured".to_string());
    value_with_source(
        value,
        config_source_label(sources, "operator.spend_hard_ceiling_usd"),
    )
}

fn stop_after_detail(
    app: &ShellApp,
    sources: Option<&kuzushi_core::config::ConfigSourceInventory>,
) -> String {
    let value = app
        .config()
        .phases
        .stop_after
        .map(kuzushi_core::GuidedPhase::label)
        .unwrap_or("not configured");
    value_with_source(value, config_source_label(sources, "phases.stop_after"))
}

fn stored_option_rows(app: &ShellApp) -> Vec<ConfigSummaryRow> {
    app.option_store()
        .stored_values()
        .into_iter()
        .enumerate()
        .map(|(index, (binding, name, value))| {
            config_summary_row(
                format!("stored option {}", index + 1),
                stored_option_detail(binding.scope, &binding.target, &name, &value),
            )
        })
        .collect()
}

fn stored_option_detail(
    scope: kuzushi_core::OptionScope,
    option_target: &kuzushi_core::OptionTarget,
    name: &str,
    value: &serde_json::Value,
) -> String {
    let target = match option_target {
        kuzushi_core::OptionTarget::All => "all".to_string(),
        kuzushi_core::OptionTarget::Module(module) => format!("module {module}"),
        kuzushi_core::OptionTarget::Tool(tool) => format!("tool {tool}"),
    };
    let value = if option_name_is_sensitive(name) {
        "[hidden]".to_string()
    } else {
        option_value_summary(value)
    };
    format!("{} · {target} · {name}={value}", option_scope_label(scope))
}

fn option_value_summary(value: &serde_json::Value) -> String {
    let rendered = match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    };
    if rendered.chars().count() <= 120 {
        return rendered;
    }
    format!("{}…", rendered.chars().take(119).collect::<String>())
}

fn option_name_is_sensitive(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    ["key", "token", "secret", "password", "credential", "cookie"]
        .iter()
        .any(|needle| normalized.contains(needle))
}

fn autonomy_detail(app: &ShellApp) -> String {
    let source = app
        .option_store()
        .effective_stored_value_scope("ui:preferences", crate::app::UI_AUTONOMY_OPTION)
        .map(option_scope_label)
        .unwrap_or("built-in default");
    format!(
        "{} · cap {} · {source}",
        app.autonomy().label(),
        app.autonomy_cap().label()
    )
}

fn option_scope_label(scope: kuzushi_core::OptionScope) -> &'static str {
    match scope {
        kuzushi_core::OptionScope::Global => "operator options",
        kuzushi_core::OptionScope::Workspace => "target options",
        kuzushi_core::OptionScope::Session => "session option",
    }
}

fn notification_detail(app: &ShellApp) -> String {
    let enabled = if app.ui().notify_enabled() {
        "on"
    } else {
        "off"
    };
    format!(
        "{enabled} · focus {}",
        focus_state_label(app.ui().terminal_focus())
    )
}

fn focus_state_label(state: crate::app::FocusState) -> &'static str {
    match state {
        crate::app::FocusState::Focused => "focused",
        crate::app::FocusState::Blurred => "blurred",
        crate::app::FocusState::Unknown => "unknown; desktop alerts unavailable",
    }
}

fn visualization_detail(app: &ShellApp) -> &'static str {
    if app.ui().auto_open_viz() {
        "auto-open on"
    } else {
        "auto-open off"
    }
}

fn config_summary_row(label: impl Into<String>, value: impl Into<String>) -> ConfigSummaryRow {
    ConfigSummaryRow {
        cells: [label.into(), value.into()],
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
            canonical_configured_model(app)
                .as_deref()
                .and_then(crate::app::model_choice_index_by_id)
                .and_then(|index| crate::app::model_choices().get(index))
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
    let configured = canonical_configured_model(app);
    let visible_indexes = crate::app::visible_model_choice_indexes(app.config().model.as_deref());
    let configured_index = configured
        .as_deref()
        .and_then(crate::app::model_choice_index_by_id);
    let mut rows = explicit_configured_model_row(app, configured.as_deref(), configured_index);
    rows.extend(visible_indexes.into_iter().filter_map(|index| {
        let choice = crate::app::model_choices().get(index)?;
        Some(ConfigModelRow {
            cells: [
                selected_marker(Some(index) == configured_index).to_string(),
                choice.index.to_string(),
                crate::app::model_choice_display_selector(choice),
                choice.thinking_level.to_string(),
                model_auth_status(choice),
            ],
        })
    }));
    rows
}

fn canonical_configured_model(app: &ShellApp) -> Option<String> {
    app.config().model.as_deref().map(|model| {
        kuzushi_core::runtime::canonical_model_spec(model)
            .unwrap_or_else(|_| model.trim().to_string())
    })
}

fn explicit_configured_model_row(
    app: &ShellApp,
    configured: Option<&str>,
    configured_index: Option<usize>,
) -> Vec<ConfigModelRow> {
    let Some(model) = configured.filter(|_| configured_index.is_none()) else {
        return Vec::new();
    };
    vec![ConfigModelRow {
        cells: [
            ">".to_string(),
            "explicit".to_string(),
            crate::app::display_model_selector(model),
            app.session_thinking_level()
                .unwrap_or("configured")
                .to_string(),
            explicit_model_auth_status(app, model),
        ],
    }]
}

fn explicit_model_auth_status(app: &ShellApp, model: &str) -> String {
    let supported = model
        .split_once(':')
        .and_then(|(provider, _)| crate::app::AuthProvider::from_scene_provider(provider));
    supported
        .map(|_| {
            super::configured_model_credential_readiness(app)
                .label()
                .to_string()
        })
        .unwrap_or_else(|| "unsupported provider".to_string())
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
