use super::*;

pub(crate) fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("CONFIG", area.width));
    lines.push(detail(
        "backend",
        crate::app::runtime_backend_label(&app.config),
    ));
    lines.push(detail("provider", &app.provider_label()));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(detail(
        "reasoning",
        app.session_thinking_level.as_deref().unwrap_or("default"),
    ));
    let auth_status = if std::env::var_os(&app.config.runtime.api_key_env).is_some() {
        "set; value hidden"
    } else {
        "missing"
    };
    lines.push(detail(
        "auth envs",
        &format!(
            "{} ({auth_status}); ANTHROPIC_API_KEY ({})",
            app.config.runtime.api_key_env,
            if std::env::var_os("ANTHROPIC_API_KEY").is_some() {
                "set; value hidden"
            } else {
                "missing"
            }
        ),
    ));
    lines.push(detail(
        "oauth",
        &format!(
            "openai-codex {}; anthropic {}",
            crate::app::oauth_provider_status("openai-codex"),
            crate::app::oauth_provider_status("anthropic")
        ),
    ));
    lines.push(detail(
        "base url",
        app.config
            .runtime
            .base_url
            .as_deref()
            .unwrap_or("provider default"),
    ));
    lines.push(detail(
        "bridge",
        crate::app::bridge_command_status(&app.config),
    ));
    lines.push(detail(
        "cost",
        &if let Some(last) = app.last_tool_cost_usd {
            format!(
                "session ${:.4}; last tool ${:.4}",
                app.session_cost_usd, last
            )
        } else {
            "unavailable until a tool reports costUsd".to_string()
        },
    ));
    if app.config.model.is_none() {
        lines.push(detail(
            "onboarding",
            "Up/Down selects a model; Enter activates it. OAuth availability is shown below.",
        ));
    }
    lines.push(blank());
    lines.push(divider("MODELS", area.width));
    let widths = [2usize, 2, 28, 6, value_width(area, 28)];
    lines.push(aligned_header(
        &["", "#", "model", "effort", "auth"],
        &widths,
    ));
    for (index, choice) in crate::app::model_choices().iter().enumerate() {
        let marker = if index == app.selected_model_index {
            ">"
        } else {
            " "
        };
        lines.push(aligned_row(
            &[
                marker.to_string(),
                choice.index.to_string(),
                choice.id.to_string(),
                choice.thinking_level.to_string(),
                model_auth_status(choice),
            ],
            &widths,
        ));
    }
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "Up/Down select",
            "Enter choose",
            "model <n> [xhigh]",
            "auth login openai-codex|anthropic",
        ],
        area.width as usize,
    ));
    lines
}
