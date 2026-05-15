use super::*;
use crate::ui_view_models::{auth_env_summary, model_auth_status, oauth_summary};

pub(crate) fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    push_config_summary(&mut lines, app, area);
    push_config_model_table(&mut lines, app, area);
    push_config_commands(&mut lines, area);
    lines
}

fn push_config_summary(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    lines.push(blank());
    lines.push(divider("CONFIG", area.width));
    lines.push(detail(
        "backend",
        crate::app::runtime_backend_label(&app.config),
    ));
    lines.push(detail("provider", &app.provider_label()));
    lines.push(detail(
        "model",
        &app.config
            .model
            .as_deref()
            .map(crate::app::display_model_selector)
            .unwrap_or_else(|| "unconfigured".to_string()),
    ));
    lines.push(detail(
        "reasoning",
        app.session_thinking_level.as_deref().unwrap_or("default"),
    ));
    lines.push(detail("auth envs", &auth_env_summary(app)));
    lines.push(detail("oauth", &oauth_summary()));
    lines.push(detail("base url", base_url_detail(app)));
    lines.push(detail(
        "bridge",
        crate::app::bridge_command_status(&app.config),
    ));
    lines.push(detail("cost", &cost_detail(app)));
    if app.config.model.is_none() {
        lines.push(detail(
            "onboarding",
            "Up/Down selects a model; Enter activates it. OAuth availability is shown below.",
        ));
    }
}

fn base_url_detail(app: &ShellApp) -> &str {
    app.config
        .runtime
        .base_url
        .as_deref()
        .unwrap_or("provider default")
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

fn push_config_model_table(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    lines.push(blank());
    lines.push(divider("MODELS", area.width));
    let widths = config_model_widths(area);
    lines.push(aligned_header(
        &["", "#", "model", "effort", "auth"],
        &widths,
    ));
    for (index, choice) in crate::app::model_choices().iter().enumerate() {
        lines.push(config_model_row(
            index,
            app.selected_model_index,
            choice,
            &widths,
        ));
    }
}

fn config_model_widths(area: Rect) -> [usize; 5] {
    [2usize, 2, 28, 6, value_width(area, 28)]
}

fn config_model_row(
    index: usize,
    selected_model_index: usize,
    choice: &crate::app::ModelChoice,
    widths: &[usize],
) -> Line<'static> {
    let marker = if index == selected_model_index {
        ">"
    } else {
        " "
    };
    aligned_row(
        &[
            marker.to_string(),
            choice.index.to_string(),
            crate::app::model_choice_display_selector(choice),
            choice.thinking_level.to_string(),
            model_auth_status(choice),
        ],
        widths,
    )
}

fn push_config_commands(lines: &mut Vec<Line<'static>>, area: Rect) {
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "Up/Down select",
            "Enter choose",
            "model <n> [xhigh]",
            "auth login openai|anthropic",
        ],
        area.width as usize,
    ));
}
