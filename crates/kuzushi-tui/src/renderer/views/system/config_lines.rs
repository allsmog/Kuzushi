use super::*;
use crate::ui_view_models::{config_model, ConfigModel, ConfigModelRow};

pub(crate) fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = config_model(app);
    push_config_summary(&mut lines, &model, area);
    push_config_model_table(&mut lines, &model, area);
    push_config_commands(&mut lines, area);
    lines
}

fn push_config_summary(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(divider("CONFIG", area.width));
    lines.push(detail("backend", &model.backend));
    lines.push(detail("provider", &model.provider));
    lines.push(detail("model", &model.model));
    lines.push(detail("reasoning", &model.reasoning));
    lines.push(detail("auth envs", &model.auth_envs));
    lines.push(detail("oauth", &model.oauth));
    lines.push(detail("base url", &model.base_url));
    lines.push(detail("bridge", &model.bridge));
    lines.push(detail("cost", &model.cost));
    if let Some(onboarding) = &model.onboarding {
        lines.push(detail("onboarding", onboarding));
    }
}

fn push_config_model_table(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(divider("MODELS", area.width));
    let widths = config_model_widths(area);
    lines.push(aligned_header(
        &["", "#", "model", "effort", "auth"],
        &widths,
    ));
    for row in &model.model_rows {
        lines.push(config_model_row(row, &widths));
    }
}

fn config_model_widths(area: Rect) -> [usize; 5] {
    [2usize, 2, 28, 6, value_width(area, 28)]
}

fn config_model_row(row: &ConfigModelRow, widths: &[usize]) -> Line<'static> {
    let marker = if row.selected { ">" } else { " " };
    aligned_row(
        &[
            marker.to_string(),
            row.index.clone(),
            row.model.clone(),
            row.effort.clone(),
            row.auth.clone(),
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
