use super::*;
use crate::ui_view_models::{health_display_model, HealthDisplayModel};
use crate::{HealthFooter, HealthStatus};

pub(crate) fn health_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    health_model_lines(health_display_model(app), area.width as usize)
}

fn health_model_lines(model: HealthDisplayModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        health_status_line(&model.status),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.extend(model.body_rows.into_iter().map(raw));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(health_footer_stage_line(width, &model.footer)));
    lines.push(raw(health_footer_keybind_line(&model.footer)));
    lines.push(raw(health_prompt_line(&model.footer)));
    lines
}

fn health_status_line(status: &HealthStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn health_footer_stage_line(width: usize, footer: &HealthFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn health_footer_keybind_line(footer: &HealthFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn health_prompt_line(footer: &HealthFooter) -> String {
    match footer.prompt_module.as_deref() {
        Some(module) => format!(" kuzushi ({module})>"),
        None => " kuzushi>".to_string(),
    }
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}
