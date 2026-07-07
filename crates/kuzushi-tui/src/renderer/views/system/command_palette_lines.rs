use super::*;

use crate::ui_view_models::{command_palette_model, CommandPaletteModel};
use crate::{CommandPaletteFooter, CommandPaletteStatus};

pub(crate) fn command_palette_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    command_palette_model_lines(command_palette_model(app), area.width as usize)
}

fn command_palette_model_lines(model: CommandPaletteModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        palette_status_line(&model.status),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.extend(model.body_rows.into_iter().map(raw));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(palette_footer_stage_line(width, &model.footer)));
    lines.push(raw(palette_footer_keybind_line(&model.footer)));
    if let Some(prompt_module) = model.footer.prompt_module {
        lines.push(raw(format!(" kuzushi ({prompt_module})>")));
    } else {
        lines.push(raw(" kuzushi>"));
    }
    lines
}

fn palette_status_line(status: &CommandPaletteStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn palette_footer_stage_line(width: usize, footer: &CommandPaletteFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn palette_footer_keybind_line(footer: &CommandPaletteFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}
