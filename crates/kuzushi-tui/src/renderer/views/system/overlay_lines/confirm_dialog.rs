use super::raw;
use crate::ui_view_models::{confirm_dialog_model, ConfirmDialogModel};
use crate::{ConfirmDialogFooter, ConfirmDialogStatus, ShellApp};
use ratatui::layout::Rect;
use ratatui::text::Line;

pub(crate) fn confirm_dialog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    confirm_dialog_model_lines(confirm_dialog_model(app), area.width as usize)
}

fn confirm_dialog_model_lines(model: ConfirmDialogModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![confirm_status_line(&model.status), raw("─".repeat(width))];
    lines.push(raw(String::new()));
    lines.extend(model.body_rows.into_iter().map(raw));
    lines.push(raw(String::new()));
    lines.push(raw("─".repeat(width)));
    lines.push(raw(confirm_footer_stage_line(width, &model.footer)));
    lines.push(raw(confirm_footer_keybind_line(&model.footer)));
    if let Some(prompt_module) = model.footer.prompt_module {
        lines.push(raw(format!(" kuzushi ({prompt_module})>")));
    } else {
        lines.push(raw(" kuzushi>"));
    }
    lines
}

fn confirm_status_line(status: &ConfirmDialogStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn confirm_footer_stage_line(width: usize, footer: &ConfirmDialogFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn confirm_footer_keybind_line(footer: &ConfirmDialogFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}
