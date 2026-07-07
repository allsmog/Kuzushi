use super::{blank, raw};
use crate::ui_view_models::{keymap_model, KeymapModel};
use crate::{KeymapBindingRow, KeymapFooter, KeymapSection, KeymapStatus, ShellApp};
use ratatui::layout::Rect;
use ratatui::text::Line;

pub(crate) fn keymap_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    keymap_model_lines(keymap_model(app), area.width as usize)
}

fn keymap_model_lines(model: KeymapModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        keymap_status_line(&model.status),
        raw("─".repeat(width)),
        blank(),
        raw(format!(" {}  ●  /help or ?", model.event_time)),
        blank(),
    ];
    push_keymap_sections(&mut lines, width, model.sections);
    lines.push(blank());
    lines.push(raw(format!("   {}", model.note)));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(keymap_footer_stage_line(width, &model.footer)));
    lines.push(raw(keymap_footer_keybind_line(&model.footer)));
    lines.push(raw(format!(" kuzushi ({})>", model.footer.prompt_module)));
    lines
}

fn push_keymap_sections(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    sections: Vec<KeymapSection>,
) {
    for (index, section) in sections.into_iter().enumerate() {
        if index > 0 {
            lines.push(blank());
        }
        lines.push(keymap_section_divider(width, &section.name, &section.blurb));
        lines.extend(section.rows.into_iter().map(keymap_binding_line));
    }
}

fn keymap_status_line(status: &KeymapStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn keymap_section_divider(width: usize, name: &str, blurb: &str) -> Line<'static> {
    let prefix = format!(" ── {name} {blurb} ");
    let fill = width
        .saturating_sub(prefix.chars().count())
        .saturating_sub(1);
    raw(format!("{prefix}{}", "─".repeat(fill.max(1))))
}

fn keymap_binding_line(row: KeymapBindingRow) -> Line<'static> {
    raw(format!(" {:<18} {}", fixed_key_cell(&row.keys), row.action))
}

fn fixed_key_cell(keys: &str) -> String {
    keys.chars().take(18).collect()
}

fn keymap_footer_stage_line(width: usize, footer: &KeymapFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn keymap_footer_keybind_line(footer: &KeymapFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}
