use super::{blank, raw};
use crate::ui_view_models::{theme_picker_model, ThemePickerModel};
use crate::{ShellApp, ThemePaletteRow, ThemePickerFooter, ThemePickerStatus};
use ratatui::layout::Rect;
use ratatui::text::Line;

pub(crate) fn theme_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    theme_picker_model_lines(theme_picker_model(app), area.width as usize)
}

fn theme_picker_model_lines(model: ThemePickerModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = theme_header_lines(&model, width);
    push_theme_palette_lines(&mut lines, model.palettes, model.selected_palette);
    push_theme_preview_lines(&mut lines, width, model.preview_title, model.preview_rows);
    push_theme_accessibility_lines(&mut lines, width, model.accessibility_rows);
    push_theme_custom_lines(&mut lines, width, model.custom_rows);
    lines.push(blank());
    lines.push(raw(format!(" {}  …  {}", model.flow_time, model.flow_hint)));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(theme_footer_stage_line(width, &model.footer)));
    lines.push(raw(theme_footer_keybind_line(&model.footer)));
    lines.push(raw(format!(" kuzushi ({})>", model.footer.prompt_module)));
    lines
}

fn theme_header_lines(model: &ThemePickerModel, width: usize) -> Vec<Line<'static>> {
    vec![
        theme_status_line(&model.status),
        raw("─".repeat(width)),
        blank(),
        raw(format!(" {}  ●  /setg theme", model.event_time)),
        raw(format!(
            "  current {}  ·  reads system pref {}  ·  per-tty override {}",
            model.current_theme, model.source_hint, model.tty_override_hint
        )),
        blank(),
        theme_section_divider(
            width,
            &format!("THEMES · {} built-in", model.palettes.len()),
        ),
    ]
}

fn push_theme_palette_lines(
    lines: &mut Vec<Line<'static>>,
    palettes: Vec<ThemePaletteRow>,
    selected_palette: usize,
) {
    lines.extend(
        palettes
            .into_iter()
            .enumerate()
            .map(|(index, palette)| theme_palette_line(palette, index == selected_palette)),
    );
}

fn push_theme_preview_lines(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    title: String,
    rows: Vec<String>,
) {
    lines.push(blank());
    lines.push(theme_section_divider(width, &format!("PREVIEW · {title}")));
    lines.extend(rows.into_iter().map(raw));
}

fn push_theme_accessibility_lines(lines: &mut Vec<Line<'static>>, width: usize, rows: Vec<String>) {
    lines.push(blank());
    lines.push(theme_section_divider(
        width,
        "ACCESSIBILITY · A11y guarantees per theme",
    ));
    lines.extend(rows.into_iter().map(theme_detail_row));
}

fn push_theme_custom_lines(lines: &mut Vec<Line<'static>>, width: usize, rows: Vec<String>) {
    lines.push(blank());
    lines.push(theme_section_divider(width, "CUSTOM"));
    lines.extend(rows.into_iter().map(raw));
}

fn theme_status_line(status: &ThemePickerStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn theme_palette_line(palette: ThemePaletteRow, selected: bool) -> Line<'static> {
    if selected {
        return raw(format!(
            "  ▌ {:<18}  {}  {}  {}  {}   {}",
            theme_palette_name(&palette.name),
            palette.background,
            palette.foreground,
            palette.accent,
            palette.severity,
            palette.blurb
        ));
    }
    raw(format!(
        "    {:<18}    {}   {}   {}   {}  {}",
        theme_palette_name(&palette.name),
        palette.background,
        palette.foreground,
        palette.accent,
        palette.severity,
        palette.blurb
    ))
}

fn theme_palette_name(name: &str) -> String {
    name.chars().take(18).collect()
}

fn theme_detail_row(row: String) -> Line<'static> {
    raw(format!("    {row}"))
}

fn theme_section_divider(width: usize, title: &str) -> Line<'static> {
    let lead = "── ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = width.saturating_sub(used).saturating_sub(1).max(1);
    raw(format!(" {lead}{label}{}", "─".repeat(fill)))
}

fn theme_footer_stage_line(width: usize, footer: &ThemePickerFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn theme_footer_keybind_line(footer: &ThemePickerFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}
