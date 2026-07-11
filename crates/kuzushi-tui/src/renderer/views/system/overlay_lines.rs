use super::*;
use crate::ui_view_models::{
    boot_splash_model, quit_confirm_model, BootSplashModel, QuitConfirmModel,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

mod confirm_dialog;
mod keymap;
mod theme_picker;
mod update_available;

pub(crate) fn boot_splash_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    boot_splash_model_lines(boot_splash_model(app), area.width as usize)
}

pub(crate) fn quit_confirm_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    quit_confirm_model_lines(quit_confirm_model(app), area.width as usize)
}

pub(crate) fn confirm_dialog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    confirm_dialog::confirm_dialog_lines(app, area)
}

pub(crate) fn theme_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    theme_picker::theme_picker_lines(app, area)
}

pub(crate) fn keymap_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    keymap::keymap_lines(app, area)
}

pub(crate) fn update_available_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    update_available::update_available_lines(app, area)
}

pub(crate) fn render_system_overlay(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let lines = contextual_overlay_lines(app, area);
    if lines.is_empty() || area.width < 8 || area.height < 5 {
        return;
    }
    let modal = overlay_rect(area, lines.len());
    render_overlay_backdrop(frame, area);
    frame.render_widget(Clear, modal);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(
            overlay_title(app.shell_view()),
            theme::heading(),
        ));
    let inner = block.inner(modal);
    frame.render_widget(block, modal);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn contextual_overlay_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let width = area.width.saturating_sub(6).min(92);
    let body_area = Rect { width, ..area };
    let lines = match app.shell_view() {
        ShellView::Catalog => viewport_lines(
            catalog_lines(app, body_area),
            area.height.saturating_sub(4),
            app.router.modules().scroll(),
        ),
        ShellView::ConfirmDialog => confirm_dialog_lines(app, body_area),
        ShellView::QuitConfirm => quit_confirm_lines(app, body_area),
        ShellView::ThemePicker => theme_picker_lines(app, body_area),
        ShellView::Keymap => keymap_lines(app, body_area),
        ShellView::UpdateAvailable => update_available_lines(app, body_area),
        _ => return Vec::new(),
    };
    strip_full_screen_chrome(lines)
}

fn strip_full_screen_chrome(mut lines: Vec<Line<'static>>) -> Vec<Line<'static>> {
    if lines.first().is_some_and(is_status_line) {
        lines.remove(0);
        remove_leading_rule_and_blank(&mut lines);
    }
    if let Some(index) = lines.iter().rposition(is_rule_line) {
        lines.truncate(index);
    }
    while lines.last().is_some_and(is_blank_line) {
        lines.pop();
    }
    lines
}

fn remove_leading_rule_and_blank(lines: &mut Vec<Line<'static>>) {
    if lines.first().is_some_and(is_rule_line) {
        lines.remove(0);
    }
    if lines.first().is_some_and(is_blank_line) {
        lines.remove(0);
    }
}

fn is_status_line(line: &Line<'_>) -> bool {
    line_text(line).trim_start().starts_with("KUZUSHI")
}

fn is_rule_line(line: &Line<'_>) -> bool {
    let text = line_text(line);
    !text.is_empty() && text.chars().all(|ch| ch == '─')
}

fn is_blank_line(line: &Line<'_>) -> bool {
    line_text(line).trim().is_empty()
}

fn line_text(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>()
}

fn overlay_rect(area: Rect, line_count: usize) -> Rect {
    let width = area.width.saturating_sub(4).min(96);
    let requested = line_count.saturating_add(2).min(u16::MAX as usize) as u16;
    let height = requested.min(area.height.saturating_sub(2)).max(3);
    centered_rect(area, width, height)
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(area.width.saturating_sub(width) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(area);
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(area.height.saturating_sub(height) / 3),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(horizontal[1]);
    vertical[1]
}

fn overlay_title(view: ShellView) -> &'static str {
    match view {
        ShellView::Catalog => " CAPABILITIES ",
        ShellView::ConfirmDialog => " CONFIRM ",
        ShellView::QuitConfirm => " QUIT ",
        ShellView::ThemePicker => " THEME ",
        ShellView::Keymap => " KEYMAP ",
        ShellView::UpdateAvailable => " UPDATE AVAILABLE ",
        _ => " OVERLAY ",
    }
}

pub(in crate::renderer) fn overlay_header(
    app: &ShellApp,
    area: Rect,
    title: &str,
) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(title, area.width));
    lines
}

pub(in crate::renderer) fn model_status(app: &ShellApp) -> String {
    app.config()
        .model
        .clone()
        .unwrap_or_else(|| "not configured".to_string())
}

fn boot_splash_model_lines(model: BootSplashModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![raw("─".repeat(width))];
    lines.extend((0..4).map(|_| blank()));
    for art_line in boot_splash_art() {
        lines.push(centered(width, art_line));
    }
    lines.push(blank());
    lines.push(centered(
        width,
        "崩し  ·  break the form before the form breaks you",
    ));
    lines.push(blank());
    lines.push(centered(width, &model.version_line));
    lines.push(blank());
    lines.push(blank());
    lines.extend(
        model
            .checks
            .into_iter()
            .map(|check| boot_check_line(width, check)),
    );
    lines.push(blank());
    lines.push(centered(width, &model.primary_hint));
    lines.push(blank());
    lines.push(centered(width, &model.secondary_hint));
    lines
}

fn boot_splash_art() -> [&'static str; 6] {
    [
        "  ██╗  ██╗██╗   ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗",
        "  ██║ ██╔╝██║   ██║╚══███╔╝██║   ██║██╔════╝██║  ██║██║",
        "  █████╔╝ ██║   ██║  ███╔╝ ██║   ██║███████╗███████║██║",
        "  ██╔═██╗ ██║   ██║ ███╔╝  ██║   ██║╚════██║██╔══██║██║",
        "  ██║  ██╗╚██████╔╝███████╗╚██████╔╝███████║██║  ██║██║",
        "  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝",
    ]
}

fn boot_check_line(width: usize, check: BootSplashCheck) -> Line<'static> {
    let label = padded_or_full(&check.label, 28);
    let value = padded_or_full(&check.value, 40);
    let inner = format!("  {label}{value}");
    let pad = width
        .saturating_sub(inner.chars().count() + boot_state_symbol(check.state).chars().count())
        / 2;
    raw(format!(
        "{}{}{}{}",
        " ".repeat(pad),
        boot_state_symbol(check.state),
        fixed_width(&check.label, 28),
        fixed_width(&check.value, 40)
    ))
}

fn boot_state_symbol(state: BootSplashCheckState) -> &'static str {
    match state {
        BootSplashCheckState::Ok => " ✓ ",
        BootSplashCheckState::Wait => " · ",
        BootSplashCheckState::Err => " ✗ ",
    }
}

fn centered(width: usize, text: &str) -> Line<'static> {
    let pad = width.saturating_sub(text.chars().count()) / 2;
    raw(format!("{}{}", " ".repeat(pad), text))
}

fn padded_or_full(value: &str, width: usize) -> String {
    if value.chars().count() >= width {
        value.to_string()
    } else {
        format!("{value}{}", " ".repeat(width - value.chars().count()))
    }
}

fn fixed_width(value: &str, width: usize) -> String {
    let mut out = value.chars().take(width).collect::<String>();
    let fill = width.saturating_sub(out.chars().count());
    out.push_str(&" ".repeat(fill));
    out
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}

fn quit_confirm_model_lines(model: QuitConfirmModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        quit_status_line(&model.status),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.push(raw(format!(" {}  ●  Ctrl-C  ·  /quit", model.timestamp)));
    lines.push(blank());
    lines.extend(quit_warning_box(
        width,
        &model.warning_title,
        &model.warning_body,
    ));
    lines.push(blank());
    for section in model.sections {
        lines.push(quit_section_divider(width, &section.title));
        lines.extend(section.rows.into_iter().map(raw));
        lines.push(blank());
    }
    lines.push(raw(format!(
        " {}  …  {}",
        model.timestamp, model.default_line
    )));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(quit_footer_stage_line(width, &model.footer)));
    lines.push(raw(quit_footer_keybind_line(&model.footer)));
    lines.push(raw(format!(" kuzushi ({})>", model.footer.prompt_module)));
    lines
}

fn quit_status_line(status: &QuitConfirmStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn quit_warning_box(width: usize, title: &str, body: &str) -> Vec<Line<'static>> {
    let top_prefix = "   ╔══ ";
    let top_title = format!("{title} ");
    let top_fill = width.saturating_sub(top_prefix.chars().count() + top_title.chars().count() + 2);
    let body_width = width.saturating_sub(8);
    let body = format!(" {body}");
    vec![
        raw(format!("{top_prefix}{top_title}{}╗", "═".repeat(top_fill))),
        raw(format!("   ║ {} ║", fixed_width(&body, body_width))),
        raw(format!("   ╚{}╝", "═".repeat(width.saturating_sub(6)))),
    ]
}

fn quit_footer_stage_line(width: usize, footer: &QuitConfirmFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn quit_footer_keybind_line(footer: &QuitConfirmFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn quit_section_divider(width: usize, title: &str) -> Line<'static> {
    let lead = "-- ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = width.saturating_sub(used).saturating_sub(1).max(1);
    raw(format!(" {lead}{label}{}", "-".repeat(fill)))
}
