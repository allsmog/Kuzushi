use super::*;
use crate::ui_view_models::{
    boot_splash_model, catalog_model, quit_confirm_model, update_available_model, BootSplashModel,
    QuitConfirmModel,
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
    let overlay_area = system_overlay_area(area, app.shell_view());
    let lines = contextual_overlay_lines(app, overlay_area);
    if lines.is_empty() || overlay_area.width < 8 || overlay_area.height < 3 {
        return;
    }
    let modal = overlay_rect(overlay_area, lines.len());
    render_system_overlay_backdrop(frame, area, app.shell_view());
    frame.render_widget(Clear, modal);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(overlay_title(app), theme::heading()));
    let inner = block.inner(modal);
    frame.render_widget(block, modal);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn system_overlay_area(area: Rect, view: ShellView) -> Rect {
    if view == ShellView::Catalog {
        area
    } else {
        overlay_body_area(area)
    }
}

fn render_system_overlay_backdrop(frame: &mut Frame<'_>, area: Rect, view: ShellView) {
    if view == ShellView::Catalog {
        frame.render_widget(Clear, area);
        return;
    }
    render_overlay_backdrop(frame, area);
}

fn contextual_overlay_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let width = area.width.saturating_sub(6).min(92);
    let body_area = Rect { width, ..area };
    let lines = match app.shell_view() {
        ShellView::Catalog => return catalog_overlay_lines(app, body_area),
        ShellView::ConfirmDialog => confirm_dialog_lines(app, body_area),
        ShellView::QuitConfirm => quit_confirm_lines(app, body_area),
        ShellView::ThemePicker => theme_picker_lines(app, body_area),
        ShellView::Keymap => keymap_lines(app, body_area),
        ShellView::Help => help_lines(app, body_area),
        ShellView::UpdateAvailable => update_available_lines(app, body_area),
        _ => return Vec::new(),
    };
    let lines = strip_full_screen_chrome(lines);
    if matches!(app.shell_view(), ShellView::Keymap | ShellView::Help) {
        return keymap_overlay_viewport(lines, area, app.router.default_scroll().offset() as usize);
    }
    lines
}

/// The Catalog is a contextual action picker, not a document. Keep its fixed
/// context separate from the cursor-windowed rows so short terminals never
/// scroll the selected action behind the header rails.
fn catalog_overlay_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let capacity = usize::from(area.height.saturating_sub(4));
    if capacity == 0 {
        return Vec::new();
    }
    let model = catalog_model(app);
    let rows = catalog_overlay_rows(&model);
    if rows.is_empty() {
        return strip_full_screen_chrome(catalog_lines(app, area));
    }
    let cursor = app
        .router
        .catalog()
        .cursor()
        .min(rows.len().saturating_sub(1));
    let width = area.width as usize;
    if capacity <= 3 {
        return compact_catalog_overlay_lines(&model, &rows, cursor, width, capacity);
    }
    windowed_catalog_overlay_lines(&model, &rows, cursor, width, capacity)
}

fn catalog_overlay_rows(model: &crate::ui_view_models::CatalogModel) -> Vec<&[String; 2]> {
    model
        .groups
        .iter()
        .flat_map(|group| group.rows.iter().map(|row| &row.cells))
        .collect()
}

fn compact_catalog_overlay_lines(
    model: &crate::ui_view_models::CatalogModel,
    rows: &[&[String; 2]],
    cursor: usize,
    width: usize,
    capacity: usize,
) -> Vec<Line<'static>> {
    let selected = compact_catalog_action_line(rows[cursor], cursor, rows.len(), width);
    if capacity == 1 {
        return vec![selected];
    }
    let mut lines = vec![catalog_overlay_header(model, width)];
    if capacity == 3 {
        lines.push(catalog_overlay_warning(model, width));
    }
    lines.push(selected);
    lines
}

fn windowed_catalog_overlay_lines(
    model: &crate::ui_view_models::CatalogModel,
    rows: &[&[String; 2]],
    cursor: usize,
    width: usize,
    capacity: usize,
) -> Vec<Line<'static>> {
    let row_capacity = capacity.saturating_sub(3).max(1).min(rows.len());
    let start = viewport_start_for_cursor(rows.len(), row_capacity, cursor);
    let end = start.saturating_add(row_capacity).min(rows.len());
    let mut lines = vec![
        catalog_overlay_header(model, width),
        catalog_overlay_warning(model, width),
        Line::styled(
            fit(
                &format!(
                    "ACTIONS {}-{}/{} · selected {}/{}",
                    start + 1,
                    end,
                    rows.len(),
                    cursor + 1,
                    rows.len()
                ),
                width,
            ),
            theme::muted(),
        ),
    ];
    lines.extend(
        rows[start..end]
            .iter()
            .enumerate()
            .map(|(offset, row)| catalog_overlay_action_line(row, start + offset == cursor, width)),
    );
    lines
}

fn catalog_overlay_header(
    model: &crate::ui_view_models::CatalogModel,
    width: usize,
) -> Line<'static> {
    let expert = if model.expanded { " · expert" } else { "" };
    Line::styled(
        fit(
            &format!(
                "{} · {} actions{expert}",
                model.phase_label, model.module_count
            ),
            width,
        ),
        theme::heading(),
    )
}

fn catalog_overlay_warning(
    model: &crate::ui_view_models::CatalogModel,
    width: usize,
) -> Line<'static> {
    let warning = model
        .collapsed
        .target_warning
        .unwrap_or("Phase-native actions first · e shows expert engines");
    Line::styled(fit(warning, width), theme::muted())
}

fn compact_catalog_action_line(
    cells: &[String; 2],
    cursor: usize,
    total: usize,
    width: usize,
) -> Line<'static> {
    let prefix = format!("▸ {}/{} ", cursor + 1, total);
    let label = cells[0].as_str();
    let description = cells[1].as_str();
    let mut body = format!("{prefix}{label}");
    let remaining = width.saturating_sub(display_width(&body));
    if remaining > 4 {
        body.push_str(" — ");
        body.push_str(&fit(description, remaining.saturating_sub(3)));
    }
    Line::styled(fit(&body, width), theme::selection())
}

fn catalog_overlay_action_line(cells: &[String; 2], selected: bool, width: usize) -> Line<'static> {
    let marker = if selected { "▸ " } else { "  " };
    let content_width = width.saturating_sub(display_width(marker));
    let label_width = if width < 56 {
        (content_width * 2 / 5).clamp(10, 18)
    } else {
        22
    }
    .min(content_width);
    let description_width = content_width.saturating_sub(label_width + 2);
    let body = format!(
        "{marker}{}  {}",
        pad(&fit(&cells[0], label_width), label_width),
        fit(&cells[1], description_width)
    );
    Line::styled(
        fit(&body, width),
        if selected {
            theme::selection()
        } else {
            theme::primary()
        },
    )
}

fn keymap_overlay_viewport(
    mut lines: Vec<Line<'static>>,
    area: Rect,
    scroll: usize,
) -> Vec<Line<'static>> {
    remove_keymap_preamble(&mut lines);
    let visible = overlay_rect(area, lines.len()).height.saturating_sub(2) as usize;
    if visible <= 3 {
        lines.retain(|line| !is_blank_line(line));
    }
    let max_start = lines.len().saturating_sub(visible);
    let start = keymap_scroll_start(scroll, max_start);
    let mut window = lines
        .iter()
        .skip(start)
        .take(visible)
        .cloned()
        .collect::<Vec<_>>();
    if window.last().is_some_and(is_section_heading) {
        if window.len() == 1 {
            return lines.get(start + 1).cloned().into_iter().collect();
        }
        window.pop();
    }
    window
}

fn keymap_scroll_start(scroll: usize, max_start: usize) -> usize {
    const TAIL_SENTINEL: usize = u16::MAX as usize;
    const TAIL_RANGE_START: usize = TAIL_SENTINEL / 2;
    if scroll <= max_start || scroll < TAIL_RANGE_START {
        return scroll.min(max_start);
    }
    let backoff = TAIL_SENTINEL.saturating_sub(scroll.min(TAIL_SENTINEL));
    max_start.saturating_sub(backoff)
}

fn remove_keymap_preamble(lines: &mut Vec<Line<'static>>) {
    if lines
        .first()
        .is_some_and(|line| line_text(line).contains("/help or ?"))
    {
        lines.remove(0);
    }
    if lines.first().is_some_and(is_blank_line) {
        lines.remove(0);
    }
}

fn is_section_heading(line: &Line<'_>) -> bool {
    line_text(line).trim_start().starts_with("── ")
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

fn overlay_title(app: &ShellApp) -> &'static str {
    match app.shell_view() {
        ShellView::Catalog => " CAPABILITIES ",
        ShellView::ConfirmDialog => " CONFIRM ",
        ShellView::QuitConfirm => " QUIT ",
        ShellView::ThemePicker => " THEME ",
        ShellView::Keymap => " KEYMAP ",
        ShellView::Help => " HELP ",
        ShellView::UpdateAvailable if update_available_model(app).release_available => {
            " UPDATE AVAILABLE "
        }
        ShellView::UpdateAvailable => " UPDATE STATUS ",
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
    let state = boot_state_symbol(check.state);
    let label = fixed_width(&fit(&check.label, 28), 28);
    let value = fixed_width(&boot_check_value(&check), 40);
    let inner_width = display_width(state) + display_width(&label) + display_width(&value);
    let pad = width.saturating_sub(inner_width) / 2;
    raw(format!("{}{state}{label}{value}", " ".repeat(pad)))
}

fn boot_check_value(check: &BootSplashCheck) -> String {
    if check.label == "workspace" {
        return fit_path(&check.value, 40);
    }
    fit(&check.value, 40)
}

fn boot_state_symbol(state: BootSplashCheckState) -> &'static str {
    match state {
        BootSplashCheckState::Ok => " ✓ ",
        BootSplashCheckState::Wait => " · ",
        BootSplashCheckState::Err => " ✗ ",
    }
}

fn centered(width: usize, text: &str) -> Line<'static> {
    let pad = width.saturating_sub(display_width(text)) / 2;
    raw(format!("{}{}", " ".repeat(pad), text))
}

fn fixed_width(value: &str, width: usize) -> String {
    // Column-aware: a wide (CJK/emoji) value must not break the box border
    // this padding aligns.
    let mut out = take_columns(value, width);
    let fill = width.saturating_sub(display_width(&out));
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
    let top_fill = width.saturating_sub(display_width(top_prefix) + display_width(&top_title) + 2);
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
        .saturating_sub(display_width(&left) + display_width(&right))
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn capabilities_clears_the_origin_backdrop_at_wide_size() {
        let backend = TestBackend::new(110, 32);
        let mut terminal = Terminal::new(backend).expect("capabilities overlay terminal");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Catalog);

        terminal
            .draw(|frame| {
                let area = frame.area();
                let backdrop = vec![Line::raw("CHOOSE A TARGET"); area.height as usize];
                frame.render_widget(Paragraph::new(backdrop), area);
                render_system_overlay(frame, area, &app);
            })
            .expect("render compact capabilities");
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("CAPABILITIES"), "{rendered}");
        assert!(rendered.contains("Quick map"), "{rendered}");
        assert!(!rendered.contains("CHOOSE A TARGET"), "{rendered}");
    }

    #[test]
    fn boot_workspace_path_preserves_target_tail_with_visible_ellipsis() {
        let line = boot_check_line(
            110,
            BootSplashCheck::new(
                BootSplashCheckState::Ok,
                "workspace",
                "/private/tmp/kzop-audit.yvo11M/deeply/nested/workspace/target-j13",
            ),
        );
        let text = line_text(&line);

        assert!(text.contains('…'), "{text}");
        assert!(text.trim_end().ends_with("target-j13"), "{text}");
        assert!(!text.trim_end().ends_with("target-j1"), "{text}");
    }

    #[test]
    fn unconfigured_update_overlay_uses_neutral_status_title() {
        let backend = TestBackend::new(110, 30);
        let mut terminal = Terminal::new(backend).expect("update status terminal");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::UpdateAvailable);

        terminal
            .draw(|frame| render_system_overlay(frame, frame.area(), &app))
            .expect("render update status");
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("UPDATE STATUS"), "{rendered}");
        assert!(rendered.contains("release feed"), "{rendered}");
        assert!(rendered.contains("not configured"), "{rendered}");
        assert!(!rendered.contains("UPDATE AVAILABLE"), "{rendered}");
    }
}
