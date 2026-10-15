use super::*;
use crate::app::{FilePickerPurpose, ShellView};
use crate::ui_view_models::study_config::study_config_area;
use kuzushi_core::run_lifecycle::SafeText;
use ratatui::widgets::{Block, Borders, Clear};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    if app.shell_view() != ShellView::FilePicker
        || app.router.file_picker().purpose() != FilePickerPurpose::ReviewEvidence
        || app.advisory().pending_confirm.is_some()
    {
        return false;
    }
    let full = frame.area();
    let area = study_config_area(full.width, full.height);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" REVIEW SUPPORTING FILES ");
    let inner = block.inner(area);
    frame.render_widget(Clear, full);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines(app, inner)), inner);
    true
}

pub(crate) fn plain_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    if app.shell_view() != ShellView::FilePicker
        || app.router.file_picker().purpose() != FilePickerPurpose::ReviewEvidence
        || app.advisory().pending_confirm.is_some()
    {
        return None;
    }
    let count = app
        .router
        .file_picker()
        .filtered_paths()
        .len()
        .min(u16::MAX as usize - 5);
    let area = Rect::new(0, 0, width as u16, (count + 5).max(10) as u16);
    let mut output = vec!["REVIEW SUPPORTING FILES".into()];
    output.extend(lines(app, area).into_iter().map(|line| {
        line.spans
            .into_iter()
            .map(|span| span.content)
            .collect::<String>()
    }));
    Some(output)
}

pub(crate) fn lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = header(app, area.width);
    let route = app.router.file_picker();
    let visible = area.height.saturating_sub(5) as usize;
    let matches = route.filtered_paths();
    let start = route
        .cursor()
        .saturating_sub(visible / 2)
        .min(matches.len().saturating_sub(visible));
    if matches.is_empty() && visible > 0 {
        lines.push(Line::styled(
            "No matches. Space adds exact path.",
            theme::muted(),
        ));
    }
    for (index, path) in matches.iter().enumerate().skip(start).take(visible) {
        lines.push(file_line(app, index, path, area.width));
    }
    while lines.len() < area.height.saturating_sub(2) as usize {
        lines.push(Line::default());
    }
    lines.push(Line::from("Space toggle · Tab basket"));
    lines.push(Line::from("↑/↓ · Enter apply · Esc cancel"));
    lines
}

fn header(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let route = app.router.file_picker();
    let selection = route.review_selection();
    let mode = if selection.basket() {
        "Basket"
    } else {
        "Repository"
    };
    let mut lines = vec![Line::from(format!(
        "{mode} · {}/16 chosen · shared byte cap",
        selection.paths().len()
    ))];
    lines.push(query_line(app, width));
    let hint = selection.notice().unwrap_or(if route.truncated() {
        "Partial index. Paste an exact path."
    } else {
        "No dependency expansion or model call."
    });
    lines.push(Line::styled(fit(hint, width as usize), theme::muted()));
    lines
}

fn query_line(app: &ShellApp, width: u16) -> Line<'static> {
    let mut line = Line::from("Find: ");
    if let Some(field) = field_editor_lines(
        app.router.file_picker().query_field(),
        width.saturating_sub(6) as usize,
        1,
    )
    .into_iter()
    .next()
    {
        line.spans.extend(field.spans);
    }
    line
}

fn file_line(app: &ShellApp, index: usize, path: &str, width: u16) -> Line<'static> {
    let route = app.router.file_picker();
    let ordinal = route
        .review_selection()
        .paths()
        .iter()
        .position(|chosen| chosen == path)
        .map(|position| (position + 1).to_string())
        .unwrap_or_default();
    let selected = route.cursor() == index;
    let marker = if selected { ">" } else { " " };
    let path = SafeText::operator_visible(path).to_string();
    let style = if selected {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(
        format!(
            "{marker}[{ordinal:>2}] {}",
            fit_path(&path, width.saturating_sub(6) as usize)
        ),
        style,
    )
}
