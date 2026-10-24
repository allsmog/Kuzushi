use super::*;
use crate::ui_view_models::study_context::{
    context_catalog, context_detail_lines, context_reader_layout, ContextRow,
};
use ratatui::widgets::{Block, Borders};

mod actions;
mod comparison;
mod diagram;
mod editor;
pub(crate) use editor::{context_choice_offset_after_page, context_choice_page_rows};

pub(super) fn render_context_picker(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(picker) = app.study_context_picker() else {
        return;
    };
    if render_context_subview(frame, app, area, picker) {
        return;
    }
    render_context_header(frame, app, area);
    let catalog = context_catalog(app);
    let layout = context_reader_layout(
        area,
        catalog.rows.len(),
        picker.text_view,
        picker.preview.is_some(),
    );
    render_context_selection(frame, &catalog.rows, picker, area, layout.list);
    render_context_detail(
        frame,
        app,
        layout.detail,
        layout.controls,
        picker.detail_scroll,
        picker.text_view,
    );
    if let Some(selected) = picker.actions_selected {
        actions::render(frame, app, area, selected);
    }
}

fn render_context_selection(
    frame: &mut Frame<'_>,
    rows: &[ContextRow],
    picker: &crate::app::StudyContextPicker,
    area: Rect,
    list: Rect,
) {
    if list.height == 0 {
        render_context_identity(frame, rows, picker.selected.as_ref(), area);
        return;
    }
    render_context_rows(frame, rows, picker.selected.as_ref(), list);
}

fn render_context_identity(
    frame: &mut Frame<'_>,
    rows: &[ContextRow],
    reference: Option<&kuzushi_core::ThreatModelRef>,
    area: Rect,
) {
    let width = area.width.saturating_sub(4);
    let identity = crate::ui_view_models::study_context::context_identity(rows, reference);
    let text = fit(&identity, usize::from(width));
    frame.render_widget(
        Paragraph::new(Line::styled(text, theme::accent())),
        Rect::new(area.x + 2, area.y + 2, width, 1),
    );
}

fn render_context_subview(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    area: Rect,
    picker: &crate::app::StudyContextPicker,
) -> bool {
    if let Some(comparison) = picker.comparison.as_ref() {
        comparison::render(frame, area, comparison);
        return true;
    }
    if picker.editor_visible {
        editor::render(frame, app, area);
        return true;
    }
    if picker.diagram_visible {
        diagram::render(frame, app, area);
        return true;
    }
    false
}

fn render_context_rows(
    frame: &mut Frame<'_>,
    rows: &[ContextRow],
    reference: Option<&kuzushi_core::ThreatModelRef>,
    area: Rect,
) {
    let selected = rows
        .iter()
        .position(|row| row.reference.as_ref() == reference);
    let start = selected
        .unwrap_or(0)
        .saturating_sub((area.height as usize).saturating_sub(1));
    let rows = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(area.height as usize)
        .map(|(index, row)| context_row(row, selected == Some(index), area.width as usize))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(rows), area);
}

fn render_context_detail(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    area: Rect,
    controls: Rect,
    scroll: usize,
    text_view: crate::app::StudyContextTextView,
) {
    let lines = context_detail_lines(app, area.width as usize);
    let max = lines.len().saturating_sub(area.height as usize);
    let offset = scroll.min(max);
    let lines = lines
        .into_iter()
        .skip(offset)
        .take(area.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
    let regeneration = app
        .study_context_picker()
        .is_some_and(|p| p.regeneration_entry);
    render_context_controls(frame, controls, offset, max, text_view, regeneration);
}

fn render_context_header(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let title = crate::ui_view_models::study_context::context_header_title(app);
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::subtle())
            .title(Span::styled(title, theme::heading())),
        area,
    );
    if let Some(config) = app.router.campaign().batch_scan_config.as_ref() {
        super::study_config::render_study_target(frame, config, area);
    }
}

fn context_row(row: &ContextRow, selected: bool, width: usize) -> Line<'static> {
    let (marker, style) = if selected {
        ("▸", theme::selection())
    } else {
        (" ", theme::primary())
    };
    Line::styled(fit(&format!("{marker} {}", row.label), width), style)
}

fn render_context_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    offset: usize,
    max: usize,
    text_view: crate::app::StudyContextTextView,
    regeneration: bool,
) {
    let tab = if area.width < 50 {
        "view"
    } else if text_view == crate::app::StudyContextTextView::Document {
        "summary"
    } else {
        "JSON"
    };
    let nav = if area.width < 50 {
        "↑↓ Enter · Tab"
    } else {
        "↑↓ choose · Enter inspect"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                context_navigation_controls(area.width, nav, offset, max),
                theme::muted(),
            ),
            Line::styled(
                crate::ui_view_models::study_context::context_text_controls(text_view, area.width)
                    .map(str::to_owned)
                    .unwrap_or_else(|| context_action_controls(area.width, tab, regeneration)),
                theme::accent(),
            ),
        ]),
        area,
    );
}

fn context_action_controls(width: u16, tab: &str, regeneration: bool) -> String {
    if regeneration {
        return "e choose text · Space actions".into();
    }
    if width < 72 {
        "c check v diagram Space actions".into()
    } else if width < 96 {
        format!("a use · c check · Space actions · p scanner · Tab {tab} · Esc back")
    } else {
        format!("a use · e edit · c check · Space actions · Tab {tab} · p scanner · Esc back")
    }
}

fn context_navigation_controls(width: u16, nav: &str, offset: usize, max: usize) -> String {
    if width < 72 {
        return "↑↓ Enter PgUp/Dn Home/End Esc back".into();
    }
    format!("{nav} · PgUp/Dn {}/{} · Home/End", offset + 1, max + 1)
}
