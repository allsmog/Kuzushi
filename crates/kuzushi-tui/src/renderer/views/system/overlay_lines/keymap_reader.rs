use super::*;
use ratatui::layout::Margin;

pub(crate) struct KeymapReaderScroll {
    pub(crate) max_offset: usize,
    pub(crate) page_rows: usize,
}

struct KeymapReader {
    modal: Rect,
    lines: Vec<Line<'static>>,
    capacity: usize,
}

pub(crate) fn keymap_reader_scroll(app: &ShellApp) -> Option<KeymapReaderScroll> {
    if app.shell_view() != ShellView::Keymap {
        return None;
    }
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    let area = crate::renderer::workbench_primary_area(app, full);
    let reader = keymap_reader(app, area);
    Some(KeymapReaderScroll {
        max_offset: reader.lines.len().saturating_sub(reader.capacity),
        // A section heading at the bottom is held for the next page.
        page_rows: reader.capacity.saturating_sub(1).max(1),
    })
}

pub(super) fn render_keymap_reader(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let reader = keymap_reader(app, area);
    if reader.capacity == 0 {
        return;
    }
    let max = reader.lines.len().saturating_sub(reader.capacity);
    let start = usize::from(app.router.default_scroll().offset()).min(max);
    let window = overlay_document_window(&reader.lines, reader.capacity, start);
    let end = (start + window.len()).min(reader.lines.len());
    let title = format!(" KEYMAP · {}–{end}/{} ", start + 1, reader.lines.len());
    render_overlay_backdrop(frame, area);
    frame.render_widget(Clear, reader.modal);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(title, theme::heading()));
    let inner = block.inner(reader.modal);
    frame.render_widget(block, reader.modal);
    frame.render_widget(Paragraph::new(window), inner);
}

fn keymap_reader(app: &ShellApp, area: Rect) -> KeymapReader {
    let available = keymap_available_area(area);
    let body = keymap_modal(available, usize::MAX).inner(Margin::new(1, 1));
    let mut lines = strip_full_screen_chrome(keymap_lines(app, body));
    remove_keymap_preamble(&mut lines);
    let lines = crate::renderer::shared::text::wrap_document_lines(lines, body.width);
    let modal = keymap_modal(available, lines.len());
    KeymapReader {
        capacity: usize::from(modal.height.saturating_sub(2)),
        modal,
        lines,
    }
}

fn keymap_available_area(area: Rect) -> Rect {
    if area.height <= 16 {
        area
    } else {
        overlay_body_area(area)
    }
}

fn keymap_modal(area: Rect, rows: usize) -> Rect {
    if area.height <= 16 {
        return Rect {
            height: area
                .height
                .min(rows.saturating_add(2).min(u16::MAX as usize) as u16),
            ..area
        };
    }
    overlay_rect(area, rows)
}
