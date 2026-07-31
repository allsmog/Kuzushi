use super::{entry_detail_lines, fit, responsive_summary};
use crate::theme;
use crate::ui_view_models::{EntryPointBreakdown, EntryPointItem};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

const WIDE_LAYOUT_MIN: u16 = 90;
const PANE_GAP: u16 = 1;

pub(crate) struct EntryPointBrowser {
    pub model: EntryPointBreakdown,
    pub selection: usize,
    pub detail_scroll: usize,
}

impl Widget for EntryPointBrowser {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if let Some(hint) = &self.model.empty_hint {
            super::super::diagram::render_empty_state_panel(
                buf,
                area,
                "no entry points",
                hint,
                &[("threat-model:build", "discover ingress surfaces")],
            );
            return;
        }
        render_browser(buf, area, &self.model, self.selection, self.detail_scroll);
    }
}

fn render_browser(
    buf: &mut Buffer,
    area: Rect,
    model: &EntryPointBreakdown,
    selection: usize,
    detail_scroll: usize,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let selection = selection.min(model.entries.len().saturating_sub(1));
    render_summary(buf, summary_area(area), model);
    let body = body_area(area);
    if area.width >= WIDE_LAYOUT_MIN && body.height >= 8 {
        render_wide(buf, body, model, selection, detail_scroll);
    } else {
        render_stacked(buf, body, model, selection, detail_scroll);
    }
}

fn summary_area(area: Rect) -> Rect {
    Rect { height: 1, ..area }
}

fn body_area(area: Rect) -> Rect {
    Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    }
}

fn render_summary(buf: &mut Buffer, area: Rect, model: &EntryPointBreakdown) {
    let text = responsive_summary(area.width as usize, model);
    Paragraph::new(Line::styled(text, theme::accent())).render(area, buf);
}

fn render_wide(
    buf: &mut Buffer,
    area: Rect,
    model: &EntryPointBreakdown,
    selection: usize,
    detail_scroll: usize,
) {
    let list_width = (area.width * 2 / 5).clamp(32, 44);
    let list = Rect {
        width: list_width,
        ..area
    };
    let detail = Rect {
        x: area.x.saturating_add(list_width + PANE_GAP),
        width: area.width.saturating_sub(list_width + PANE_GAP),
        ..area
    };
    render_entry_list(buf, list, model, selection);
    render_entry_detail(buf, detail, model, selection, detail_scroll);
}

fn render_stacked(
    buf: &mut Buffer,
    area: Rect,
    model: &EntryPointBreakdown,
    selection: usize,
    detail_scroll: usize,
) {
    if area.height == 0 {
        return;
    }
    let list_height = stacked_list_height(area.height);
    let list = Rect {
        height: list_height,
        ..area
    };
    let detail = Rect {
        y: area.y.saturating_add(list_height + PANE_GAP),
        height: area.height.saturating_sub(list_height + PANE_GAP),
        ..area
    };
    render_entry_list(buf, list, model, selection);
    render_entry_detail(buf, detail, model, selection, detail_scroll);
}

fn stacked_list_height(height: u16) -> u16 {
    if height < 10 {
        return height.saturating_sub(3).max(2);
    }
    (height / 3).clamp(5, 10)
}

fn render_entry_list(buf: &mut Buffer, area: Rect, model: &EntryPointBreakdown, selection: usize) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let title = format!(
        " ENTRY POINTS · {}/{} ",
        selection.saturating_add(1),
        model.entries.len()
    );
    let block = bordered_block(&title, area.width, theme::heading());
    let inner = block.inner(area);
    block.render(area, buf);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let rows = entry_list_rows(model, selection, inner.width as usize);
    let selected_row = rows
        .iter()
        .position(|row| row.entry_index == Some(selection))
        .unwrap_or_default();
    let start = viewport_start(rows.len(), inner.height as usize, selected_row);
    let visible = rows
        .into_iter()
        .skip(start)
        .take(inner.height as usize)
        .map(|row| row.line)
        .collect::<Vec<_>>();
    Paragraph::new(visible).render(inner, buf);
}

struct EntryListRow {
    entry_index: Option<usize>,
    line: Line<'static>,
}

fn entry_list_rows(
    model: &EntryPointBreakdown,
    selection: usize,
    width: usize,
) -> Vec<EntryListRow> {
    let mut rows = Vec::new();
    let mut active_zone = None::<&str>;
    for (index, entry) in model.entries.iter().enumerate() {
        if active_zone != Some(entry.trust_zone.as_str()) {
            active_zone = Some(&entry.trust_zone);
            rows.push(zone_row(model, &entry.trust_zone, width));
        }
        rows.push(entry_row(index, entry, index == selection, width));
    }
    rows
}

fn zone_row(model: &EntryPointBreakdown, zone: &str, width: usize) -> EntryListRow {
    let count = model
        .zones
        .iter()
        .find(|group| group.name == zone)
        .map_or(0, |group| group.count);
    let label = format!(" {} · {count}", zone.replace('_', " ").to_uppercase());
    EntryListRow {
        entry_index: None,
        line: Line::styled(fit(&label, width), theme::label()),
    }
}

fn entry_row(index: usize, entry: &EntryPointItem, selected: bool, width: usize) -> EntryListRow {
    let marker = if selected { "›" } else { " " };
    let text = fit(&format!("{marker} {}", entry.name), width);
    let style = if selected {
        theme::accent()
    } else {
        theme::primary()
    };
    EntryListRow {
        entry_index: Some(index),
        line: Line::styled(text, style),
    }
}

fn render_entry_detail(
    buf: &mut Buffer,
    area: Rect,
    model: &EntryPointBreakdown,
    selection: usize,
    detail_scroll: usize,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let Some(entry) = model.entries.get(selection) else {
        return;
    };
    let lines = entry_detail_lines(area.width.saturating_sub(2) as usize, entry);
    let block = detail_block(
        area,
        entry,
        selection,
        model.entries.len(),
        &lines,
        detail_scroll,
    );
    let inner = block.inner(area);
    block.render(area, buf);
    let start = detail_scroll.min(lines.len().saturating_sub(inner.height as usize));
    Paragraph::new(
        lines
            .into_iter()
            .skip(start)
            .take(inner.height as usize)
            .collect::<Vec<_>>(),
    )
    .render(inner, buf);
}

fn detail_block(
    area: Rect,
    entry: &EntryPointItem,
    selection: usize,
    total: usize,
    lines: &[Line<'static>],
    detail_scroll: usize,
) -> Block<'static> {
    let visible = area.height.saturating_sub(2) as usize;
    let start = detail_scroll.min(lines.len().saturating_sub(visible));
    let position = if lines.len() > visible && visible > 0 {
        format!(
            " · rows {}-{}/{}",
            start + 1,
            (start + visible).min(lines.len()),
            lines.len()
        )
    } else {
        String::new()
    };
    bordered_block(
        &format!(
            " DETAIL · {} · {}/{}{} ",
            entry.id,
            selection + 1,
            total,
            position
        ),
        area.width,
        theme::accent(),
    )
}

fn bordered_block(title: &str, width: u16, title_style: Style) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Line::styled(
            fit(title, width.saturating_sub(2) as usize),
            title_style,
        ))
}

fn viewport_start(total: usize, visible: usize, cursor: usize) -> usize {
    if total <= visible || visible == 0 {
        return 0;
    }
    cursor
        .saturating_sub(visible.saturating_sub(1) / 2)
        .min(total - visible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{EntryPointGroup, EntryPointTarget};

    #[test]
    fn browser_keeps_selection_and_detail_visible_across_width_classes() {
        for (width, height) in [(120, 36), (80, 30), (40, 30), (24, 24)] {
            let text = render_to_text(
                EntryPointBrowser {
                    model: sample_model(),
                    selection: 0,
                    detail_scroll: 0,
                },
                width,
                height,
            );

            assert!(text.contains("ENTRY POINTS"), "{width}x{height}\n{text}");
            assert!(text.contains("POST /admin"), "{width}x{height}\n{text}");
            assert!(text.contains("EP-1"), "{width}x{height}\n{text}");
            assert!(text.contains("internet"), "{width}x{height}\n{text}");
        }
    }

    #[test]
    fn detail_scroll_exposes_tail_without_moving_selection() {
        let mut model = sample_model();
        model.entries[0].evidence = "evidence ".repeat(40);

        let text = render_to_text(
            EntryPointBrowser {
                model,
                selection: 0,
                detail_scroll: usize::MAX,
            },
            40,
            18,
        );

        assert!(text.contains("rows"), "{text}");
        assert!(text.contains("id"), "{text}");
        assert!(text.contains("EP-1"), "{text}");
    }

    fn sample_model() -> EntryPointBreakdown {
        EntryPointBreakdown {
            entries: vec![EntryPointItem {
                id: "EP-1".into(),
                name: "POST /admin".into(),
                kind: "http_route".into(),
                trust_zone: "internet".into(),
                description: "Administrative route".into(),
                ingress: "POST /admin".into(),
                source: "src/routes.rs:42".into(),
                evidence: "route registration with authorization middleware".into(),
                targets: vec![EntryPointTarget {
                    id: "N1".into(),
                    label: "N1 Share API · cloud_function".into(),
                }],
                unresolved_target_count: 0,
            }],
            kinds: vec![EntryPointGroup {
                name: "http_route".into(),
                count: 1,
            }],
            zones: vec![EntryPointGroup {
                name: "internet".into(),
                count: 1,
            }],
            linked_target_count: 1,
            target_count: 1,
            empty_hint: None,
        }
    }

    fn render_to_text(widget: impl Widget, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buffer = Buffer::empty(area);
        widget.render(area, &mut buffer);
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
