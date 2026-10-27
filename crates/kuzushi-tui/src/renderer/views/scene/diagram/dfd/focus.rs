use crate::renderer::shared::text::fit;
use crate::theme;
use crate::ui_view_models::{
    dfd_security_items_for_selection, dfd_selected_item, DfdModel, DfdSecurityItem,
    DfdSecurityKind, DfdSelected,
};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

const WIDE_FOCUS_MIN: u16 = 96;
const DETAIL_HEIGHT: u16 = 5;

pub(super) fn render(
    buf: &mut Buffer,
    area: Rect,
    model: &DfdModel,
    selection: usize,
    context_selection: usize,
) {
    if area.width < 4 || area.height < 4 {
        return;
    }
    let items = dfd_security_items_for_selection(model, selection);
    let selected = clamped_selection(context_selection, items.len());
    if area.height < 9 {
        render_short_context(buf, area, model, selection, &items, selected);
        return;
    }
    let regions = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(DETAIL_HEIGHT.min(area.height.saturating_sub(2))),
        ])
        .split(area);
    render_element_header(buf, regions[0], model, selection, items.len());
    if area.width >= WIDE_FOCUS_MIN {
        render_wide_context(buf, regions[1], &items, selected);
    } else {
        render_compact_context(buf, regions[1], &items, selected);
    }
    render_annotation_detail(buf, regions[2], items.get(selected).copied());
}

fn render_short_context(
    buf: &mut Buffer,
    area: Rect,
    model: &DfdModel,
    selection: usize,
    items: &[&DfdSecurityItem],
    selected: usize,
) {
    let heading = Rect::new(area.x, area.y, area.width, 1);
    render_element_header(buf, heading, model, selection, items.len());
    let body = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
    let Some(item) = items.get(selected) else {
        Paragraph::new("No linked annotations")
            .style(theme::muted())
            .render(body, buf);
        return;
    };
    let lines = [
        format!(
            "{} · {}/{} · {}",
            kind_label(item.kind),
            selected + 1,
            items.len(),
            item.label
        ),
        format!("Evidence: {}", item.evidence_label()),
        item.detail.clone(),
    ]
    .map(|line| Line::styled(fit(&line, area.width as usize), theme::primary()));
    Paragraph::new(Vec::from(lines)).render(body, buf);
}

fn render_element_header(
    buf: &mut Buffer,
    area: Rect,
    model: &DfdModel,
    selection: usize,
    count: usize,
) {
    let label = selected_element_label(model, selection);
    let text = if area.width < 60 {
        format!("Enter topology · {label} · {count}")
    } else {
        format!("LOCAL SECURITY GRAPH · Enter topology · {label} · {count} linked")
    };
    Paragraph::new(fit(&text, area.width as usize))
        .style(Style::default().fg(theme::T_HEADING))
        .render(area, buf);
}

fn selected_element_label(model: &DfdModel, selection: usize) -> String {
    match dfd_selected_item(model, selection) {
        Some(DfdSelected::Node(node)) => format!("node {} [{}]", node.name, node.zone),
        Some(DfdSelected::Flow(flow)) => format!("flow {} → {}", flow.from, flow.to),
        Some(DfdSelected::Boundary(boundary)) => {
            format!(
                "boundary {} [{} → {}]",
                boundary.name, boundary.outer_zone, boundary.inner_zone
            )
        }
        None => "no selected DFD element".to_string(),
    }
}

fn render_wide_context(buf: &mut Buffer, area: Rect, items: &[&DfdSecurityItem], selected: usize) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
        .split(area);
    render_wide_lanes(buf, rows[0], items, selected);
    render_group(
        buf,
        rows[1],
        "THREATS",
        items,
        selected,
        &[DfdSecurityKind::Threat],
    );
}

fn render_wide_lanes(buf: &mut Buffer, area: Rect, items: &[&DfdSecurityItem], selected: usize) {
    let lanes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(area);
    render_group(
        buf,
        lanes[0],
        "CALLERS + ENTRY POINTS",
        items,
        selected,
        &[DfdSecurityKind::TrustedCaller, DfdSecurityKind::EntryPoint],
    );
    render_group(
        buf,
        lanes[1],
        "GATES + BOUNDARIES",
        items,
        selected,
        &[DfdSecurityKind::RoleGate],
    );
    render_group(
        buf,
        lanes[2],
        "SINKS + ASSETS",
        items,
        selected,
        &[DfdSecurityKind::ExternalSink, DfdSecurityKind::Asset],
    );
}

fn render_group(
    buf: &mut Buffer,
    area: Rect,
    title: &str,
    items: &[&DfdSecurityItem],
    selected: usize,
    kinds: &[DfdSecurityKind],
) {
    let grouped = indexed_items(items, kinds);
    let capacity = area.height.saturating_sub(2) as usize;
    let visible = visible_page(&grouped, selected, capacity);
    let title = group_title(title, visible.start, visible.rows.len(), grouped.len());
    let lines = group_lines(
        &visible.rows,
        area.width.saturating_sub(2) as usize,
        selected,
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::T_MUTED))
        .title(Span::styled(title, Style::default().fg(theme::T_LABEL)));
    Paragraph::new(lines).block(block).render(area, buf);
}

struct VisibleGroup<'a> {
    start: usize,
    rows: Vec<(usize, &'a DfdSecurityItem)>,
}

fn visible_page<'a>(
    rows: &[(usize, &'a DfdSecurityItem)],
    selected: usize,
    capacity: usize,
) -> VisibleGroup<'a> {
    if capacity == 0 {
        return VisibleGroup {
            start: 0,
            rows: Vec::new(),
        };
    }
    let selected_row = rows.iter().position(|(index, _)| *index == selected);
    let start = selected_row.map_or(0, |position| position / capacity * capacity);
    VisibleGroup {
        start,
        rows: rows.iter().skip(start).take(capacity).copied().collect(),
    }
}

fn indexed_items<'a>(
    items: &[&'a DfdSecurityItem],
    kinds: &[DfdSecurityKind],
) -> Vec<(usize, &'a DfdSecurityItem)> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| kinds.contains(&item.kind))
        .map(|(index, item)| (index, *item))
        .collect()
}

fn group_title(title: &str, start: usize, shown: usize, total: usize) -> String {
    if total <= shown {
        return format!(" {title} · {total} ");
    }
    format!(" {title} · {}-{}/{} ", start + 1, start + shown, total)
}

fn group_lines(
    rows: &[(usize, &DfdSecurityItem)],
    width: usize,
    selected: usize,
) -> Vec<Line<'static>> {
    if rows.is_empty() {
        return vec![Line::styled("none linked", theme::muted())];
    }
    rows.iter()
        .map(|(index, item)| annotation_line(item, width, *index == selected))
        .collect()
}

fn annotation_line(item: &DfdSecurityItem, width: usize, selected: bool) -> Line<'static> {
    let prefix = if selected { "› " } else { "· " };
    let label = fit(
        &format!("{prefix}{} · {}", kind_label(item.kind), item.label),
        width,
    );
    let style = if selected {
        Style::default().fg(theme::T_SUCCESS)
    } else {
        Style::default().fg(theme::T_PRIMARY)
    };
    Line::styled(label, style)
}

fn render_compact_context(
    buf: &mut Buffer,
    area: Rect,
    items: &[&DfdSecurityItem],
    selected: usize,
) {
    let capacity = area.height.saturating_sub(2) as usize;
    let indexed = items.iter().copied().enumerate().collect::<Vec<_>>();
    let visible = visible_page(&indexed, selected, capacity);
    let title = group_title(
        "CAUSAL CONTEXT",
        visible.start,
        visible.rows.len(),
        indexed.len(),
    );
    let lines = group_lines(
        &visible.rows,
        area.width.saturating_sub(2) as usize,
        selected,
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::T_MUTED))
        .title(Span::styled(title, Style::default().fg(theme::T_LABEL)));
    Paragraph::new(lines).block(block).render(area, buf);
}

fn render_annotation_detail(buf: &mut Buffer, area: Rect, item: Option<&DfdSecurityItem>) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::T_MUTED))
        .title(Span::styled(
            " LINK DETAIL · j/k selects ",
            Style::default().fg(theme::T_SUCCESS),
        ));
    let width = area.width.saturating_sub(2) as usize;
    let lines = item.map_or_else(
        || vec![Line::styled("no linked annotations", theme::muted())],
        |item| detail_lines(item, width),
    );
    Paragraph::new(lines).block(block).render(area, buf);
}

fn detail_lines(item: &DfdSecurityItem, width: usize) -> Vec<Line<'static>> {
    [
        format!("{} · {} · {}", kind_label(item.kind), item.key, item.label),
        item.detail.clone(),
        item.evidence_label(),
    ]
    .into_iter()
    .filter(|line| !line.is_empty())
    .take(3)
    .map(|line| Line::styled(fit(&line, width), theme::primary()))
    .collect()
}

fn clamped_selection(selection: usize, len: usize) -> usize {
    selection.min(len.saturating_sub(1))
}

fn kind_label(kind: DfdSecurityKind) -> &'static str {
    match kind {
        DfdSecurityKind::EntryPoint => "ENTRY",
        DfdSecurityKind::RoleGate => "GATE",
        DfdSecurityKind::ExternalSink => "SINK",
        DfdSecurityKind::TrustedCaller => "CALLER",
        DfdSecurityKind::Asset => "ASSET",
        DfdSecurityKind::Threat => "THREAT",
    }
}

#[cfg(test)]
mod tests;
