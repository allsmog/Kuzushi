use super::{diagram_muted, diagram_primary, diagram_style, DfdKind, DfdModel};
use crate::renderer::views::scene::gallery_layout::summary_document_area;
use crate::theme;
use crate::ui_view_models::{dfd_overview, DfdContextCounts, DfdOverview};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget, Wrap};

const WIDE_MIN_WIDTH: u16 = 96;
const WIDE_MIN_HEIGHT: u16 = 18;

mod tree;

pub(super) fn render(
    buf: &mut Buffer,
    area: Rect,
    model: &DfdModel,
    component_selection: usize,
    scroll: i32,
) {
    let overview = dfd_overview(model);
    if let Some(top_height) = wide_top_height(area, model, &overview) {
        render_wide(
            buf,
            area,
            model,
            &overview,
            component_selection,
            scroll,
            top_height,
        );
    } else {
        render_compact(buf, area, model, &overview, component_selection, scroll);
    }
}

fn render_wide(
    buf: &mut Buffer,
    area: Rect,
    model: &DfdModel,
    overview: &DfdOverview,
    component_selection: usize,
    scroll: i32,
    top_height: u16,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(top_height), Constraint::Min(5)])
        .split(area);
    let top = wide_columns(rows[0]);
    render_panel(
        buf,
        top[0],
        "EXECUTIVE SUMMARY",
        executive_summary_lines(model, overview),
    );
    render_panel(buf, top[1], "OVERALL DATA FLOW", zone_flow_lines(overview));
    render_tree(buf, rows[1], model, overview, component_selection, scroll);
}

fn wide_columns(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .spacing(1)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area)
}

fn wide_top_height(area: Rect, model: &DfdModel, overview: &DfdOverview) -> Option<u16> {
    if area.width < WIDE_MIN_WIDTH || area.height < WIDE_MIN_HEIGHT {
        return None;
    }
    let width = usize::from(wide_columns(area)[0].width.saturating_sub(2).max(1));
    let summary = wrapped_rows(&executive_summary_lines(model, overview), width).saturating_add(2);
    let height = summary
        .max(overview.zone_flows.len().saturating_add(3))
        .max(9);
    let height = u16::try_from(height).unwrap_or(u16::MAX);
    (height <= area.height.saturating_sub(5)).then_some(height)
}

pub(crate) fn summary_reading_rows(area: Rect, model: &DfdModel) -> usize {
    let overview = dfd_overview(model);
    let height = wide_top_height(area, model, &overview)
        .map(|top| area.height.saturating_sub(top))
        .unwrap_or(area.height);
    let body = Rect { height, ..area };
    usize::from(summary_document_area(body).height).max(1)
}

fn render_compact(
    buf: &mut Buffer,
    area: Rect,
    model: &DfdModel,
    overview: &DfdOverview,
    component_selection: usize,
    scroll: i32,
) {
    let mut lines = executive_summary_lines(model, overview);
    if area.height > 4 {
        lines.insert(0, section_line("EXECUTIVE SUMMARY"));
    }
    lines.push(Line::default());
    lines.push(section_line("OVERALL DATA FLOW"));
    lines.extend(zone_flow_lines(overview));
    lines.push(Line::default());
    lines.push(section_line("COMPONENT TREE"));
    let tree = tree::component_tree_document(model, overview, component_selection);
    let tree_offset = lines.len();
    let anchor = compact_anchor(&tree, tree_offset);
    lines.extend(tree.lines.iter().cloned());
    render_scrolled_document(buf, area, compact_title(&tree), lines, scroll, anchor);
}

fn render_tree(
    buf: &mut Buffer,
    area: Rect,
    model: &DfdModel,
    overview: &DfdOverview,
    component_selection: usize,
    scroll: i32,
) {
    let tree = tree::component_tree_document(model, overview, component_selection);
    let anchor = Some(component_anchor(&tree, 0));
    render_scrolled_document(buf, area, tree_title(&tree), tree.lines, scroll, anchor);
}

fn render_panel(buf: &mut Buffer, area: Rect, title: &str, lines: Vec<Line<'static>>) {
    Paragraph::new(lines)
        .block(panel_block(title))
        .wrap(Wrap { trim: false })
        .render(area, buf);
}

fn render_scrolled_document(
    buf: &mut Buffer,
    area: Rect,
    title: String,
    lines: Vec<Line<'static>>,
    requested_scroll: i32,
    anchor: Option<ScrollAnchor>,
) {
    let document = summary_document_area(area);
    let viewport = usize::from(document.height);
    let width = usize::from(document.width.max(1));
    let scroll = document_scroll(&lines, width, viewport, anchor, requested_scroll);
    let mut paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    if document != area {
        paragraph = paragraph.block(panel_block(&title));
    }
    paragraph.render(area, buf);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScrollAnchor {
    start_line: usize,
    end_line: usize,
}

fn compact_anchor(tree: &tree::ComponentTreeDocument, tree_offset: usize) -> Option<ScrollAnchor> {
    (tree.selection > 0).then(|| component_anchor(tree, tree_offset))
}

fn component_anchor(tree: &tree::ComponentTreeDocument, offset: usize) -> ScrollAnchor {
    ScrollAnchor {
        start_line: offset + tree.selected_start,
        end_line: offset + tree.selected_end,
    }
}

fn document_scroll(
    lines: &[Line<'_>],
    width: usize,
    viewport: usize,
    anchor: Option<ScrollAnchor>,
    requested_scroll: i32,
) -> u16 {
    let total_rows = wrapped_rows(lines, width);
    let max_scroll = total_rows.saturating_sub(viewport);
    let base = anchor
        .map(|anchor| centered_anchor_scroll(lines, width, viewport, anchor))
        .unwrap_or_default();
    let requested = (base as i64 + i64::from(requested_scroll)).clamp(0, max_scroll as i64);
    requested.min(i64::from(u16::MAX)) as u16
}

fn centered_anchor_scroll(
    lines: &[Line<'_>],
    width: usize,
    viewport: usize,
    anchor: ScrollAnchor,
) -> usize {
    let start = wrapped_rows(&lines[..anchor.start_line.min(lines.len())], width);
    let end = wrapped_rows(&lines[..anchor.end_line.min(lines.len())], width);
    let block_rows = end.saturating_sub(start);
    let leading_room = viewport.saturating_sub(block_rows) / 2;
    start.saturating_sub(leading_room)
}

fn wrapped_rows(lines: &[Line<'_>], width: usize) -> usize {
    lines
        .iter()
        .map(|line| {
            crate::renderer::shared::text::wrap_text(&line.to_string(), width.max(1))
                .len()
                .max(1)
        })
        .sum()
}

fn panel_block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(diagram_style(super::diagram_subtle()))
        .title(Span::styled(format!("{title} "), theme::heading()))
}

fn executive_summary_lines(model: &DfdModel, overview: &DfdOverview) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(notice) = model.evidence_notice() {
        lines.push(Line::styled(notice, theme::label()));
    }
    lines.extend(vec![
        Line::styled(
            overview.executive_summary.clone(),
            diagram_style(diagram_primary()),
        ),
        Line::default(),
        Line::styled(component_shape(model), diagram_style(diagram_muted())),
        Line::styled(security_shape(model), diagram_style(diagram_muted())),
    ]);
    if let Some(notice) = model.topology_notice() {
        lines.push(Line::styled(notice, theme::label()));
    }
    lines
}

fn component_shape(model: &DfdModel) -> String {
    let entities = kind_count(model, DfdKind::Entity);
    let processes = kind_count(model, DfdKind::Process);
    let stores = kind_count(model, DfdKind::Store);
    format!("shape · {entities} entities · {processes} processes · {stores} stores")
}

fn kind_count(model: &DfdModel, kind: DfdKind) -> usize {
    model.nodes.iter().filter(|node| node.kind == kind).count()
}

fn security_shape(model: &DfdModel) -> String {
    let counts =
        model
            .security_context
            .iter()
            .fold(DfdContextCounts::default(), |mut counts, item| {
                match item.kind {
                    crate::ui_view_models::DfdSecurityKind::EntryPoint => counts.entry_points += 1,
                    crate::ui_view_models::DfdSecurityKind::RoleGate => counts.role_gates += 1,
                    crate::ui_view_models::DfdSecurityKind::ExternalSink => {
                        counts.external_sinks += 1
                    }
                    crate::ui_view_models::DfdSecurityKind::TrustedCaller => {
                        counts.trusted_callers += 1
                    }
                    crate::ui_view_models::DfdSecurityKind::Asset => counts.assets += 1,
                    crate::ui_view_models::DfdSecurityKind::Threat => counts.threats += 1,
                }
                counts
            });
    format!(
        "context · {}, {}, {}, {}",
        count_label(counts.entry_points, "entry"),
        count_label(counts.role_gates, "gate"),
        count_label(counts.assets, "asset"),
        count_label(counts.threats, "threat")
    )
}

fn zone_flow_lines(overview: &DfdOverview) -> Vec<Line<'static>> {
    if overview.zone_flows.is_empty() {
        return vec![Line::styled("no data flows recorded", diagram_muted())];
    }
    overview
        .zone_flows
        .iter()
        .map(|flow| {
            let crossing = zone_crossing_label(flow.flow_count, flow.crossing_count);
            Line::styled(
                format!(
                    "{} → {} · {}{crossing}",
                    flow.from_zone,
                    flow.to_zone,
                    count_label(flow.flow_count, "flow")
                ),
                diagram_style(if flow.crossing_count > 0 {
                    theme::SEV_HIGH
                } else {
                    diagram_primary()
                }),
            )
        })
        .collect()
}

fn zone_crossing_label(flow_count: usize, crossing_count: usize) -> String {
    if crossing_count == 0 {
        String::new()
    } else if crossing_count == flow_count {
        " · boundary".to_string()
    } else {
        format!(" · {}", count_label(crossing_count, "crossing"))
    }
}

fn count_label(count: usize, singular: &str) -> String {
    if count == 1 {
        return format!("{count} {singular}");
    }
    let plural = match singular {
        "entry" => "entries".to_string(),
        value => format!("{value}s"),
    };
    format!("{count} {plural}")
}

fn tree_title(tree: &tree::ComponentTreeDocument) -> String {
    format!(
        "COMPONENT TREE · {} · {} · ↑/↓ select · Enter DFD · PgUp/PgDn scroll",
        tree.selected_zone,
        component_position(tree)
    )
}

fn compact_title(tree: &tree::ComponentTreeDocument) -> String {
    format!(
        "SYSTEM SUMMARY · component {} · ↑/↓ select · Enter DFD",
        component_position(tree)
    )
}

fn component_position(tree: &tree::ComponentTreeDocument) -> String {
    if tree.total == 0 {
        return "0/0".to_string();
    }
    format!("{}/{}", tree.selection + 1, tree.total)
}

fn section_line(title: &'static str) -> Line<'static> {
    Line::styled(title, theme::heading())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{DfdKind, DfdNodeModel};

    #[test]
    fn scroll_anchors_to_wrapped_selected_component_and_accepts_relative_paging() {
        let lines = vec![
            Line::from("header"),
            Line::from("first component has enough text to wrap across rows"),
            Line::from("first detail"),
            Line::from("selected component has enough text to wrap too"),
            Line::from("selected detail"),
            Line::from("tail"),
        ];
        let anchor = Some(ScrollAnchor {
            start_line: 3,
            end_line: 5,
        });

        let centered = document_scroll(&lines, 12, 4, anchor, 0);
        let paged_up = document_scroll(&lines, 12, 4, anchor, -2);
        let paged_down = document_scroll(&lines, 12, 4, anchor, 2);

        assert!(centered > 0);
        assert_eq!(paged_up, centered.saturating_sub(2));
        assert_eq!(paged_down, centered + 2);
    }

    #[test]
    fn selected_component_stays_visible_across_summary_layouts() {
        let model = component_model(8);

        for (width, height) in [(100, 18), (60, 20), (40, 12)] {
            let area = Rect::new(0, 0, width, height);
            let mut buf = Buffer::empty(area);
            render(&mut buf, area, &model, 7, 0);
            let text = buffer_text(&buf, width, height);

            assert!(text.contains("component-8"), "{width}x{height}: {text}");
            assert!(text.contains("› ◇"), "{width}x{height}: {text}");
        }
    }

    #[test]
    fn tiny_summary_document_keeps_the_description_and_selected_component_readable() {
        let model = component_model(8);
        for height in 1..=4 {
            let area = Rect::new(0, 0, 40, height);
            let mut first = Buffer::empty(area);
            render(&mut first, area, &model, 0, 0);
            let text = buffer_text(&first, 40, height);
            assert!(text.contains("Operators use Sample"), "{height}: {text}");

            let mut selected = Buffer::empty(area);
            render(&mut selected, area, &model, 7, 0);
            let text = buffer_text(&selected, 40, height);
            assert!(text.contains("component-8"), "{height}: {text}");
        }
    }

    #[test]
    fn wide_summary_keeps_the_end_of_a_long_system_description_visible() {
        let mut model = component_model(3);
        model.system_context = Some(format!(
            "{} COMPLETE_DESCRIPTION",
            "Operators review local records and preserve their decisions. ".repeat(10)
        ));
        let area = Rect::new(0, 0, 120, 28);
        let mut buf = Buffer::empty(area);
        render(&mut buf, area, &model, 0, 0);
        let text = buffer_text(&buf, 120, 28);
        assert!(text.contains("COMPLETE_DESCRIPTION"), "{text}");
        assert!(text.contains("COMPONENT TREE"), "{text}");
    }

    #[test]
    fn oversized_wide_description_uses_a_document_with_a_reachable_component_tail() {
        let mut model = component_model(3);
        model.system_context = Some("Operators review local records. ".repeat(100));
        let area = Rect::new(0, 0, 120, 28);
        let mut first = Buffer::empty(area);
        render(&mut first, area, &model, 0, 0);
        assert!(buffer_text(&first, 120, 28).contains("SYSTEM SUMMARY"));

        let mut last = Buffer::empty(area);
        render(&mut last, area, &model, 0, i32::MAX);
        assert!(buffer_text(&last, 120, 28).contains("component-3"));
    }

    fn component_model(count: usize) -> DfdModel {
        DfdModel {
            target_name: "sample".into(),
            system_context: Some("Operators use Sample to review local records.".into()),
            zones: vec!["desktop".into()],
            nodes: (1..=count)
                .map(|index| DfdNodeModel {
                    key: format!("component-{index}"),
                    name: format!("component-{index}"),
                    description: Some("Processes locally supplied records.".into()),
                    purpose: Some("Keeps the operator's review flow local.".into()),
                    zone: "desktop".into(),
                    kind: DfdKind::Process,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn buffer_text(buf: &Buffer, width: u16, height: u16) -> String {
        (0..height)
            .map(|y| (0..width).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
}
