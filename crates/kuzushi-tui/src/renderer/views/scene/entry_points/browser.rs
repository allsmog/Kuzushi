use super::{
    browser_summary_text, digest_summary, disposition_summary, entry_detail_lines, fit,
    paired_digest_summary, provenance_summary, receipt_count_summary, responsive_summary,
    revision_summary, timestamp_summary,
};
use crate::renderer::shared::text::{display_width, fit_path, pad};
use crate::theme;
use crate::ui_view_models::{EntryPointBreakdown, EntryPointItem};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use std::sync::Arc;

const WIDE_LAYOUT_MIN: u16 = 90;
const PANE_GAP: u16 = 1;
/// Widest the list pane grows beside the detail pane. A real catalog names
/// most rows by kind alone, so the list needs room for a name *and* the
/// location that separates two of them; the detail pane still keeps the
/// larger share at every width that reaches this cap.
const LIST_PANE_MAX: u16 = 60;
const LIST_PANE_MIN: u16 = 32;
const SOURCE_SEPARATOR: &str = " · ";
/// Below this the location is fragments rather than a file and line, and
/// below `MIN_NAME_COLUMNS` the name it would displace stops reading.
const MIN_SOURCE_COLUMNS: usize = 10;
const MIN_NAME_COLUMNS: usize = 8;

pub(crate) struct EntryPointBrowser {
    pub model: Arc<EntryPointBreakdown>,
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
                &[
                    ("entry-points:extract", "extract concrete ingress surfaces"),
                    ("threat-model:build", "model extracted surfaces"),
                ],
            );
            return;
        }
        render_browser(
            buf,
            area,
            self.model.as_ref(),
            self.selection,
            self.detail_scroll,
        );
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
    let (summary, compact_summary) = frame_summary_text(area, model);
    let summary_height = (summary.len() as u16).min(area.height);
    render_summary(buf, summary_area(area, summary_height), summary);
    let body = body_area(area, summary_height);
    if area.width >= WIDE_LAYOUT_MIN && body.height >= 8 {
        render_wide(buf, body, model, selection, detail_scroll, compact_summary);
    } else {
        render_stacked(buf, body, model, selection, detail_scroll, compact_summary);
    }
}

fn frame_summary_text(area: Rect, model: &EntryPointBreakdown) -> (Vec<String>, bool) {
    let full = browser_summary_text(area.width as usize, model);
    let compact = area.height.saturating_sub(full.len() as u16) < 10;
    if !compact {
        return (full, false);
    }
    let width = area.width as usize;
    let mut lines = vec![
        responsive_summary(width, model),
        disposition_summary(width, model),
        provenance_summary(width, model),
        receipt_count_summary(width, model),
    ];
    if !model.receipt.warnings.is_empty() {
        lines.push(fit(
            &format!("WARNING · {}", model.receipt.warnings.join(" · ")),
            width,
        ));
    }
    (lines, true)
}

fn summary_area(area: Rect, height: u16) -> Rect {
    Rect { height, ..area }
}

fn body_area(area: Rect, summary_height: u16) -> Rect {
    Rect {
        y: area.y.saturating_add(summary_height),
        height: area.height.saturating_sub(summary_height),
        ..area
    }
}

fn render_summary(buf: &mut Buffer, area: Rect, summary: Vec<String>) {
    let lines = summary
        .into_iter()
        .enumerate()
        .map(|(index, text)| {
            let style = if index == 0 {
                theme::accent()
            } else {
                theme::muted()
            };
            Line::styled(text, style)
        })
        .collect::<Vec<_>>();
    Paragraph::new(lines).render(area, buf);
}

fn render_wide(
    buf: &mut Buffer,
    area: Rect,
    model: &EntryPointBreakdown,
    selection: usize,
    detail_scroll: usize,
    compact_summary: bool,
) {
    let list_width = (area.width * 2 / 5).clamp(LIST_PANE_MIN, LIST_PANE_MAX);
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
    render_entry_detail(
        buf,
        detail,
        model,
        selection,
        detail_scroll,
        compact_summary,
    );
}

fn render_stacked(
    buf: &mut Buffer,
    area: Rect,
    model: &EntryPointBreakdown,
    selection: usize,
    detail_scroll: usize,
    compact_summary: bool,
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
    render_entry_detail(
        buf,
        detail,
        model,
        selection,
        detail_scroll,
        compact_summary,
    );
}

fn stacked_list_height(height: u16) -> u16 {
    let preferred = if height < 10 {
        height.saturating_sub(3).max(2)
    } else {
        (height / 3).clamp(5, 10)
    };
    let max_with_detail = height.saturating_sub(PANE_GAP + 3).max(2);
    preferred.min(max_with_detail)
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
    let visible = visible_entry_list_lines(
        model,
        selection,
        inner.width as usize,
        inner.height as usize,
    );
    Paragraph::new(visible).render(inner, buf);
}

struct EntryListSection<'a> {
    disposition: &'a str,
    count: usize,
    entry_start: usize,
    row_start: usize,
}

fn visible_entry_list_lines(
    model: &EntryPointBreakdown,
    selection: usize,
    width: usize,
    visible: usize,
) -> Vec<Line<'static>> {
    let sections = entry_list_sections(model);
    let total = model.entries.len().saturating_add(sections.len());
    let selected_row = selected_display_row(&sections, selection);
    let start = viewport_start(total, visible, selected_row);
    (start..start.saturating_add(visible).min(total))
        .filter_map(|row| display_row_line(model, &sections, row, selection, width))
        .collect()
}

fn entry_list_sections(model: &EntryPointBreakdown) -> Vec<EntryListSection<'_>> {
    let mut entry_start = 0usize;
    model
        .dispositions
        .iter()
        .enumerate()
        .map(|(section_index, group)| {
            let section = EntryListSection {
                disposition: &group.name,
                count: group.count,
                entry_start,
                row_start: entry_start + section_index,
            };
            entry_start = entry_start.saturating_add(group.count);
            section
        })
        .collect()
}

fn selected_display_row(sections: &[EntryListSection<'_>], selection: usize) -> usize {
    sections
        .iter()
        .find(|section| selection < section.entry_start.saturating_add(section.count))
        .map_or(selection, |section| {
            section.row_start + 1 + selection.saturating_sub(section.entry_start)
        })
}

fn display_row_line(
    model: &EntryPointBreakdown,
    sections: &[EntryListSection<'_>],
    row: usize,
    selection: usize,
    width: usize,
) -> Option<Line<'static>> {
    let section = sections.iter().find(|section| {
        row >= section.row_start && row <= section.row_start.saturating_add(section.count)
    })?;
    if row == section.row_start {
        let label = format!(
            " {} · {}",
            section.disposition.to_uppercase(),
            section.count
        );
        return Some(Line::styled(fit(&label, width), theme::label()));
    }
    let index = section.entry_start + row.saturating_sub(section.row_start + 1);
    model
        .entries
        .get(index)
        .map(|entry| entry_row(entry, index == selection, width))
}

fn entry_row(entry: &EntryPointItem, selected: bool, width: usize) -> Line<'static> {
    let marker = if selected { "›" } else { " " };
    let style = if selected {
        theme::accent()
    } else {
        theme::primary()
    };
    Line::styled(entry_row_text(entry, marker, width), style)
}

/// A real catalog names most rows by kind alone — one audited target carries
/// 512 rows titled "Deserialization or parser boundary" — so the row's own
/// `path:line` is the only thing that tells two of them apart without opening
/// each in turn. Keep it on the row, truncated from the left so the file and
/// line survive a narrow pane, and pad the name so the locations line up.
fn entry_row_text(entry: &EntryPointItem, marker: &str, width: usize) -> String {
    let name = format!("{marker} {}", entry.name);
    let Some(source) = entry.recorded_source() else {
        return fit(&name, width);
    };
    let source_width = source_columns(source, width);
    if source_width == 0 {
        return fit(&name, width);
    }
    let name_width = width - source_width - display_width(SOURCE_SEPARATOR);
    format!(
        "{}{SOURCE_SEPARATOR}{}",
        pad(&name, name_width),
        fit_path(source, source_width)
    )
}

/// Columns the location may take: never more than it needs, never more than
/// half the row, and none at all when what remains could not hold a name.
fn source_columns(source: &str, width: usize) -> usize {
    let budget = (width / 2).min(display_width(source));
    let name_room = width.saturating_sub(budget + display_width(SOURCE_SEPARATOR));
    if budget < MIN_SOURCE_COLUMNS || name_room < MIN_NAME_COLUMNS {
        return 0;
    }
    budget
}

fn render_entry_detail(
    buf: &mut Buffer,
    area: Rect,
    model: &EntryPointBreakdown,
    selection: usize,
    detail_scroll: usize,
    compact_summary: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let Some(entry) = model.entries.get(selection) else {
        return;
    };
    let width = area.width.saturating_sub(2) as usize;
    let lines = browser_detail_lines(width, model, entry, compact_summary);
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

fn browser_detail_lines(
    width: usize,
    model: &EntryPointBreakdown,
    entry: &EntryPointItem,
    compact_summary: bool,
) -> Vec<Line<'static>> {
    let mut lines = entry_detail_lines(width, entry);
    if !compact_summary {
        return lines;
    }
    lines.push(Line::from(String::new()));
    lines.push(Line::styled("SOURCE RECEIPT", theme::label()));
    lines.extend(receipt_detail_lines(width, model));
    append_warning_details(&mut lines, width, model);
    lines
}

fn receipt_detail_lines(
    width: usize,
    model: &EntryPointBreakdown,
) -> impl Iterator<Item = Line<'static>> {
    [
        revision_summary(width, model),
        digest_summary(width, "C SHA256", model.receipt.catalog_digest.as_deref()),
        digest_summary(
            width,
            "M SHA256",
            model.receipt.model_catalog_digest.as_deref(),
        ),
        paired_digest_summary(
            width,
            "CONTEXT",
            model.receipt.context_digest.as_deref(),
            model.receipt.model_context_digest.as_deref(),
        ),
        paired_digest_summary(
            width,
            "TREE",
            model.receipt.tree_hash.as_deref(),
            model.receipt.model_tree_hash.as_deref(),
        ),
        timestamp_summary(width, model),
    ]
    .into_iter()
    .map(|text| Line::styled(text, theme::muted()))
}

fn append_warning_details(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    model: &EntryPointBreakdown,
) {
    if model.receipt.warnings.is_empty() {
        return;
    }
    lines.push(Line::styled("WARNINGS", theme::label()));
    for warning in &model.receipt.warnings {
        lines.extend(
            crate::renderer::shared::text::wrap_text(warning, width)
                .into_iter()
                .map(|text| Line::styled(text, theme::muted())),
        );
    }
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
    use crate::ui_view_models::{
        EntryPointArtifactStatus, EntryPointComposition, EntryPointCounts, EntryPointDisposition,
        EntryPointFreshness, EntryPointGroup, EntryPointReceipt, EntryPointTarget,
    };

    #[test]
    fn browser_keeps_selection_and_detail_visible_across_width_classes() {
        for (width, height) in [(160, 48), (120, 36), (80, 24), (40, 30), (24, 24)] {
            let text = render_to_text(
                EntryPointBrowser {
                    model: Arc::new(sample_model()),
                    selection: 0,
                    detail_scroll: 0,
                },
                width,
                height,
            );

            assert!(text.contains("ENTRY POINTS"), "{width}x{height}\n{text}");
            assert!(text.contains("POST /admin"), "{width}x{height}\n{text}");
            assert!(text.contains("EP-1"), "{width}x{height}\n{text}");
            if width >= 40 {
                assert!(text.contains("internet"), "{width}x{height}\n{text}");
            }
        }
    }

    #[test]
    fn full_shell_80x24_keeps_selected_detail_visible() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let model_path = kuzushi_core::capabilities::persistent_threat_model_path(target.path());
        std::fs::create_dir_all(model_path.parent().unwrap()).unwrap();
        std::fs::write(
            model_path,
            serde_json::json!({
                "attackSurface": {"entryPoints": [{
                    "id": "EP-narrow",
                    "name": "narrow route",
                    "kind": "http_route",
                    "trustZone": "internet",
                    "targetElementIds": []
                }]}
            })
            .to_string(),
        )
        .unwrap();
        let mut app = crate::ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.router
            .scene_mut()
            .set_page(crate::scene3d::VizPage::EntryPoints);
        app.set_shell_view(crate::ShellView::Scene);
        app.hydrate_all_view_data_for_test();
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = buffer_text(terminal.backend().buffer());

        assert!(text.contains("narrow route"), "{text}");
        assert!(
            text.contains("kind"),
            "selected detail must be visible:\n{text}"
        );
        assert!(text.contains("http route"), "{text}");
        assert!(text.contains("threat model only"), "{text}");
    }

    #[test]
    fn detail_scroll_exposes_tail_without_moving_selection() {
        let mut model = sample_model();
        model.entries[0].evidence = "evidence ".repeat(40);

        let text = render_to_text(
            EntryPointBrowser {
                model: Arc::new(model),
                selection: 0,
                detail_scroll: usize::MAX,
            },
            40,
            18,
        );

        assert!(text.contains("rows"), "{text}");
        assert!(text.contains("CONTEXT"), "{text}");
        assert!(text.contains("T(ms)"), "{text}");
        assert!(text.contains("EP-1"), "{text}");
    }

    #[test]
    fn large_catalog_viewport_reaches_the_last_of_six_hundred_rows() {
        let mut model = sample_model();
        model.entries = (0..600)
            .map(|index| EntryPointItem {
                id: format!("EP-{index:03}"),
                name: format!("entry {index:03}"),
                ..model.entries[0].clone()
            })
            .collect();
        model.dispositions[0].count = 600;

        let text = render_to_text(
            EntryPointBrowser {
                model: Arc::new(model.clone()),
                selection: 599,
                detail_scroll: 0,
            },
            80,
            24,
        );

        assert!(text.contains("entry 599"), "{text}");
        assert!(text.contains("EP-599"), "{text}");
        let formatted = visible_entry_list_lines(&model, 599, 40, 10);
        assert_eq!(formatted.len(), 10, "only viewport rows are formatted");
        assert!(formatted
            .iter()
            .any(|line| line.to_string().contains("entry 599")));
        assert_eq!(viewport_start(600, 10, 599), 590);
        assert_eq!(viewport_start(600, 10, 0), 0);
        assert_eq!(viewport_start(600, 10, 300), 296);
    }

    /// The defect this guards: a real catalog titles hundreds of rows by kind
    /// alone, and the list used to render nothing but that title.
    #[test]
    fn rows_sharing_a_generic_title_are_told_apart_by_their_own_location() {
        let model = generic_title_model();

        let rows = visible_entry_list_lines(&model, 0, 46, 8)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert!(rows.iter().any(|row| row.contains("parse/frames.rs:18")));
        assert!(rows.iter().any(|row| row.contains("wire/codec.rs:204")));
        assert!(rows.iter().any(|row| row.contains("codec.rs:9")));
        for row in &rows {
            assert!(display_width(row) <= 46, "row overflows the pane: {row}");
        }
    }

    #[test]
    fn a_row_without_a_recorded_location_carries_only_its_name() {
        let mut entry = sample_model().entries.remove(0);
        entry.source = "not recorded".into();

        assert_eq!(entry_row_text(&entry, "›", 46).trim_end(), "› POST /admin");
    }

    /// A location cropped to fragments explains less than the name it would
    /// displace, so the narrow row keeps the name whole instead.
    #[test]
    fn a_pane_too_narrow_for_both_keeps_the_name() {
        let entry = sample_model().entries.remove(0);

        let row = entry_row_text(&entry, "›", 20);

        assert_eq!(row, "› POST /admin");
        assert_eq!(source_columns("src/routes.rs:42", 20), 0);
    }

    #[test]
    fn a_long_location_keeps_its_file_and_line_rather_than_its_repository_prefix() {
        let mut entry = sample_model().entries.remove(0);
        entry.source = "crates/kuzushi-core/src/modules/registry/dispatch.rs:1180".into();

        let row = entry_row_text(&entry, " ", 46);

        assert!(row.ends_with("dispatch.rs:1180"), "{row}");
        assert_eq!(display_width(&row), 46, "{row}");
    }

    fn generic_title_model() -> EntryPointBreakdown {
        let template = sample_model();
        let mut model = template.clone();
        model.entries = ["parse/frames.rs:18", "wire/codec.rs:204", "codec.rs:9"]
            .iter()
            .enumerate()
            .map(|(index, source)| EntryPointItem {
                id: format!("EP-{index}"),
                name: "Deserialization or parser boundary".into(),
                source: (*source).into(),
                ..template.entries[0].clone()
            })
            .collect();
        model.dispositions[0].count = model.entries.len();
        model
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
                risk: "high · score 78".into(),
                disposition: EntryPointDisposition::Modeled,
                disposition_note: "catalog row linked to current threat-model context".into(),
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
            dispositions: vec![EntryPointGroup {
                name: "modeled".into(),
                count: 1,
            }],
            counts: EntryPointCounts {
                extracted: 1,
                modeled: 1,
                overlap: 1,
                union: 1,
                ..Default::default()
            },
            receipt: EntryPointReceipt {
                catalog_artifact: EntryPointArtifactStatus::Ready,
                model_artifact: EntryPointArtifactStatus::Ready,
                composition: EntryPointComposition::Current,
                freshness: EntryPointFreshness::Current,
                records: Some(1),
                records_selected: Some(1),
                records_linked: Some(1),
                ..Default::default()
            },
            linked_target_count: 1,
            target_count: 1,
            empty_hint: None,
        }
    }

    fn render_to_text(widget: impl Widget, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buffer = Buffer::empty(area);
        widget.render(area, &mut buffer);
        buffer_text(&buffer)
    }

    fn buffer_text(buffer: &Buffer) -> String {
        let area = buffer.area;
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
