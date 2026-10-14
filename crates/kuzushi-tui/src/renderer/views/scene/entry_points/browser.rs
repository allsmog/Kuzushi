use super::{entry_detail_lines, fit};
use layout::browser_layout;
mod layout;
mod receipt;
use crate::renderer::shared::text::{display_width, fit_path, pad};
use crate::theme;
use crate::ui_view_models::{EntryPointBreakdown, EntryPointItem};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use std::sync::Arc;

#[cfg(test)]
mod reading_tests;

const SOURCE_SEPARATOR: &str = " · ";
/// Narrowest a *truncated* location may be before it reads as fragments
/// rather than a file and line. A location that already fits whole is never
/// held to it — a complete `a.py:1` identifies its row as well as any longer
/// path does. Below `MIN_NAME_COLUMNS` the name it would displace stops
/// reading, and then the location is dropped instead.
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
    let layout = browser_layout(area, model);
    render_summary(buf, layout.summary_area, layout.summary);
    render_entry_list(buf, layout.list, model, selection);
    render_entry_detail(buf, layout.detail, model, selection, detail_scroll);
}

pub(crate) fn entry_point_page_scroll(app: &crate::ShellApp, direction: i32) -> Option<usize> {
    let area = super::super::gallery_layout::gallery_body_area(app)?;
    let model = crate::ui_view_models::entry_point_breakdown(app);
    let selection = app
        .router
        .scene()
        .entry_point_selection()
        .min(model.entries.len().saturating_sub(1));
    let entry = model.entries.get(selection)?;
    let layout = browser_layout(area, &model);
    let visible = layout.detail.height.saturating_sub(2) as usize;
    if visible == 0 {
        return None;
    }
    let lines = browser_detail_lines(
        layout.detail.width.saturating_sub(2) as usize,
        &model,
        entry,
    );
    Some(layout::page_offset(
        app.router.scene().entry_point_detail_scroll(),
        direction,
        visible,
        lines.len(),
    ))
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

fn render_entry_list(buf: &mut Buffer, area: Rect, model: &EntryPointBreakdown, selection: usize) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    if area.height < 3 {
        Paragraph::new(visible_entry_list_lines(
            model,
            selection,
            area.width as usize,
            1,
        ))
        .render(area, buf);
        return;
    }
    let window = entry_list_window(model, selection, area.height.saturating_sub(2) as usize);
    let title = entry_list_title(model, selection, window);
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

/// The display rows (section headers plus entries) a viewport of `visible`
/// rows shows around the selection, and the catalog entries it leaves out
/// above and below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryListWindow {
    start: usize,
    end: usize,
    hidden_above: usize,
    hidden_below: usize,
}

fn entry_list_window(
    model: &EntryPointBreakdown,
    selection: usize,
    visible: usize,
) -> EntryListWindow {
    let sections = entry_list_sections(model);
    let total = model.entries.len().saturating_add(sections.len());
    let selected_row = selected_display_row(&sections, selection);
    let start = viewport_start(total, visible, selected_row);
    let end = start.saturating_add(visible).min(total);
    EntryListWindow {
        start,
        end,
        hidden_above: entries_before_row(&sections, start),
        hidden_below: model
            .entries
            .len()
            .saturating_sub(entries_before_row(&sections, end)),
    }
}

/// The catalog entries that sit above display row `row`. A disposition header
/// spends a display row without being a catalog entry, so scrolling one past
/// the top of the viewport hides pane chrome, not an entry.
fn entries_before_row(sections: &[EntryListSection<'_>], row: usize) -> usize {
    let headers = sections
        .iter()
        .filter(|section| section.row_start < row)
        .count();
    row.saturating_sub(headers)
}

/// The list title names the selection and, when the viewport clips the
/// catalog, how many entries sit above and below it — a hidden entry is never
/// silent, and nothing the operator can already see is reported as hidden.
fn entry_list_title(
    model: &EntryPointBreakdown,
    selection: usize,
    window: EntryListWindow,
) -> String {
    let mut parts = vec![format!(
        "ENTRY POINTS · {}/{}",
        selection.saturating_add(1),
        model.entries.len()
    )];
    if window.hidden_above > 0 {
        parts.push(format!("+{} above", window.hidden_above));
    }
    if window.hidden_below > 0 {
        parts.push(format!("+{} below", window.hidden_below));
    }
    format!(" {} ", parts.join(" · "))
}

fn visible_entry_list_lines(
    model: &EntryPointBreakdown,
    selection: usize,
    width: usize,
    visible: usize,
) -> Vec<Line<'static>> {
    let sections = entry_list_sections(model);
    let window = entry_list_window(model, selection, visible);
    (window.start..window.end)
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
/// half the row, and none at all when what remains could not hold a name or
/// when half the row would leave only a fragment of a long location.
fn source_columns(source: &str, width: usize) -> usize {
    let source_width = display_width(source);
    let budget = (width / 2).min(source_width);
    let name_room = width.saturating_sub(budget + display_width(SOURCE_SEPARATOR));
    let is_fragment = budget < source_width && budget < MIN_SOURCE_COLUMNS;
    if is_fragment || name_room < MIN_NAME_COLUMNS {
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
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let Some(entry) = model.entries.get(selection) else {
        return;
    };
    let width = area.width.saturating_sub(2) as usize;
    let lines = browser_detail_lines(width, model, entry);
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
) -> Vec<Line<'static>> {
    let mut lines: Vec<_> = crate::renderer::shared::text::wrap_text(&entry.name, width)
        .into_iter()
        .map(|text| Line::styled(text, theme::heading()))
        .collect();
    lines.extend(entry_detail_lines(width, entry).into_iter().skip(1));
    lines.push(Line::from(String::new()));
    lines.push(Line::styled("SOURCE RECEIPT", theme::label()));
    lines.extend(receipt::detail_lines(width, model));
    lines
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
    let identity = if display_width(&entry.id) <= 12 {
        format!("DETAIL {}", entry.id)
    } else {
        "DETAIL".to_string()
    };
    bordered_block(
        &format!(
            " {identity}{position} · {}/{} · PgUp/PgDn ",
            selection + 1,
            total
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
    fn a_clipped_entry_list_names_the_entries_it_hides() {
        let model = large_catalog_model(40);
        let entries = model.entries.len();

        let clipped = entry_list_window(&model, 0, 1);
        let title = entry_list_title(&model, 0, clipped);
        assert_eq!(clipped.hidden_below, entries - 1, "{clipped:?}");
        assert!(
            title.contains(&format!("+{} below", entries - 1)),
            "{title}"
        );

        let whole = entry_list_window(&model, 0, entries + model.dispositions.len());
        let title = entry_list_title(&model, 0, whole);
        assert!(
            !title.contains("below") && !title.contains("above"),
            "{title}"
        );
    }

    /// The defect this guards: on the first of 1250 entries an 80x24 viewport
    /// titled the list `+1 above`, because the disposition header scrolled
    /// past the top of the window counted as a hidden catalog entry. Nothing
    /// precedes the first entry, so no viewport height may claim otherwise.
    #[test]
    fn the_first_entry_is_never_reported_as_having_entries_above_it() {
        let model = large_catalog_model(1250);

        for visible in 1..=24 {
            let window = entry_list_window(&model, 0, visible);
            assert_eq!(window.hidden_above, 0, "visible={visible} {window:?}");
            let title = entry_list_title(&model, 0, window);
            assert!(!title.contains("above"), "visible={visible} {title}");
        }
    }

    /// Hidden counts partition the catalog: what the title says is clipped
    /// plus what the viewport formats is the whole catalog, across every
    /// selection and viewport height, with headers belonging to neither side.
    #[test]
    fn hidden_entry_counts_account_for_the_whole_catalog() {
        let model = two_disposition_model();
        let entries = model.entries.len();

        for selection in 0..entries {
            for visible in 1..=entries + 2 {
                let window = entry_list_window(&model, selection, visible);
                let shown = visible_entry_list_lines(&model, selection, 60, visible)
                    .iter()
                    .filter(|line| line.to_string().contains("entry "))
                    .count();
                assert_eq!(
                    window.hidden_above + shown + window.hidden_below,
                    entries,
                    "selection={selection} visible={visible} shown={shown} {window:?}"
                );
            }
        }
    }

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
        assert!(text.contains("model only"), "{text}");
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
        assert!(text.contains("TIMESTAMPS MS"), "{text}");
        assert!(text.contains("EP-1"), "{text}");
    }

    #[test]
    fn large_catalog_viewport_reaches_the_last_of_six_hundred_rows() {
        let model = large_catalog_model(600);

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

    /// The fragment floor guards truncation, not shortness: a complete
    /// `a.py:1` tells its row apart from the next one just as well as a long
    /// path does, and a pane with room to spare must not suppress it.
    #[test]
    fn a_short_but_complete_location_still_reaches_the_row() {
        let mut entry = sample_model().entries.remove(0);
        entry.source = "a.py:1".into();

        assert_eq!(source_columns("a.py:1", 46), display_width("a.py:1"));
        assert!(entry_row_text(&entry, " ", 46).ends_with("a.py:1"));
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

    /// One disposition group holding `entries` rows, named so a formatted row
    /// is told apart from the group header above it.
    fn large_catalog_model(entries: usize) -> EntryPointBreakdown {
        let template = sample_model();
        let mut model = template.clone();
        model.entries = (0..entries)
            .map(|index| EntryPointItem {
                id: format!("EP-{index:03}"),
                name: format!("entry {index:03}"),
                ..template.entries[0].clone()
            })
            .collect();
        model.dispositions[0].count = entries;
        model
    }

    /// Two disposition groups, so the clip math meets more than one header
    /// row and a viewport can sit below both of them.
    fn two_disposition_model() -> EntryPointBreakdown {
        let mut model = large_catalog_model(9);
        model.dispositions = vec![
            EntryPointGroup {
                name: "modeled".into(),
                count: 4,
            },
            EntryPointGroup {
                name: "extracted only".into(),
                count: 5,
            },
        ];
        model
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

    pub(super) fn sample_model() -> EntryPointBreakdown {
        EntryPointBreakdown {
            entries: vec![EntryPointItem {
                id: "EP-1".into(),
                name: "POST /admin".into(),
                kind: "http_route".into(),
                trust_zone: "internet".into(),
                description: "Administrative route".into(),
                ingress: "POST /admin".into(),
                source: "src/routes.rs:42".into(),
                source_framework: None,
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

    pub(super) fn render_to_text(widget: impl Widget, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buffer = Buffer::empty(area);
        widget.render(area, &mut buffer);
        buffer_text(&buffer)
    }

    pub(super) fn buffer_text(buffer: &Buffer) -> String {
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
