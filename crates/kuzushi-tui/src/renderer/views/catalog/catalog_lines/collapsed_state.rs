use super::*;
use crate::ui_view_models::CatalogModel;

pub(super) fn append_collapsed_catalog(
    model: &CatalogModel,
    area: Rect,
    lines: &mut Vec<Line<'static>>,
) {
    append_warning(model, lines);
    append_next_action(model, area, lines);
    append_start_path(model, area.width, lines);
    append_shortcuts(lines);
}

fn append_warning(model: &CatalogModel, lines: &mut Vec<Line<'static>>) {
    if let Some(warning) = model.collapsed.target_warning {
        lines.push(styled(warning, theme::warn()));
    }
}

fn append_next_action(model: &CatalogModel, area: Rect, lines: &mut Vec<Line<'static>>) {
    lines.push(next_action_line(
        catalog_next_hint(model),
        area.width as usize,
    ));
    if let Some(hint) = &model.collapsed.scan_hint {
        lines.push(muted(&fit(hint, area.width as usize)));
    }
}

fn append_start_path(model: &CatalogModel, width: u16, lines: &mut Vec<Line<'static>>) {
    if width < 96 {
        lines.push(Line::from(vec![
            Span::styled("Start here: ", theme::muted()),
            Span::styled("kuzushi doctor --target .", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("context build", theme::accent()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Then: ", theme::muted()),
            Span::styled(model.collapsed.scan_command, theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("findings", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("pr-comment", theme::accent()),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Start here: ", theme::muted()),
            Span::styled("kuzushi doctor --target .", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("context build", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled(model.collapsed.scan_command, theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("findings", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("pr-comment", theme::accent()),
        ]));
    }
}

fn append_shortcuts(lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(vec![
        Span::styled("Quickstart: ", theme::muted()),
        Span::styled("quickstart", theme::accent()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("Context: ", theme::muted()),
        Span::styled("context build", theme::accent()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("Runtime: ", theme::muted()),
        Span::styled("model", theme::accent()),
    ]));
    lines.push(muted(
        "Type help, modules, use <module>, scan, or run <tool> [key=value].",
    ));
}
