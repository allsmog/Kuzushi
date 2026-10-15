use super::*;

const FILE_PICKER_HEADER_LINES: u16 = 8;

pub(crate) fn file_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if app.router.file_picker().purpose() == crate::app::FilePickerPurpose::ReviewEvidence {
        return crate::renderer::review_source_files::lines(app, area);
    }
    let mut lines: Vec<Line<'static>> = Vec::new();
    let document = app.router.file_picker().purpose() == crate::app::FilePickerPurpose::MapDocument;
    lines.push(divider(
        if document {
            "CHOOSE A DESIGN DOCUMENT"
        } else {
            "ATTACH A FILE"
        },
        area.width,
    ));
    lines.push(blank());
    let hint = if document {
        "Choose a target file to add to the Map plan."
    } else {
        "Choose a target file to attach as context."
    };
    lines.extend(
        wrap_text(hint, area.width as usize)
            .into_iter()
            .map(|line| muted(&line)),
    );
    lines.push(file_picker_query_line(app, area.width));
    lines.push(file_picker_count_line(app, area.width));
    lines.push(blank());
    push_file_picker_rows(app, area, &mut lines);
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("type", "filter"),
        ("↑/↓", "move"),
        ("Enter", if document { "choose" } else { "attach" }),
        ("Esc", "back"),
    ]));
    lines
}

fn file_picker_query_line(app: &ShellApp, width: u16) -> Line<'static> {
    let route = app.router.file_picker();
    let mut line = Line::from(Span::styled("filter: ", theme::label()));
    if let Some(field) =
        field_editor_lines(route.query_field(), width.saturating_sub(8) as usize, 1)
            .into_iter()
            .next()
    {
        line.spans.extend(field.spans);
    }
    line
}

fn file_picker_count_line(app: &ShellApp, width: u16) -> Line<'static> {
    let matches = app.filtered_file_picker_paths().len();
    let route = app.router.file_picker();
    let suffix = if route.truncated() {
        " · partial index · paste exact path if missing"
    } else {
        ""
    };
    Line::styled(
        fit(
            &format!(
                "{} shown · {} indexed{suffix}",
                matches,
                route.files().len()
            ),
            width as usize,
        ),
        theme::muted(),
    )
}

fn push_file_picker_rows(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let matches = app.filtered_file_picker_paths();
    if matches.is_empty() {
        lines.push(muted("  no files match the current filter"));
        return;
    }
    let visible = visible_row_count(area.height);
    let start = row_window_start(app.router.file_picker().cursor(), matches.len(), visible);
    for (idx, path) in matches.iter().enumerate().skip(start).take(visible) {
        lines.push(file_picker_row(app, idx, path, area.width));
    }
}

fn visible_row_count(height: u16) -> usize {
    height.saturating_sub(FILE_PICKER_HEADER_LINES).max(4) as usize
}

fn row_window_start(cursor: usize, len: usize, visible: usize) -> usize {
    if len <= visible {
        return 0;
    }
    cursor.saturating_sub(visible / 2).min(len - visible)
}

fn file_picker_row(app: &ShellApp, idx: usize, path: &str, width: u16) -> Line<'static> {
    let selected = idx == app.router.file_picker().cursor();
    let marker = if selected { ">" } else { " " };
    let body = format!("  {marker} {path}");
    let style = if selected {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(fit(&body, width as usize), style)
}
