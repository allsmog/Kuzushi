use super::*;

#[cfg(test)]
#[path = "logs/tests.rs"]
mod tests;

/// Full-screen scrollable transcript view (M1 §1.1). Unlike the embedded
/// 2-row transcript strip at the bottom of every other view, this paints
/// the entire log buffer; `j`/`k`/`g`/`G`/`PgUp`/`PgDn` page through it.
pub(crate) fn logs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = logs_model(app);
    let mut lines = logs_header(app, area, &model.summary);
    if let Some(notice) = model.notice.as_deref() {
        lines.push(Line::styled(
            fit(&format!(" {notice}"), area.width as usize),
            theme::warn(),
        ));
    }
    for row in model.rows {
        lines.extend(wrapped_log_lines(
            &row.prefix,
            &row.body,
            row.continuation,
            row.time_secs,
            area.width as usize,
        ));
    }
    lines
}

fn logs_header(app: &ShellApp, area: Rect, summary: &str) -> Vec<Line<'static>> {
    let follow = if app.router.logs().is_following() {
        "following"
    } else {
        "paused · G follows"
    };
    if app.router.logs().reader_open() {
        let commands = if app.router.logs().command_text_expanded() {
            " · command text"
        } else {
            ""
        };
        return vec![muted(&fit(
            &format!("{summary}{commands} · {follow}"),
            usize::from(area.width),
        ))];
    }
    if area.height <= 16 {
        return vec![muted(&fit(
            &format!("LOGS · z expand · {summary} · {follow}"),
            usize::from(area.width),
        ))];
    }
    let mut lines = context_strip(app, area);
    if lines.len() == 1 {
        lines.push(blank());
    }
    lines.push(divider("LOGS", area.width));
    let hint = format!(
        "{} · {follow} · z expand · / filter · j/k scroll · g/G jump · back to return",
        summary
    );
    lines.push(muted(&fit(&hint, area.width as usize)));
    lines
}

/// Rows the Logs view pins above the scrolling body: the context strip, the
/// blank, the `LOGS` divider, the summary hint, and any notice.
pub(crate) fn logs_pinned_rows(app: &ShellApp, area: Rect) -> usize {
    let notice = usize::from(logs_model(app).notice.is_some());
    logs_header(app, area, "").len() + notice
}

pub(crate) struct LogsReaderScroll {
    pub(crate) max_offset: usize,
    pub(crate) page_rows: usize,
}

pub(crate) fn logs_reader_scroll(app: &ShellApp) -> Option<LogsReaderScroll> {
    if app.shell_view() != ShellView::Logs {
        return None;
    }
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    let area = logs_reading_area(app, full);
    let rows = logs_lines(app, area).len();
    let pinned = logs_pinned_rows(app, area);
    let height = usize::from(area.height);
    let body_height = height.saturating_sub(pinned + 1).max(1);
    let max_offset = if rows <= height {
        0
    } else {
        rows.saturating_sub(pinned + body_height)
    };
    Some(LogsReaderScroll {
        max_offset,
        page_rows: body_height,
    })
}

fn logs_reading_area(app: &ShellApp, full: Rect) -> Rect {
    if app.router.logs().reader_open() {
        return crate::renderer::logs_reader::reader_area(full);
    }
    crate::renderer::workbench_primary_area(app, full)
}

fn wrapped_log_lines(
    prefix: &str,
    body: &str,
    continuation: bool,
    time_secs: u64,
    width: usize,
) -> Vec<Line<'static>> {
    let first_prefix = line_width(&transcript_line_dated(prefix, "", continuation, time_secs));
    let next_prefix = line_width(&transcript_line_dated(prefix, "", true, 0));
    wrapped_log_body(
        body,
        width.saturating_sub(first_prefix).max(8),
        width.saturating_sub(next_prefix).max(8),
    )
    .into_iter()
    .enumerate()
    .map(|(index, chunk)| {
        transcript_line_dated(
            prefix,
            &chunk,
            continuation || index > 0,
            if index == 0 { time_secs } else { 0 },
        )
    })
    .collect()
}

fn wrapped_log_body(body: &str, first_width: usize, next_width: usize) -> Vec<String> {
    wrap_document_text(body, first_width, next_width)
}

fn line_width(line: &Line<'_>) -> usize {
    display_width(&line_text(line))
}

fn line_text(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}
