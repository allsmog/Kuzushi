use super::*;

pub(crate) fn viewport_lines(
    lines: Vec<Line<'static>>,
    visible_height: u16,
    scroll: usize,
) -> Vec<Line<'static>> {
    let visible = visible_height as usize;
    if visible == 0 {
        return Vec::new();
    }
    if lines.len() <= visible {
        return lines;
    }
    let start = scroll.min(lines.len().saturating_sub(visible));
    lines.into_iter().skip(start).take(visible).collect()
}

pub(crate) fn pinned_document_viewport_lines(
    mut lines: Vec<Line<'static>>,
    visible_height: u16,
    scroll: usize,
    pinned_rows: usize,
) -> Vec<Line<'static>> {
    let visible = visible_height as usize;
    if visible == 0 || lines.len() <= visible {
        return lines.into_iter().take(visible).collect();
    }
    let pinned_count = pinned_rows.min(lines.len()).min(visible);
    let body = lines.split_off(pinned_count);
    if visible <= pinned_count {
        return lines;
    }
    if visible == pinned_count + 1 {
        let row = scroll.min(body.len().saturating_sub(1)) + 1;
        lines.push(Line::styled(
            format!(" row {row}/{}", body.len()),
            theme::muted(),
        ));
        return lines;
    }
    let capacity = visible - pinned_count - 1;
    let start = scroll.min(body.len().saturating_sub(capacity));
    let end = start.saturating_add(capacity).min(body.len());
    lines.push(Line::styled(
        format!(" rows {}-{}/{}", start + 1, end, body.len()),
        theme::muted(),
    ));
    lines.extend(body.into_iter().skip(start).take(capacity));
    lines
}

pub(crate) fn viewport_start_for_cursor(
    total_rows: usize,
    visible_rows: usize,
    cursor: usize,
) -> usize {
    if total_rows <= visible_rows || visible_rows == 0 {
        return 0;
    }
    let max_start = total_rows.saturating_sub(visible_rows);
    let margin = visible_rows.saturating_sub(1) / 2;
    cursor.saturating_sub(margin).min(max_start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_document_keeps_identity_title_and_position_while_scrolling() {
        let lines = ["KUZUSHI", "", "TOOLS", "one", "two", "three", "four"]
            .into_iter()
            .map(Line::raw)
            .collect();

        let rendered = pinned_document_viewport_lines(lines, 6, usize::MAX, 3)
            .into_iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();

        assert_eq!(&rendered[..3], ["KUZUSHI", "", "TOOLS"]);
        assert!(rendered[3].starts_with(" rows "), "{rendered:?}");
        assert_eq!(&rendered[4..], ["three", "four"]);
    }

    #[test]
    fn pinned_document_uses_its_only_spare_row_for_position() {
        let lines = ["KUZUSHI", "", "HELP", "one", "two"]
            .into_iter()
            .map(Line::raw)
            .collect();

        let rendered = pinned_document_viewport_lines(lines, 4, 1, 3)
            .into_iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();

        assert_eq!(rendered, ["KUZUSHI", "", "HELP", " row 2/2"]);
    }
}
