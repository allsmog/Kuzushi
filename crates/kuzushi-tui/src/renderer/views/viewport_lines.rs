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
