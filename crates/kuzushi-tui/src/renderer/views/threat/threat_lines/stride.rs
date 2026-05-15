use super::*;

pub(super) fn append_stride_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let rollup = crate::ui_view_models::threat_stride_rollup(app);
    let total_issues: usize = rollup.iter().map(|row| row.count).sum();
    lines.push(section_header_line(
        &format!("STRIDE ROLLUP · {total_issues} issues"),
        area.width,
    ));
    for row in &rollup {
        lines.push(stride_row(
            row.letter,
            row.severity,
            row.category,
            row.count,
            &row.description,
            area.width,
        ));
    }
}
