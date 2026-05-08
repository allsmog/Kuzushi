use super::*;

pub(super) fn append_stride_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let doc = current_threat_model_doc(app);
    let rollup = doc
        .as_ref()
        .and_then(stride_rollup_from_doc)
        .unwrap_or_else(stride_rollup_rows);
    let total_issues: usize = rollup.iter().map(|r| r.3).sum();
    lines.push(section_header_line(
        &format!("STRIDE ROLLUP · {total_issues} issues"),
        area.width,
    ));
    for (letter, sev, category, count, description) in &rollup {
        lines.push(stride_row(
            letter,
            *sev,
            category,
            *count,
            description,
            area.width,
        ));
    }
}
