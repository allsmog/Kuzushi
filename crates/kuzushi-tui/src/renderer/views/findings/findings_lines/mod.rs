use super::*;

mod empty_state;
mod filter_chips;
mod finding_table;

pub(crate) fn findings_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(filter_chips::filter_chip_line(app));
    lines.push(blank());

    if app.findings.is_empty() {
        empty_state::append_empty_findings(app, area, &mut lines);
        return lines;
    }

    finding_table::append_finding_table(app, area, &mut lines);
    lines
}
