use super::*;
use crate::ui_view_models::findings_model;

mod empty_state;
mod filter_chips;
mod finding_table;

pub(crate) fn findings_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = findings_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(filter_chips::filter_chip_line(&model));
    lines.push(blank());

    if model.rows.is_empty() {
        empty_state::append_empty_findings(&model, area, &mut lines);
        return lines;
    }

    finding_table::append_finding_table(&model, area, &mut lines);
    lines
}
