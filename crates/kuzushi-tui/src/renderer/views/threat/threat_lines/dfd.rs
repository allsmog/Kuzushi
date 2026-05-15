use super::*;

pub(super) fn append_dfd_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    lines.push(section_header_line("DFD · acme-checkout", area.width));
    lines.extend(dfd_canonical_lines());
    let Some(model) = crate::ui_view_models::threat_dfd_model(app) else {
        return;
    };
    lines.push(blank());
    lines.push(section_header_line(&model.header, area.width));
    for row in model.rows {
        let [id, node_type, trust_zone] = row.cells;
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled(pad(&id, 24), theme::accent()),
            Span::styled(pad(&node_type, 16), theme::muted()),
            Span::styled(trust_zone, theme::subtle()),
        ]));
    }
}
