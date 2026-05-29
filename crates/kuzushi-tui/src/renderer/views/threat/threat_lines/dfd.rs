use super::*;

pub(super) fn append_dfd_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    // Lead with the target's actual DFD nodes (from threat-model.json).
    if let Some(model) = crate::ui_view_models::threat_dfd_model(app) {
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
        lines.push(blank());
    }
    // The boxes below are an illustrative legend of DFD notation, not the
    // target's topology — labelled clearly so it is never mistaken for it.
    lines.push(section_header_line(
        "DFD NOTATION · illustrative example",
        area.width,
    ));
    lines.extend(dfd_canonical_lines());
}
