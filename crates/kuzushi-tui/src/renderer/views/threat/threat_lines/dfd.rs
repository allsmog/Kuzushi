use super::*;

pub(super) fn append_dfd_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    lines.push(section_header_line("DFD · acme-checkout", area.width));
    lines.extend(dfd_canonical_lines());
    if let Some(doc) = current_threat_model_doc(app) {
        if let Some(nodes) = dfd_nodes_from_doc(&doc) {
            lines.push(blank());
            lines.push(section_header_line(
                &format!("NODES FROM threat-model.json · {}", nodes.len()),
                area.width,
            ));
            for (id, node_type, zone) in nodes.into_iter().take(8) {
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled(pad(&id, 24), theme::accent()),
                    Span::styled(pad(&node_type, 16), theme::muted()),
                    Span::styled(zone, theme::subtle()),
                ]));
            }
        }
    }
}
