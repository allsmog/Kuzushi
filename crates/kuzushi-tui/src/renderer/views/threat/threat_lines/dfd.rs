use super::*;

pub(super) fn append_dfd_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    lines.push(section_header_line("DFD · acme-checkout", area.width));
    lines.extend(dfd_canonical_lines());
    let nodes = crate::ui_view_models::threat_dfd_nodes(app);
    if nodes.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(section_header_line(
        &format!("NODES FROM threat-model.json · {}", nodes.len()),
        area.width,
    ));
    for node in nodes.into_iter().take(8) {
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled(pad(&node.id, 24), theme::accent()),
            Span::styled(pad(&node.node_type, 16), theme::muted()),
            Span::styled(node.trust_zone, theme::subtle()),
        ]));
    }
}
