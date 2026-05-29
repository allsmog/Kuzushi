use super::*;
use crate::ui_view_models::{threat_dfd_diagram_lines, threat_model_doc, DfdLineKind};

pub(super) fn append_dfd_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    // Lead with the target's actual data-flow diagram drawn from threat-model.json.
    if append_real_dfd(app, area, lines) {
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

fn append_real_dfd(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) -> bool {
    let Some(doc) = threat_model_doc(app) else {
        return false;
    };
    let Some(diagram) = threat_dfd_diagram_lines(&doc, area.width as usize) else {
        return false;
    };
    for diagram_line in diagram {
        lines.push(Line::from(Span::styled(
            diagram_line.text,
            dfd_line_style(diagram_line.kind),
        )));
    }
    true
}

fn dfd_line_style(kind: DfdLineKind) -> Style {
    match kind {
        DfdLineKind::Title => theme::accent(),
        DfdLineKind::Zone => theme::accent(),
        DfdLineKind::Boundary => theme::warn(),
        DfdLineKind::Flow => theme::muted(),
        DfdLineKind::Node | DfdLineKind::Summary => theme::subtle(),
    }
}
