use super::*;

pub(crate) fn threat_editor_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("THREAT MODEL EDIT", area.width));
    lines.push(detail("artifact", ".kuzushi/threat-model.json"));
    lines.push(detail("mode", "operator edits"));
    lines.push(detail("sections", "elements, boundaries, stories, scope"));
    lines
}
