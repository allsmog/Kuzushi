use super::*;

pub(crate) fn actor_detail_lines(app: &ShellApp, area: Rect, index: usize) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(&format!("ACTOR {index}"), area.width));
    lines.push(detail("tool", "semgrep:scan"));
    lines.push(detail(
        "status",
        app.scan
            .as_ref()
            .map(scan_status)
            .unwrap_or_else(|| "idle".to_string())
            .as_str(),
    ));
    lines.push(detail("filter", app.actor_detail_filter.label()));
    lines.push(keybind_hint_line(&[
        ("f", "cycle filter"),
        ("0", "reset"),
        ("j/k/g/G", "scroll"),
        ("back", "home"),
    ]));
    lines.push(blank());

    let visible = area.height.saturating_sub(8).max(2) as usize;
    let filter = app.actor_detail_filter;
    let mut kept: Vec<&crate::app::LogLine> = app
        .log
        .iter()
        .filter(|line| filter.keeps(&line.prefix))
        .collect();
    let start = kept.len().saturating_sub(visible);
    kept.drain(..start);
    if kept.is_empty() {
        lines.push(muted("(no matching transcript entries under this filter)"));
    } else {
        for line in kept {
            lines.push(Line::from(vec![
                Span::styled(format!("{:>8} ", line.prefix), theme::subtle()),
                Span::raw(line.body.clone()),
            ]));
        }
    }
    lines
}
