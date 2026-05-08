use super::*;

pub(super) fn append_story_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let doc = current_threat_model_doc(app);
    let stories = doc
        .as_ref()
        .and_then(stories_from_doc)
        .unwrap_or_else(canonical_stories_fixture);
    lines.push(section_header_line(
        &format!("ATTACKER STORIES · {}", stories.len()),
        area.width,
    ));
    for (id, severity, title, attack, location) in stories.into_iter().take(8) {
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled("▸ ", theme::warn()),
            Span::styled(pad(&id, 8), theme::accent()),
            Span::styled(
                pad(&severity.as_str().to_uppercase(), 9),
                theme::severity(severity),
            ),
            Span::styled(title, theme::primary()),
        ]));
        append_story_detail("attack ", attack, lines);
        append_story_detail("loc    ", location, lines);
    }
}

fn append_story_detail(label: &'static str, value: String, lines: &mut Vec<Line<'static>>) {
    if value.is_empty() {
        return;
    }
    lines.push(Line::from(vec![
        Span::raw("              "),
        Span::styled(label, theme::subtle()),
        Span::styled(value, theme::muted()),
    ]));
}
