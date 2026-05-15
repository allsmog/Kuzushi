use super::*;

pub(super) fn append_story_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let stories = crate::ui_view_models::threat_story_rows(app);
    lines.push(section_header_line(
        &format!("ATTACKER STORIES · {}", stories.len()),
        area.width,
    ));
    for story in stories.into_iter().take(8) {
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled("▸ ", theme::warn()),
            Span::styled(pad(&story.id, 8), theme::accent()),
            Span::styled(
                pad(&story.severity.as_str().to_uppercase(), 9),
                theme::severity(story.severity),
            ),
            Span::styled(story.title, theme::primary()),
        ]));
        append_story_detail("attack ", story.attack, lines);
        append_story_detail("loc    ", story.location, lines);
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
