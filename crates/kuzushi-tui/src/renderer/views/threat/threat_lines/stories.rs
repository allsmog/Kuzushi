use super::*;
use crate::ui_view_models::ThreatStoryTone;

pub(super) fn append_story_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let stories = crate::ui_view_models::threat_story_rows(app);
    lines.push(section_header_line(
        &format!("ATTACKER STORIES · {}", stories.len()),
        area.width,
    ));
    for story in stories.into_iter().take(8) {
        let [id, severity, title, attack, location] = story.cells;
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled("▸ ", theme::warn()),
            Span::styled(pad(&id, 8), theme::accent()),
            Span::styled(pad(&severity, 9), threat_story_tone_style(story.tone)),
            Span::styled(title, theme::primary()),
        ]));
        append_story_detail("attack ", attack, lines);
        append_story_detail("loc    ", location, lines);
    }
}

fn threat_story_tone_style(tone: ThreatStoryTone) -> Style {
    match tone {
        ThreatStoryTone::Critical => theme::severity(Severity::Critical),
        ThreatStoryTone::High => theme::severity(Severity::High),
        ThreatStoryTone::Medium => theme::severity(Severity::Medium),
        ThreatStoryTone::Low => theme::severity(Severity::Low),
        ThreatStoryTone::Info => theme::severity(Severity::Info),
        ThreatStoryTone::Unknown => theme::severity(Severity::Unknown),
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
