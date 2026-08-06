use super::*;
use crate::ui_view_models::{SeverityTone, ThreatStoryTone};

pub(super) fn append_story_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let model = crate::ui_view_models::threat_story_model(app);
    lines.push(section_header_line(&model.header, area.width));
    if let Some(hint) = &model.empty_hint {
        lines.push(empty_hint_line(hint));
        return;
    }
    for story in model.rows {
        let [id, severity, title] = story.cells;
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled("▸ ", theme::warn()),
            Span::styled(pad(&id, 8), theme::accent()),
            Span::styled(pad(&severity, 9), threat_story_tone_style(story.tone)),
            Span::styled(title, theme::primary()),
        ]));
        for detail in story.details {
            append_story_detail(detail.label, detail.value, lines);
        }
    }
}

fn threat_story_tone_style(tone: ThreatStoryTone) -> Style {
    match tone {
        ThreatStoryTone::Critical => theme::severity_tone(SeverityTone::Critical),
        ThreatStoryTone::High => theme::severity_tone(SeverityTone::High),
        ThreatStoryTone::Medium => theme::severity_tone(SeverityTone::Medium),
        ThreatStoryTone::Low => theme::severity_tone(SeverityTone::Low),
        ThreatStoryTone::Info => theme::severity_tone(SeverityTone::Info),
        ThreatStoryTone::Unknown => theme::severity_tone(SeverityTone::Unknown),
    }
}

fn append_story_detail(label: &'static str, value: String, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(vec![
        Span::raw("              "),
        Span::styled(label, theme::subtle()),
        Span::styled(value, theme::muted()),
    ]));
}
