use super::*;
use crate::ui_view_models::{actor_detail_model, ActorDetailModel, ActorTranscriptRow};

pub(crate) fn actor_detail_lines(app: &ShellApp, area: Rect, index: usize) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let visible = area.height.saturating_sub(8).max(2) as usize;
    let model = actor_detail_model(app, visible);
    lines.push(blank());
    lines.push(divider(&format!("ACTOR {index}"), area.width));
    lines.push(detail("tool", "semgrep:scan"));
    lines.push(detail("status", &model.status));
    lines.push(detail("filter", &model.filter_label));
    lines.push(keybind_hint_line(&[
        ("f", "cycle filter"),
        ("0", "reset"),
        ("j/k/g/G", "scroll"),
        ("back", "home"),
    ]));
    lines.push(blank());

    push_transcript_lines(&mut lines, &model);
    lines
}

fn push_transcript_lines(lines: &mut Vec<Line<'static>>, model: &ActorDetailModel) {
    if model.transcript.is_empty() {
        lines.push(muted("(no matching transcript entries under this filter)"));
        return;
    }
    for row in &model.transcript {
        lines.push(transcript_line(row));
    }
}

fn transcript_line(row: &ActorTranscriptRow) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:>8} ", row.prefix), theme::subtle()),
        Span::raw(row.body.clone()),
    ])
}
