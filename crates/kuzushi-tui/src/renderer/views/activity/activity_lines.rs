use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_view_model, ActivityEmptyStateModel, ActivityHeartbeatTone, ActivityViewModel,
    RunFocusModel,
};
use std::time::Instant;

/// Plain output serializes the same Run Focus model in reading order. It does
/// not imitate a terminal column split, which made logs truncate differently
/// from the interactive view.
pub(crate) fn activity_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match activity_view_model(app) {
        ActivityViewModel::Active(activity) => {
            active_activity_lines(activity_context_lines(app, area), area, activity)
        }
        ActivityViewModel::Inactive(empty) => {
            inactive_activity_lines(activity_context_lines(app, area), area.width, empty)
        }
    }
}

fn activity_context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines
}

fn inactive_activity_lines(
    mut lines: Vec<Line<'static>>,
    width: u16,
    empty: ActivityEmptyStateModel,
) -> Vec<Line<'static>> {
    if width < 70 {
        if lines.last().is_some_and(is_blank_line) {
            lines.pop();
        }
        lines.push(divider(empty.title, width));
        lines.extend(compact_activity_empty_state_lines(&empty, width as usize));
        return lines;
    }
    lines.push(divider(empty.title, width));
    lines.extend(empty_state_panel(
        empty.glyph_label,
        empty.explanations,
        empty.ctas,
    ));
    lines
}

fn compact_activity_empty_state_lines(
    empty: &ActivityEmptyStateModel,
    width: usize,
) -> Vec<Line<'static>> {
    let content_width = width.saturating_sub(2);
    let mut lines = vec![Line::from(vec![
        Span::styled("∅ ", theme::subtle()),
        Span::styled(empty.glyph_label.to_string(), theme::muted()),
    ])];
    if let Some(explanation) = empty.explanations.first() {
        lines.push(muted(&fit(explanation, content_width)));
    }
    lines.extend(
        empty
            .ctas
            .iter()
            .map(|(command, blurb)| compact_activity_cta(command, blurb, content_width)),
    );
    lines
}

fn compact_activity_cta(command: &str, blurb: &str, width: usize) -> Line<'static> {
    let prefix = format!("▸ {command} — ");
    let blurb = fit(blurb, width.saturating_sub(prefix.chars().count()));
    Line::from(vec![
        Span::styled("▸ ", theme::warn()),
        Span::styled(command.to_string(), theme::accent()),
        Span::styled(" — ", theme::subtle()),
        Span::styled(blurb, theme::muted()),
    ])
}

fn is_blank_line(line: &Line<'_>) -> bool {
    line.spans.iter().all(|span| span.content.trim().is_empty())
}

fn active_activity_lines(
    mut lines: Vec<Line<'static>>,
    area: Rect,
    activity: RunFocusModel<'_>,
) -> Vec<Line<'static>> {
    let header = activity.header();
    lines.push(divider(&header.summary_title, area.width));
    lines.push(muted(&fit(activity.context_line(), area.width as usize)));
    if let Some(banner) = activity.abort_banner() {
        lines.push(Line::from(vec![Span::styled(banner, theme::warn())]));
    }
    append_activity_heartbeat(&mut lines, area.width, &activity);

    if let Some(question) = activity.operator_question() {
        let hints = activity.operator_question_key_hints();
        lines.push(divider("WAITING INPUT", area.width));
        lines.extend(super::operator_question::operator_question_lines(
            question,
            &hints,
            area.width as usize,
        ));
    } else {
        append_activity_pane_lines(&mut lines, area, &activity);
    }

    lines.push(blank());
    append_activity_footer(&mut lines, area.width, &activity);
    lines
}

fn append_activity_heartbeat(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    activity: &RunFocusModel<'_>,
) {
    let model = activity.heartbeat(Instant::now());
    let style = match model.tone {
        ActivityHeartbeatTone::Live => theme::success(),
        ActivityHeartbeatTone::Stalled => theme::warn(),
        ActivityHeartbeatTone::Complete => theme::muted(),
        ActivityHeartbeatTone::Warning => theme::warn(),
        ActivityHeartbeatTone::Failed => theme::danger(),
    };
    lines.push(Line::styled(fit(&model.text, width as usize), style));
}

fn append_activity_pane_lines(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    activity: &RunFocusModel<'_>,
) {
    let width = area.width.saturating_sub(2) as usize;
    lines.push(divider("STEPS", area.width));
    lines.extend(
        activity
            .dag_pane_rows(width, Instant::now())
            .into_iter()
            .map(|row| Line::from(Span::styled(row.text, dag_row_style(row.tone)))),
    );
    lines.push(divider("OUTPUT", area.width));
    lines.extend(
        activity
            .feed_pane_rows(width)
            .into_iter()
            .map(|row| Line::from(Span::styled(row.text, feed_row_style(row.tone)))),
    );
}

fn append_activity_footer(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    activity: &RunFocusModel<'_>,
) {
    let footer = activity.footer(width);
    if let Some(editor) = footer.steer_line {
        lines.push(Line::styled(editor, theme::accent()));
    }
    if let Some(error) = footer.steer_error {
        lines.push(Line::styled(format!(" ⚠ {error}"), theme::warn()));
    }
    lines.push(Line::from(vec![Span::styled(
        footer.body_line,
        theme::label(),
    )]));
    lines.extend(footer.hint_rows.iter().map(|row| {
        let pairs = row
            .iter()
            .map(|hint| (hint.plain_key_text.as_str(), hint.plain_hint_text))
            .collect::<Vec<_>>();
        keybind_hint_line(&pairs)
    }));
}
