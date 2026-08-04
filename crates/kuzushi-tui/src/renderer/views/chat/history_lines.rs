use super::*;
use crate::ui_view_models::{
    session_history_model, session_story_model, CommandHistoryModel, SessionStoryModel,
};

pub(crate) fn history_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("COMMAND HISTORY", area.width));

    let model = session_history_model(app, 50);
    append_history_rows(&mut lines, &model, area);

    lines.push(blank());
    lines.push(command_list_line(
        &["clear", "run <tool>", "show runs", "back"],
        area.width as usize,
    ));
    lines
}

fn append_history_rows(lines: &mut Vec<Line<'static>>, model: &CommandHistoryModel, area: Rect) {
    if model.rows.is_empty() {
        lines.extend(empty_state_panel(
            "no commands run yet",
            &[
                "session history records every operator-typed command line.",
                "type something at the prompt and it will land here.",
            ],
            &[
                ("help", "browse the full command catalog"),
                ("modules", "see what's loaded"),
                ("scan", "open the Scan phase planner"),
            ],
        ));
    } else {
        for row_model in &model.rows {
            let [number, command] = &row_model.cells;
            lines.push(row(&[
                format!("{number:>width$}", width = model.number_width),
                fit(command, area.width.saturating_sub(8) as usize),
            ]));
        }
    }
}

pub(crate) fn story_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(
        "SESSION STORY · event log (refresh with /story)",
        area.width,
    ));

    let model = session_story_model(app, story_event_limit(area));
    append_story_scan_row(&mut lines, &model, area);
    lines.push(blank());
    append_story_events(&mut lines, &model, area);

    lines.push(blank());
    lines.push(command_list_line(
        &[
            "Ctrl+O toggle",
            "/history commands",
            "/show runs",
            "/replay <runId>",
            "/trace <runId>",
        ],
        area.width as usize,
    ));
    lines
}

fn story_event_limit(area: Rect) -> usize {
    (area.height as usize).saturating_sub(8).max(8)
}

fn append_story_scan_row(lines: &mut Vec<Line<'static>>, model: &SessionStoryModel, area: Rect) {
    if let Some(scan) = &model.scan_row {
        let [label, body] = &scan.cells;
        lines.push(row(&[
            pad(label, 10),
            fit(body, area.width.saturating_sub(14) as usize),
        ]));
    }
}

fn append_story_events(lines: &mut Vec<Line<'static>>, model: &SessionStoryModel, area: Rect) {
    if model.events.is_empty() {
        lines.extend(empty_state_panel(
            "no session events yet",
            &[
                "the timeline replays prior scan / agent / module events.",
                "run something to populate it.",
            ],
            &[
                ("full <target>", "guided Map → Scan workflow"),
                ("ask <question>", "single-shot agent question"),
                ("run <tool>", "dispatch a registered tool"),
            ],
        ));
    } else {
        for event in &model.events {
            let body_width = area.width.saturating_sub(14) as usize;
            let [label, body] = &event.cells;
            lines.push(row(&[pad(label, 10), fit(body, body_width)]));
        }
    }
}
