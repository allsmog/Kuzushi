use super::*;
use crate::ui_view_models::{failure_handoff_model, FailureHandoffModel};

pub(crate) fn failure_handoff_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("FAILURE HANDOFF", area.width));
    let body_w = area.width.saturating_sub(3) as usize;

    if let Some(model) = failure_handoff_model(app) {
        append_failure_rows(&mut lines, &model, body_w);
    } else {
        append_failure_empty_state(&mut lines);
    }

    lines.push(blank());
    lines.push(command_list_line(
        &["ask <question>", "runs", "replay <run>", "back"],
        area.width as usize,
    ));
    lines
}

fn append_failure_empty_state(lines: &mut Vec<Line<'static>>) {
    lines.extend(empty_state_panel(
        "no failure handoff loaded",
        &[
            "partial and failed tool runs create bounded handoff context.",
            "the next agent question inherits that context once.",
        ],
        &[
            ("runs", "inspect recent run artifacts"),
            ("activity", "watch current module progress"),
            (
                "ask <question>",
                "next /ask inherits this failure context once",
            ),
        ],
    ));
}

fn append_failure_rows(lines: &mut Vec<Line<'static>>, model: &FailureHandoffModel, body_w: usize) {
    for row in &model.rows {
        append_failure_detail(lines, row.label, &row.value, body_w);
    }
}

fn append_failure_detail(lines: &mut Vec<Line<'static>>, key: &str, value: &str, body_w: usize) {
    for (index, segment) in wrap_text(value, body_w).into_iter().enumerate() {
        let label = if index == 0 { key } else { "" };
        lines.push(detail(label, &segment));
    }
}
