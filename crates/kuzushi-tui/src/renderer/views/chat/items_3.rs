use super::*;

pub(crate) fn history_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("COMMAND HISTORY", area.width));

    let entries = app
        .command_history
        .iter()
        .rev()
        .take(50)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        lines.extend(empty_state_panel(
            "no commands run yet",
            &[
                "session history records every operator-typed command line.",
                "type something at the prompt and it will land here.",
            ],
            &[
                ("help", "browse the full command catalog"),
                ("modules", "see what's loaded"),
                ("scan .", "smallest one-shot run"),
            ],
        ));
    } else {
        let start = app.command_history.len().saturating_sub(entries.len()) + 1;
        let width = (start + entries.len()).to_string().len();
        for (offset, command) in entries.into_iter().rev().enumerate() {
            lines.push(row(&[
                format!("{:>width$}", start + offset, width = width),
                fit(command, area.width.saturating_sub(8) as usize),
            ]));
        }
    }

    lines.push(blank());
    lines.push(command_list_line(
        &["clear", "run <tool>", "show runs", "back"],
        area.width as usize,
    ));
    lines
}

pub(crate) fn story_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("SESSION STORY · live event timeline", area.width));
    if let Some(scan) = &app.scan {
        let label = if scan.running {
            if scan.abort_requested {
                "abort requested"
            } else if app.is_scan_paused() {
                "paused"
            } else {
                "running"
            }
        } else {
            "idle"
        };
        lines.push(row(&[
            pad("scan", 10),
            fit(
                &format!(
                    "{label} · stage={} · findings={}",
                    scan.stage, scan.findings_count
                ),
                area.width.saturating_sub(14) as usize,
            ),
        ]));
    }
    lines.push(blank());

    let max_events = (area.height as usize).saturating_sub(8).max(8);
    let events = app
        .log
        .iter()
        .filter(|line| line.prefix != ">")
        .rev()
        .take(max_events)
        .collect::<Vec<_>>();
    if events.is_empty() {
        lines.extend(empty_state_panel(
            "no session events yet",
            &[
                "the timeline replays prior scan / agent / module events.",
                "run something to populate it.",
            ],
            &[
                ("scan <target>", "umbrella scan against a workspace"),
                ("ask <question>", "single-shot agent question"),
                ("run <tool>", "dispatch a registered tool"),
            ],
        ));
    } else {
        for line in events.into_iter().rev() {
            let body_width = area.width.saturating_sub(14) as usize;
            lines.push(row(&[pad(&line.prefix, 10), fit(&line.body, body_width)]));
        }
    }

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
